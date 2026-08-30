"""Supervised C2 dual-surface runtime: loopback control + private-LAN pairing."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import threading
from collections.abc import Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import uvicorn
from fastapi import FastAPI

from .api import create_app
from .credential_transition import PairingOperatorService
from .credential_transition_api import (
    create_pairing_operator_router,
    install_operator_openapi_scheme,
)
from .https_runtime import build_https_config, validate_port
from .listen_policy import (
    LISTEN_LOOPBACK_ONLY,
    LISTEN_PAIRING_ONLY,
    LOOPBACK_HOST,
    resolve_listen_policy,
)
from .pairing_codec import PROTOCOL_VERSION, require_digest
from .pairing_store import PairingStore
from .pairing_store_executor import PairingStoreExecutor
from .tls_identity import build_ssl_context_factory, load_tls_identity, redacted_error

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_PRE_LISTEN = 2
READY_MAX_BYTES = 2_048
CONTROL_LINE_MAX_CHARS = 16


@asynccontextmanager
async def _control_lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # The owning LAN app drains the shared executor after control stops.
    yield


def create_local_pairing_control_app(
    *,
    pairing_store: PairingStore,
    store_executor: PairingStoreExecutor,
    operator_token_digest: str,
) -> FastAPI:
    """Create an operator-only app. It owns neither executor nor store."""
    app = FastAPI(
        title="Data Steward Local Pairing Control",
        version="1",
        lifespan=_control_lifespan,
    )
    service = PairingOperatorService(
        pairing_store=pairing_store,
        store_executor=store_executor,
    )
    app.state.pairing_store = pairing_store
    app.state.pairing_store_executor = store_executor
    app.include_router(
        create_pairing_operator_router(
            pairing_service=service,
            operator_token_digest=operator_token_digest,
        )
    )
    install_operator_openapi_scheme(app)
    return app


async def _serve_one(server: uvicorn.Server) -> None:
    try:
        await server.serve()
    except SystemExit as exc:
        raise RuntimeError("listener_start_failed") from None


def _start_control_reader(
    loop: asyncio.AbstractEventLoop,
) -> asyncio.Future[str]:
    """Read one bounded control line without owning a non-daemon worker."""
    result: asyncio.Future[str] = loop.create_future()

    def publish(*, line: str | None = None, failed: bool = False) -> None:
        if result.done():
            return
        if failed:
            result.set_exception(RuntimeError("control_read_failed"))
        else:
            result.set_result(line or "")

    def read() -> None:
        try:
            line = sys.stdin.readline(CONTROL_LINE_MAX_CHARS + 1)
        except Exception:  # noqa: BLE001
            try:
                loop.call_soon_threadsafe(lambda: publish(failed=True))
            except RuntimeError:
                pass
            return
        try:
            loop.call_soon_threadsafe(lambda: publish(line=line))
        except RuntimeError:
            # A listener failed and the child event loop already closed.
            pass

    threading.Thread(
        target=read,
        name="c2-control-stdin",
        daemon=True,
    ).start()
    return result


async def _wait_started(
    lan_server: uvicorn.Server,
    control_server: uvicorn.Server,
    lan_task: asyncio.Task[None],
    control_task: asyncio.Task[None],
) -> bool:
    while True:
        if lan_server.started and control_server.started:
            return True
        if lan_task.done() or control_task.done():
            return False
        await asyncio.sleep(0.01)


async def _stop_servers(
    *,
    lan_server: uvicorn.Server,
    control_server: uvicorn.Server,
    lan_task: asyncio.Task[None],
    control_task: asyncio.Task[None],
) -> None:
    # Local control stops first so it cannot submit into a draining executor.
    control_server.should_exit = True
    await asyncio.gather(control_task, return_exceptions=True)
    lan_server.should_exit = True
    await asyncio.gather(lan_task, return_exceptions=True)


async def _serve_dual(
    *,
    lan_server: uvicorn.Server,
    control_server: uvicorn.Server,
    ready_payload: dict[str, Any],
) -> bool:
    lan_task = asyncio.create_task(_serve_one(lan_server))
    control_task = asyncio.create_task(_serve_one(control_server))
    try:
        if not await _wait_started(
            lan_server,
            control_server,
            lan_task,
            control_task,
        ):
            return False
        encoded = json.dumps(
            ready_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > READY_MAX_BYTES:
            raise RuntimeError("readiness_too_large")
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()

        stdin_task = _start_control_reader(asyncio.get_running_loop())
        done, _pending = await asyncio.wait(
            {lan_task, control_task, stdin_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stdin_task in done:
            line = stdin_task.result()
            if line not in {"shutdown\n", "shutdown\r\n", ""}:
                raise RuntimeError("control_input_invalid")
        return lan_task not in done and control_task not in done
    finally:
        await _stop_servers(
            lan_server=lan_server,
            control_server=control_server,
            lan_task=lan_task,
            control_task=control_task,
        )


def serve_supervised_pairing(
    *,
    database_path: str | Path,
    identity_root: str | Path,
    private_host: str,
    pairing_port: int,
    control_port: int,
    operator_token_digest: str,
    private_lan_authorized: bool,
) -> int:
    """Run two coordinated HTTPS listeners around one pairing runtime."""
    pairing: PairingStore | None = None
    executor: PairingStoreExecutor | None = None
    try:
        lan_policy = resolve_listen_policy(
            mode=LISTEN_PAIRING_ONLY,
            host=private_host,
            private_lan_authorized=private_lan_authorized,
        )
        control_policy = resolve_listen_policy(
            mode=LISTEN_LOOPBACK_ONLY,
            host=LOOPBACK_HOST,
        )
        validate_port(pairing_port)
        validate_port(control_port)
        if pairing_port == control_port:
            raise ValueError("listener_ports_must_differ")
        digest = require_digest("operator_token_digest", operator_token_digest)
        identity = load_tls_identity(Path(identity_root))
        pairing = PairingStore(database_path, auto_start_runtime=False)
        pairing.initialize_hub_identity(
            hub_id=identity.manifest.hub_id,
            cert_fingerprint=identity.cert_fingerprint_sha256,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="identity-root",
        )
        pairing.start_runtime()
        executor = PairingStoreExecutor()

        lan_app = create_app(
            database_path=database_path,
            pairing_store=pairing,
            close_pairing_store=False,
            pairing_store_executor=executor,
            business_routes_enabled=False,
            transport_scope=lan_policy.transport_scope,
        )
        control_app = create_local_pairing_control_app(
            pairing_store=pairing,
            store_executor=executor,
            operator_token_digest=digest,
        )
        lan_factory, _lan_cleanup = build_ssl_context_factory(identity)
        control_factory, _control_cleanup = build_ssl_context_factory(identity)
        del _lan_cleanup, _control_cleanup
        lan_server = uvicorn.Server(
            build_https_config(
                app=lan_app,
                host=private_host,
                port=pairing_port,
                identity=identity,
                ssl_context_factory=lan_factory,
                listen_policy=lan_policy,
            )
        )
        control_server = uvicorn.Server(
            build_https_config(
                app=control_app,
                host=LOOPBACK_HOST,
                port=control_port,
                identity=identity,
                ssl_context_factory=control_factory,
                listen_policy=control_policy,
            )
        )
        servers = (lan_server, control_server)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(
                signal.SIGBREAK,
                lambda _s, _f: [setattr(server, "should_exit", True) for server in servers],
            )
        ready = {
            "event": "c2_pairing_ready",
            "protocol_version": PROTOCOL_VERSION,
            "control_url": f"https://{LOOPBACK_HOST}:{control_port}",
            "pairing_url": f"https://{private_host}:{pairing_port}",
            "hub_id": identity.manifest.hub_id,
            "cert_fingerprint": identity.cert_fingerprint_sha256,
            "transport_scope": lan_policy.transport_scope,
        }
        clean_stop = asyncio.run(
            _serve_dual(
                lan_server=lan_server,
                control_server=control_server,
                ready_payload=ready,
            )
        )
        return EXIT_OK if clean_stop else EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(redacted_error("C2_RUNTIME", exc) + "\n")
        return EXIT_PRE_LISTEN
    finally:
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_queued=True)
            except Exception:  # noqa: BLE001
                pass
        if pairing is not None:
            try:
                pairing.close()
            except Exception:  # noqa: BLE001
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Supervised Data Steward Huawei pairing runtime"
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--identity-root", required=True)
    parser.add_argument("--private-host", required=True)
    parser.add_argument("--pairing-port", type=int, required=True)
    parser.add_argument("--control-port", type=int, required=True)
    parser.add_argument("--operator-token-digest", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--acknowledge-private-lan-risk", action="store_true")
    args = parser.parse_args(argv)
    if args.workers != 1:
        raise SystemExit("exactly one worker is required")
    return serve_supervised_pairing(
        database_path=args.database,
        identity_root=args.identity_root,
        private_host=args.private_host,
        pairing_port=args.pairing_port,
        control_port=args.control_port,
        operator_token_digest=args.operator_token_digest,
        private_lan_authorized=args.acknowledge_private_lan_risk,
    )


if __name__ == "__main__":
    raise SystemExit(main())
