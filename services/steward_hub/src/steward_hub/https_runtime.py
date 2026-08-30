"""Policy-gated HTTPS Hub runtime with production TLS identity loading."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import signal
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import uvicorn

from .api import create_app
from .device_auth import AUTH_MODE_REQUIRED
from .listen_policy import (
    LISTEN_LOOPBACK_ONLY,
    LISTEN_MODES,
    LOOPBACK_HOST,
    ListenPolicy,
    resolve_listen_policy,
)
from .pairing_api import shutdown_pairing_store_executor
from .pairing_errors import PairingIdentityConflictError, PairingValidationError
from .pairing_store import PairingStore
from .pairing_store_executor import PairingStoreExecutor
from .tls_identity import (
    LoadedTlsIdentity,
    TlsIdentityError,
    build_ssl_context_factory,
    load_tls_identity,
    redacted_error,
)
from .websocket_auth import MAX_AUTH_FRAME_BYTES

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_PRE_LISTEN = 2
MAX_CONTROL_LINE_BYTES = 256
_CONTROL_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


class UvicornStartupFailed(RuntimeError):
    """Uvicorn called sys.exit on bind/startup failure."""

    error_code = "https_bind_failed"


def validate_loopback_bind_host(host: str) -> str:
    return resolve_listen_policy(
        mode=LISTEN_LOOPBACK_ONLY,
        host=host,
    ).host


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("port_invalid")
    return port


def allocate_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_HOST, 0))
        return int(sock.getsockname()[1])


def build_https_config(
    *,
    app: Any,
    host: str,
    port: int,
    identity: LoadedTlsIdentity,
    ssl_context_factory: Any,
    listen_policy: ListenPolicy | None = None,
) -> uvicorn.Config:
    policy = listen_policy or resolve_listen_policy(
        mode=LISTEN_LOOPBACK_ONLY,
        host=host,
    )
    if not policy.listener_enabled or policy.host != host:
        raise ValueError("listen_policy_mismatch")
    validate_port(port)
    # No ssl_keyfile_password — factory returns a preloaded SSLContext.
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=1,
        reload=False,
        access_log=False,
        proxy_headers=False,
        ws_max_size=MAX_AUTH_FRAME_BYTES,
        log_level="warning",
        ssl_certfile=str(identity.cert_path),
        ssl_keyfile=str(identity.key_path),
        ssl_context_factory=ssl_context_factory,
        server_header=False,
        date_header=False,
    )


def _write_control_reply(path: Path | None, payload: dict[str, Any]) -> None:
    """Smoke-only reply file. Never includes control-line body text."""
    if path is None:
        return
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _handle_control_line(
    line: str,
    *,
    pairing: PairingStore,
    server: uvicorn.Server,
    reply_path: Path | None,
) -> bool:
    """
    SMOKE-ONLY control protocol (enabled solely with --shutdown-stdin).

    Never echo the raw control line into replies, logs, or exceptions.
    Supported commands:
      shutdown
      CREATE_SESSION <ott_digest_hex> <ttl_seconds>
      HUB_CONFIRM <pairing_session_id> <pairing_attempt_id>
    """
    if len(line.encode("utf-8", errors="replace")) > MAX_CONTROL_LINE_BYTES:
        _write_control_reply(
            reply_path, {"ok": False, "op": "?", "error": "control_too_long"}
        )
        return False
    text = line.strip("\r\n")
    if not text:
        return False
    if text == "shutdown":
        server.should_exit = True
        _write_control_reply(reply_path, {"ok": True, "op": "shutdown"})
        return True
    parts = text.split(" ")
    if len(parts) > 4:
        _write_control_reply(
            reply_path, {"ok": False, "op": "?", "error": "control_arity"}
        )
        return False
    op = parts[0]
    try:
        if op == "CREATE_SESSION":
            if len(parts) != 3:
                raise ValueError("control_arity")
            digest, ttl_raw = parts[1], parts[2]
            if not _CONTROL_DIGEST_RE.fullmatch(digest):
                raise ValueError("control_digest")
            if not ttl_raw.isdigit():
                raise ValueError("control_ttl")
            ttl = int(ttl_raw)
            session = pairing.create_pairing_session(
                pairing_token_digest=digest,
                ttl_seconds=ttl,
            )
            _write_control_reply(
                reply_path,
                {
                    "ok": True,
                    "op": "CREATE_SESSION",
                    "pairing_session_id": session.pairing_session_id,
                },
            )
            return False
        if op == "HUB_CONFIRM":
            if len(parts) != 3:
                raise ValueError("control_arity")
            session_id, attempt_id = parts[1], parts[2]
            if not _CONTROL_ULID_RE.fullmatch(session_id):
                raise ValueError("control_session")
            if not _CONTROL_ULID_RE.fullmatch(attempt_id):
                raise ValueError("control_attempt")
            pairing.record_hub_confirmation(
                pairing_session_id=session_id,
                pairing_attempt_id=attempt_id,
                granted_capabilities=["session.sync"],
            )
            _write_control_reply(
                reply_path,
                {"ok": True, "op": "HUB_CONFIRM"},
            )
            return False
        _write_control_reply(
            reply_path,
            {"ok": False, "op": "?", "error": "control_unknown"},
        )
    except Exception as exc:  # noqa: BLE001
        _write_control_reply(
            reply_path,
            {
                "ok": False,
                "op": op if op in {"CREATE_SESSION", "HUB_CONFIRM"} else "?",
                "error": type(exc).__name__,
            },
        )
    return False


def _classify_pre_listen(exc: BaseException) -> str:
    if isinstance(exc, TlsIdentityError):
        return "HTTPS_IDENTITY"
    if isinstance(exc, PairingIdentityConflictError):
        return "HTTPS_IDENTITY_CONFLICT"
    if isinstance(exc, PairingValidationError):
        return "HTTPS_PAIRING_VALIDATION"
    if isinstance(exc, (OSError, UvicornStartupFailed)):
        return "HTTPS_BIND"
    return "HTTPS_PRE_LISTEN"


def _cleanup_runtime(app: Any | None, pairing: PairingStore | None) -> None:
    """Close executor/stores on every path; ignore secondary cleanup errors."""
    if app is not None:
        try:
            asyncio.run(shutdown_pairing_store_executor(app))
        except Exception:  # noqa: BLE001
            pass
        store = getattr(getattr(app, "state", None), "event_store", None)
        if store is not None:
            try:
                store.close()
            except Exception:  # noqa: BLE001
                pass
    if pairing is not None:
        try:
            pairing.close()
        except Exception:  # noqa: BLE001
            pass


def serve_https_hub(
    *,
    database_path: str | Path,
    identity_root: str | Path,
    host: str = LOOPBACK_HOST,
    port: int,
    shutdown_stdin: bool = False,
    control_reply: str | Path | None = None,
    operator_token_digest: str | None = None,
    listen_mode: str = LISTEN_LOOPBACK_ONLY,
    private_lan_authorized: bool = False,
) -> int:
    """
    Load TLS identity (fail before listen), then serve create_app over HTTPS.

    listener_created becomes true only after Uvicorn reports startup/bind success.
    Smoke control stdin is available only when shutdown_stdin=True.
    """
    listener_created = False
    listen_flag = {"created": False}
    pairing: PairingStore | None = None
    app: Any | None = None
    try:
        listen_policy = resolve_listen_policy(
            mode=listen_mode,
            host=host,
            private_lan_authorized=private_lan_authorized,
        )
        validate_port(port)
        if not listen_policy.listener_enabled:
            return EXIT_OK
        identity = load_tls_identity(Path(identity_root))
        factory, _cleanup_ssl = build_ssl_context_factory(identity)
        del _cleanup_ssl  # password already wiped inside factory builder
        pairing = PairingStore(database_path, auto_start_runtime=False)
        pairing.initialize_hub_identity(
            hub_id=identity.manifest.hub_id,
            cert_fingerprint=identity.cert_fingerprint_sha256,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="identity-root",
        )
        pairing.start_runtime()
        app = create_app(
            database_path=database_path,
            pairing_store=pairing,
            close_pairing_store=False,
            business_auth_mode=AUTH_MODE_REQUIRED,
            operator_token_digest=operator_token_digest,
            business_routes_enabled=listen_policy.business_routes_enabled,
            transport_scope=listen_policy.transport_scope,
        )
        config = build_https_config(
            app=app,
            host=host,
            port=port,
            identity=identity,
            ssl_context_factory=factory,
            listen_policy=listen_policy,
        )
        server = uvicorn.Server(config)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(
                signal.SIGBREAK,
                lambda _s, _f: setattr(server, "should_exit", True),
            )
        reply = Path(control_reply) if (shutdown_stdin and control_reply) else None
        if shutdown_stdin:
            started = asyncio.run(
                _serve_with_control_stdin(
                    server,
                    pairing=pairing,
                    reply_path=reply,
                    listen_flag=listen_flag,
                )
            )
        else:
            started = asyncio.run(
                _serve_tracked(server, listen_flag=listen_flag)
            )
        listener_created = bool(listen_flag["created"] or started)
        if not listener_created:
            sys.stderr.write(
                redacted_error("HTTPS_BIND", RuntimeError("startup_failed")) + "\n"
            )
            return EXIT_PRE_LISTEN
        return EXIT_OK
    except SystemExit as exc:
        # Uvicorn bind/startup failure calls sys.exit(STARTUP_FAILURE).
        listener_created = bool(listen_flag["created"] or listener_created)
        sys.stderr.write(
            redacted_error(
                "HTTPS_RUNTIME" if listener_created else "HTTPS_BIND",
                RuntimeError(f"system_exit_{exc.code}"),
            )
            + "\n"
        )
        return EXIT_RUNTIME if listener_created else EXIT_PRE_LISTEN
    except Exception as exc:  # noqa: BLE001
        listener_created = bool(listen_flag["created"] or listener_created)
        if listener_created:
            sys.stderr.write(redacted_error("HTTPS_RUNTIME", exc) + "\n")
            return EXIT_RUNTIME
        sys.stderr.write(redacted_error(_classify_pre_listen(exc), exc) + "\n")
        return EXIT_PRE_LISTEN
    finally:
        _cleanup_runtime(app, pairing)


async def _server_serve_bounded(server: uvicorn.Server) -> None:
    """Wrap server.serve() so SystemExit becomes a catchable RuntimeError."""
    try:
        await server.serve()
    except SystemExit as exc:
        raise UvicornStartupFailed(f"startup_exit_{exc.code}") from None


async def _mark_started(
    server: uvicorn.Server, listen_flag: dict[str, bool]
) -> bool:
    if server.started:
        listen_flag["created"] = True
        return True
    return False


async def _serve_tracked(
    server: uvicorn.Server, *, listen_flag: dict[str, bool]
) -> bool:
    server_task = asyncio.create_task(_server_serve_bounded(server))
    try:
        while not server_task.done() and not server.started:
            await asyncio.sleep(0.01)
        started = await _mark_started(server, listen_flag)
        try:
            await server_task
        except UvicornStartupFailed:
            return False
        return await _mark_started(server, listen_flag) or started
    finally:
        await _mark_started(server, listen_flag)
        if not server_task.done():
            server.should_exit = True
            await asyncio.gather(server_task, return_exceptions=True)


async def _serve_with_control_stdin(
    server: uvicorn.Server,
    *,
    pairing: PairingStore,
    reply_path: Path | None,
    listen_flag: dict[str, bool],
) -> bool:
    """Smoke-only serve loop with stdin control. Returns whether listener started."""
    server_task = asyncio.create_task(_server_serve_bounded(server))
    try:
        while not server_task.done() and not server.started:
            await asyncio.sleep(0.01)
        started = await _mark_started(server, listen_flag)
        if server_task.done() and not started:
            try:
                await server_task
            except UvicornStartupFailed:
                return False
            return False
        while not server.should_exit:
            if server_task.done():
                break
            line = await asyncio.to_thread(sys.stdin.readline)
            if line == "":
                break
            should_stop = _handle_control_line(
                line,
                pairing=pairing,
                server=server,
                reply_path=reply_path,
            )
            if should_stop:
                break
        server.should_exit = True
        try:
            await server_task
        except UvicornStartupFailed:
            return await _mark_started(server, listen_flag) or started
        await _write_shutdown_snapshot(server, reply_path)
        return await _mark_started(server, listen_flag) or started
    finally:
        await _mark_started(server, listen_flag)
        server.should_exit = True
        if not server_task.done():
            await asyncio.gather(server_task, return_exceptions=True)


async def _write_shutdown_snapshot(
    server: uvicorn.Server,
    reply_path: Path | None,
) -> None:
    """Smoke-only post-lifespan ownership evidence; contains no identifiers."""
    if reply_path is None:
        return
    app = getattr(server.config, "app", None)
    state = getattr(app, "state", None)
    registry = getattr(state, "device_connection_registry", None)
    subscriptions = getattr(state, "subscriptions", None)
    executor = getattr(state, "pairing_store_executor", None)
    handshake_count = -1
    connection_count = -1
    operation_count = -1
    if registry is not None:
        snapshot = await registry.snapshot()
        handshake_count = int(snapshot.handshake_count)
        connection_count = int(snapshot.connection_count)
        operation_count = int(snapshot.operation_count)
    _write_control_reply(
        reply_path,
        {
            "ok": True,
            "op": "shutdown_complete",
            "handshake_count": handshake_count,
            "connection_count": connection_count,
            "operation_count": operation_count,
            "subscription_count": int(
                getattr(subscriptions, "subscriber_count", -1)
            ),
            "worker_count": int(
                executor.worker_thread_count()
                if isinstance(executor, PairingStoreExecutor)
                else -1
            ),
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Policy-gated HTTPS Data Steward Hub")
    parser.add_argument("--database", required=True)
    parser.add_argument("--identity-root", required=True)
    parser.add_argument("--host", default=LOOPBACK_HOST)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument(
        "--listen-mode",
        choices=sorted(LISTEN_MODES),
        default=LISTEN_LOOPBACK_ONLY,
    )
    parser.add_argument(
        "--acknowledge-private-lan-risk",
        action="store_true",
        help=(
            "required with pairing-only/authenticated-service; does not change "
            "Windows Firewall"
        ),
    )
    # Smoke/harness only — suppressed from normal --help product surface.
    parser.add_argument(
        "--shutdown-stdin",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--control-reply", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--operator-token-digest",
        default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    if args.workers != 1:
        raise SystemExit("exactly one worker is required")
    # Product path never reads TLS passwords from environment variables.
    # Do not mutate unrelated caller environment keys.
    if args.control_reply and not args.shutdown_stdin:
        raise SystemExit("control_reply_requires_shutdown_stdin")
    return serve_https_hub(
        database_path=args.database,
        identity_root=args.identity_root,
        host=args.host,
        port=args.port,
        shutdown_stdin=args.shutdown_stdin,
        control_reply=args.control_reply,
        operator_token_digest=args.operator_token_digest,
        listen_mode=args.listen_mode,
        private_lan_authorized=args.acknowledge_private_lan_risk,
    )


if __name__ == "__main__":
    raise SystemExit(main())
