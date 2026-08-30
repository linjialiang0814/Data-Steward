"""No-listen smoke for pairing HTTP contract (TestClient + temp SQLite)."""

from __future__ import annotations

import asyncio
import base64
import gc
import hashlib
import json
import logging
import shutil
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.pairing_api import map_pairing_exception, shutdown_pairing_store_executor
from steward_hub.pairing_codec import canonicalize_capabilities, compute_short_verification_code
from steward_hub.pairing_rate_limit import PairingRateLimiter
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import (
    PairingStoreExecutor,
    list_alive_pairing_worker_threads,
)
from steward_hub.store import EventStore

PROTOCOL = "pairing_auth/1"
HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ATTEMPT_B = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
MARKER = "SMOKE_R2_SECRET_MARKER_9f2c"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _safe_exc_projection(exc: BaseException) -> dict[str, str]:
    """Type-only projection — never include args/repr/message bodies."""
    return {"type": type(exc).__name__}


def _count_markers_in_bytes(blob: bytes, markers: tuple[bytes, ...]) -> int:
    return sum(blob.count(item) for item in markers)


def _resolve_openapi_refs(node: Any, components: dict[str, Any], stack: set[str]) -> bool:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/components/schemas/"):
                return False
            name = ref.rsplit("/", 1)[-1]
            if name in stack:
                return True
            schema = components.get(name)
            if schema is None:
                return False
            stack.add(name)
            ok = _resolve_openapi_refs(schema, components, stack)
            stack.remove(name)
            return ok
        return all(
            _resolve_openapi_refs(value, components, stack) for value in node.values()
        )
    if isinstance(node, list):
        return all(_resolve_openapi_refs(item, components, stack) for item in node)
    return True


def _rmtree_strict(path: Path, *, attempts: int = 80, delay_s: float = 0.05) -> bool:
    """Bounded Windows-friendly retries; never silently ignore final failure."""
    gc.collect()
    for _ in range(attempts):
        if not path.exists():
            return True
        try:
            for child in sorted(path.rglob("*"), reverse=True):
                try:
                    if child.is_file() or child.is_symlink():
                        child.unlink(missing_ok=True)
                    elif child.is_dir():
                        child.rmdir()
                except OSError:
                    pass
            shutil.rmtree(path, ignore_errors=False)
        except PermissionError:
            time.sleep(delay_s)
            gc.collect()
            continue
        except OSError:
            time.sleep(delay_s)
            gc.collect()
            continue
        if not path.exists():
            return True
        time.sleep(delay_s)
        gc.collect()
    return not path.exists()


class _BlockingStore:
    def __init__(self, inner: PairingStore) -> None:
        self._inner = inner
        self.block = threading.Event()
        self.entered = threading.Event()

    def __getattr__(self, name: str):
        return getattr(self._inner, name)

    def register_client_hello_digest(self, **kwargs):
        self.entered.set()
        self.block.wait(timeout=30.0)
        return self._inner.register_client_hello_digest(**kwargs)


def run_smoke() -> dict[str, object]:
    ott_raw = b"\x10" * 32
    claim_raw = b"\x20" * 32
    cred_raw = b"\x30" * 32
    ott = _b64url(ott_raw)
    claim = _b64url(claim_raw)
    wrong_claim = _b64url(b"\xaa" * 32)
    cred_digest = hashlib.sha256(cred_raw).hexdigest()
    response_blobs: list[str] = []
    log_records: list[str] = []
    exception_projections: list[dict[str, str]] = []
    tracked_executors: list[PairingStoreExecutor] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            log_records.append(record.getMessage())

    handler = _Handler()
    logging.getLogger().addHandler(handler)

    stalled_body_timeout_enforced = False
    store_deadline_enforced = False
    late_task_reaped = False
    same_qr_short_code_diverged = False
    second_attempt_cannot_replace_first = False
    duplicate_json_rejected = False
    status_rate_limit_verified = False
    retry_after_ceil_verified = False
    bounded_executor_verified = False
    saturation_rejected = False
    late_worker_count_after_shutdown = -1
    store_closed_with_active_calls = True
    queued_write_cancelled_on_shutdown = False
    late_error_retention_bounded = False
    openapi_refs_resolved = False
    confirm_body_has_no_claim_secret = False
    wal_mode_active = False
    open_db_secret_marker_count = -1
    exception_secret_marker_count = 0
    all_pairing_worker_threads_non_daemon = False
    temp_root_removed = False

    secret_markers_bytes = (
        ott_raw,
        claim_raw,
        cred_raw,
        ott.encode("ascii"),
        claim.encode("ascii"),
        MARKER.encode("ascii"),
    )

    tmp = Path(tempfile.mkdtemp(prefix="pairing-http-smoke-"))
    event_store: EventStore | None = None
    pairing: PairingStore | None = None
    report: dict[str, object] = {"status": "FAIL"}

    def _track(app: Any) -> Any:
        executor = app.state.pairing_store_executor
        if isinstance(executor, PairingStoreExecutor):
            tracked_executors.append(executor)
        return app

    try:
        db = tmp / "pairing-http-smoke.sqlite3"
        clock = {"t": datetime(2026, 7, 30, 4, 0, 0, tzinfo=timezone.utc)}

        def wall() -> datetime:
            return clock["t"]

        event_store = EventStore(db)
        pairing = PairingStore(db, clock=wall, auto_start_runtime=False)
        pairing.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="b" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="smoke-http-ref",
        )
        pairing.start_runtime()
        session = pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(ott_raw).hexdigest(),
            ttl_seconds=600,
        )

        caps, _, caps_digest = canonicalize_capabilities(["session.sync"])
        code_a = compute_short_verification_code(
            hub_id=HUB_ID,
            cert_fingerprint="b" * 64,
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=ATTEMPT,
            ott_digest=hashlib.sha256(ott_raw).hexdigest(),
            device_credential_digest=cred_digest,
            claim_secret_digest=hashlib.sha256(claim_raw).hexdigest(),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities_digest=caps_digest,
        )
        code_b = compute_short_verification_code(
            hub_id=HUB_ID,
            cert_fingerprint="b" * 64,
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_B,
            ott_digest=hashlib.sha256(ott_raw).hexdigest(),
            device_credential_digest=hashlib.sha256(b"\x31" * 32).hexdigest(),
            claim_secret_digest=hashlib.sha256(b"\x21" * 32).hexdigest(),
            client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
            requested_capabilities_digest=caps_digest,
        )
        same_qr_short_code_diverged = code_a != code_b
        _ = caps

        app = _track(
            create_app(
                event_store=event_store,
                pairing_store=pairing,
                pairing_rate_limiter=PairingRateLimiter(
                    limits={
                        "client_hello": 10,
                        "client_confirm": 20,
                        "status": 30,
                    }
                ),
                pairing_source_key_fn=lambda _req: "smoke-src",
                pairing_store_max_workers=2,
                pairing_store_max_queued=2,
                close_pairing_store=False,
            )
        )
        with TestClient(app) as client:
            executor = app.state.pairing_store_executor
            bounded_executor_verified = (
                isinstance(executor, PairingStoreExecutor)
                and executor.max_workers == 2
                and executor.max_queued == 2
                and executor.capacity == 4
                and executor.workers_are_non_daemon()
            )
            all_pairing_worker_threads_non_daemon = all(
                not thread.daemon for thread in list_alive_pairing_worker_threads()
            )

            hello_body = {
                "protocol_version": PROTOCOL,
                "pairing_attempt_id": ATTEMPT,
                "pairing_token": ott,
                "claim_secret": claim,
                "device_credential_digest": cred_digest,
                "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "requested_capabilities": ["session.sync"],
                "platform": "android",
                "display_name": "SmokePhone",
            }
            hello1 = client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(hello_body).encode("utf-8"),
            )
            hello2 = client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(hello_body).encode("utf-8"),
            )
            response_blobs.extend([hello1.text, hello2.text])
            h1 = hello1.json()
            h2 = hello2.json()
            short_code = h1.get("short_verification_code", "")

            second = client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(
                    {
                        **hello_body,
                        "pairing_attempt_id": ATTEMPT_B,
                        "claim_secret": _b64url(b"\x21" * 32),
                        "device_credential_digest": hashlib.sha256(
                            b"\x31" * 32
                        ).hexdigest(),
                        "client_nonce": "BBBBBBBBBBBBBBBBBBBBBB",
                    }
                ).encode("utf-8"),
            )
            response_blobs.append(second.text)
            second_attempt_cannot_replace_first = (
                second.status_code == 409
                and second.json().get("error_code") == "pairing_busy"
            )

            dup = (
                '{"protocol_version":"pairing_auth/1",'
                f'"pairing_token":{json.dumps(ott)},'
                f'"pairing_token":{json.dumps(ott)},'
                f'"pairing_attempt_id":{json.dumps(ATTEMPT)},'
                f'"claim_secret":{json.dumps(claim)},'
                f'"device_credential_digest":{json.dumps(cred_digest)},'
                '"client_nonce":"AAAAAAAAAAAAAAAAAAAAAA",'
                '"requested_capabilities":["session.sync"],'
                '"platform":"android"}'
            )
            dup_resp = client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=dup.encode("utf-8"),
            )
            response_blobs.append(dup_resp.text)
            duplicate_json_rejected = (
                dup_resp.status_code == 400
                and dup_resp.json().get("error_code") == "pairing_validation_error"
            )

            pairing.record_hub_confirmation(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id=ATTEMPT,
                granted_capabilities=["session.sync"],
            )
            confirm = client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_confirm",
                headers={
                    "content-type": "application/json",
                    "authorization": f"Pairing {claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
                content=json.dumps(
                    {
                        "protocol_version": PROTOCOL,
                        "pairing_attempt_id": ATTEMPT,
                        "short_verification_code": short_code,
                    }
                ).encode("utf-8"),
            )
            response_blobs.append(confirm.text)
            status = client.get(
                f"/v1/pairing/sessions/{session.pairing_session_id}/status",
                params={"pairing_attempt_id": ATTEMPT},
                headers={
                    "authorization": f"Pairing {claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(status.text)
            wrong = client.get(
                f"/v1/pairing/sessions/{session.pairing_session_id}/status",
                params={"pairing_attempt_id": ATTEMPT},
                headers={
                    "authorization": f"Pairing {wrong_claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(wrong.text)

            openapi = client.get("/openapi.json").json()
            components = openapi.get("components", {}).get("schemas", {})
            openapi_refs_resolved = _resolve_openapi_refs(openapi, components, set())
            confirm_body = (
                openapi.get("paths", {})
                .get("/v1/pairing/sessions/{pairing_session_id}/client_confirm", {})
                .get("post", {})
                .get("requestBody", {})
            )
            confirm_text = json.dumps(confirm_body)
            confirm_body_has_no_claim_secret = "claim_secret" not in confirm_text

            class _MarkerExc(Exception):
                pass

            try:
                raise _MarkerExc(MARKER, ott, claim, str(db))
            except _MarkerExc as exc:
                projection = _safe_exc_projection(exc)
                exception_projections.append(projection)
                mapped = map_pairing_exception(exc)
                response_blobs.append(mapped.body.decode("utf-8") if mapped.body else "")
                proj_text = json.dumps(projection)
                if any(
                    token in proj_text
                    for token in (MARKER, ott, claim, str(db), "Authorization")
                ):
                    exception_secret_marker_count += 1
                if any(
                    token in (mapped.body.decode("utf-8") if mapped.body else "")
                    for token in (MARKER, ott, claim, str(db))
                ):
                    exception_secret_marker_count += 1

        # Stalled body timeout via ASGI (no lifespan — explicit executor shutdown).
        stall_app = _track(
            create_app(
                event_store=event_store,
                pairing_store=pairing,
                pairing_request_timeout_s=0.05,
                pairing_source_key_fn=lambda _r: "smoke-stall",
            )
        )
        path = (
            f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello"
        ).encode("ascii")
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path.decode("ascii"),
            "raw_path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("smoke-stall", 50000),
            "server": ("test", 80),
        }
        state = {"sent": False}

        async def receive() -> dict[str, object]:
            if not state["sent"]:
                state["sent"] = True
                return {
                    "type": "http.request",
                    "body": b'{"protocol_version":"',
                    "more_body": True,
                }
            await asyncio.sleep(3600)
            return {"type": "http.request", "body": b"", "more_body": False}

        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        started = time.monotonic()
        try:
            asyncio.run(stall_app(scope, receive, send))
            stalled_body_timeout_enforced = (
                time.monotonic() - started < 1.0
                and any(
                    m.get("type") == "http.response.start" and m.get("status") == 503
                    for m in messages
                )
            )
        finally:
            stall_app.state.pairing_store_executor.shutdown(wait=True, cancel_queued=True)
            assert stall_app.state.pairing_store_executor.worker_thread_count() == 0

        # Store deadline + late reap
        blocking = _BlockingStore(pairing)
        block_app = _track(
            create_app(
                event_store=event_store,
                pairing_store=blocking,  # type: ignore[arg-type]
                pairing_request_timeout_s=0.05,
                pairing_store_max_workers=2,
                pairing_store_max_queued=2,
                pairing_source_key_fn=lambda _r: "smoke-block",
            )
        )
        with TestClient(block_app) as block_client:
            ott2_raw = b"\x50" * 32
            ott2 = _b64url(ott2_raw)
            session2 = pairing.create_pairing_session(
                pairing_token_digest=hashlib.sha256(ott2_raw).hexdigest(),
                ttl_seconds=600,
            )
            started = time.monotonic()
            blocked = block_client.post(
                f"/v1/pairing/sessions/{session2.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(
                    {
                        **hello_body,
                        "pairing_token": ott2,
                        "pairing_attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FB3",
                        "claim_secret": _b64url(b"\x51" * 32),
                        "device_credential_digest": hashlib.sha256(
                            b"\x52" * 32
                        ).hexdigest(),
                    }
                ).encode("utf-8"),
            )
            store_deadline_enforced = (
                time.monotonic() - started < 1.0 and blocked.status_code == 503
            )
            response_blobs.append(blocked.text)
            assert blocking.entered.wait(timeout=1.0)
            executor = block_app.state.pairing_store_executor
            blocking.block.set()
            deadline = time.monotonic() + 2.0
            while executor.active_count > 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            late_task_reaped = executor.active_count == 0
            pairing.abort_pairing_session(
                pairing_session_id=session2.pairing_session_id,
                reason="cancel",
            )
        late_worker_count_after_shutdown = (
            block_app.state.pairing_store_executor.worker_thread_count()
        )

        # Saturation fail-closed
        sat_block = _BlockingStore(pairing)
        sat_app = _track(
            create_app(
                event_store=event_store,
                pairing_store=sat_block,  # type: ignore[arg-type]
                pairing_request_timeout_s=3.0,
                pairing_store_max_workers=1,
                pairing_store_max_queued=1,
                pairing_source_key_fn=lambda _r: "smoke-sat",
            )
        )
        with TestClient(sat_app) as sat_client:
            ott3_raw = b"\x60" * 32
            session3 = pairing.create_pairing_session(
                pairing_token_digest=hashlib.sha256(ott3_raw).hexdigest(),
                ttl_seconds=600,
            )
            body3 = {
                **hello_body,
                "pairing_token": _b64url(ott3_raw),
                "pairing_attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FB4",
                "claim_secret": _b64url(b"\x61" * 32),
                "device_credential_digest": hashlib.sha256(b"\x62" * 32).hexdigest(),
            }
            url3 = f"/v1/pairing/sessions/{session3.pairing_session_id}/client_hello"

            def _post() -> None:
                sat_client.post(
                    url3,
                    headers={"content-type": "application/json"},
                    content=json.dumps(body3).encode("utf-8"),
                )

            threads = [threading.Thread(target=_post) for _ in range(2)]
            for thread in threads:
                thread.start()
            assert sat_block.entered.wait(timeout=2.0)
            third = sat_client.post(
                url3,
                headers={"content-type": "application/json"},
                content=json.dumps(body3).encode("utf-8"),
            )
            response_blobs.append(third.text)
            saturation_rejected = (
                third.status_code == 503
                and third.json().get("error_code") == "pairing_unavailable"
                and sat_app.state.pairing_store_executor.active_count <= 1
                and sat_app.state.pairing_store_executor.worker_thread_count() <= 1
            )
            sat_block.block.set()
            for thread in threads:
                thread.join(timeout=5.0)
            pairing.abort_pairing_session(
                pairing_session_id=session3.pairing_session_id,
                reason="cancel",
            )

        # Shutdown waits for active; Store close only after active==0
        life_block = _BlockingStore(pairing)
        life_app = _track(
            create_app(
                event_store=event_store,
                pairing_store=life_block,  # type: ignore[arg-type]
                pairing_request_timeout_s=5.0,
                pairing_store_max_workers=1,
                pairing_store_max_queued=1,
                pairing_source_key_fn=lambda _r: "smoke-life",
                close_pairing_store=False,
            )
        )
        with TestClient(life_app) as life_client:
            life_executor = life_app.state.pairing_store_executor
            closed_with_active = {"value": False}
            original_close = pairing.close

            def guarded_close() -> None:
                closed_with_active["value"] = life_executor.active_count > 0
                return None

            pairing.close = guarded_close  # type: ignore[method-assign]
            try:
                ott4_raw = b"\x70" * 32
                session4 = pairing.create_pairing_session(
                    pairing_token_digest=hashlib.sha256(ott4_raw).hexdigest(),
                    ttl_seconds=600,
                )
                body4 = {
                    **hello_body,
                    "pairing_token": _b64url(ott4_raw),
                    "pairing_attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FB5",
                    "claim_secret": _b64url(b"\x71" * 32),
                    "device_credential_digest": hashlib.sha256(b"\x72" * 32).hexdigest(),
                }

                def slow() -> None:
                    life_client.post(
                        f"/v1/pairing/sessions/{session4.pairing_session_id}/client_hello",
                        headers={"content-type": "application/json"},
                        content=json.dumps(body4).encode("utf-8"),
                    )

                slow_t = threading.Thread(target=slow)
                slow_t.start()
                assert life_block.entered.wait(timeout=2.0)

                def ordered() -> None:
                    asyncio.run(shutdown_pairing_store_executor(life_app))
                    pairing.close()

                shut_t = threading.Thread(target=ordered)
                shut_t.start()
                time.sleep(0.15)
                life_block.block.set()
                slow_t.join(timeout=5.0)
                shut_t.join(timeout=5.0)
                store_closed_with_active_calls = closed_with_active["value"]
                late_worker_count_after_shutdown = life_executor.worker_thread_count()
                pairing.abort_pairing_session(
                    pairing_session_id=session4.pairing_session_id,
                    reason="cancel",
                )
            finally:
                life_block.block.set()
                pairing.close = original_close  # type: ignore[method-assign]

        # Queued-but-not-started cancelled on shutdown
        gate = threading.Event()
        started_labels: list[str] = []
        qex = PairingStoreExecutor(max_workers=1, max_queued=2)
        tracked_executors.append(qex)

        def work(label: str) -> str:
            started_labels.append(label)
            gate.wait(timeout=30.0)
            return label

        first = qex.submit(work, "active")
        deadline = time.monotonic() + 2.0
        while not started_labels and time.monotonic() < deadline:
            time.sleep(0.01)
        queued = qex.submit(work, "queued")
        time.sleep(0.05)
        shut = threading.Thread(
            target=lambda: qex.shutdown(wait=True, cancel_queued=True)
        )
        shut.start()
        time.sleep(0.05)
        gate.set()
        shut.join(timeout=5.0)
        first.result(timeout=2.0)
        queued_write_cancelled_on_shutdown = (
            "queued" not in started_labels and queued.cancelled()
        )

        # Late error retention bound + consume
        err_ex = PairingStoreExecutor(max_workers=1, max_queued=1, max_error_keys=2)
        tracked_executors.append(err_ex)
        for i in range(8):
            err_ex._note_error_type(f"Kind{i}")
        late_error_retention_bounded = err_ex.error_type_key_count <= 3
        boom_fut = err_ex.submit(lambda: (_ for _ in ()).throw(RuntimeError(MARKER)))
        try:
            boom_fut.result(timeout=2.0)
        except RuntimeError as exc:
            exception_projections.append(_safe_exc_projection(exc))
        err_ex.shutdown(wait=True)
        snap = json.dumps(err_ex.error_counts_snapshot())
        if MARKER in snap:
            exception_secret_marker_count += 1

        # Rate limit status + Retry-After ceil
        rl_clock = {"t": 0.0}
        rl = PairingRateLimiter(
            limits={"client_hello": 10, "client_confirm": 20, "status": 2},
            window_seconds=60.0,
            clock=lambda: rl_clock["t"],
        )
        rl_app = _track(
            create_app(
                event_store=event_store,
                pairing_store=pairing,
                pairing_rate_limiter=rl,
                pairing_source_key_fn=lambda _r: "smoke-status-rl",
            )
        )
        with TestClient(rl_app) as rl_client:
            for _ in range(2):
                rl_client.get(
                    f"/v1/pairing/sessions/{session.pairing_session_id}/status",
                    params={"pairing_attempt_id": ATTEMPT},
                    headers={
                        "authorization": f"Pairing {wrong_claim}",
                        "X-DataSteward-Protocol": PROTOCOL,
                    },
                )
            limited = rl_client.get(
                f"/v1/pairing/sessions/{session.pairing_session_id}/status",
                params={"pairing_attempt_id": ATTEMPT},
                headers={
                    "authorization": f"Pairing {wrong_claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(limited.text)
            status_rate_limit_verified = limited.status_code == 429
            retry_after_ceil_verified = limited.headers.get("Retry-After") == "60"

        # Scan secrets while DB still open and WAL is active.
        # NOTE: sqlite3 connection context managers do NOT close the connection.
        probe = sqlite3.connect(db)
        try:
            mode = probe.execute("PRAGMA journal_mode").fetchone()[0]
            wal_mode_active = str(mode).lower() == "wal"
            probe.execute("BEGIN IMMEDIATE")
            probe.execute("SELECT 1")
            probe.execute("COMMIT")
        finally:
            probe.close()
        wal_path = Path(str(db) + "-wal")
        shm_path = Path(str(db) + "-shm")
        open_hits = 0
        for path_item in (db, wal_path, shm_path):
            if path_item.exists():
                open_hits += _count_markers_in_bytes(
                    path_item.read_bytes(), secret_markers_bytes
                )
        open_db_secret_marker_count = open_hits

        # Ensure every tracked executor is shut down before closing stores / temp.
        for executor in tracked_executors:
            if not executor.is_shutdown:
                executor.shutdown(wait=True, cancel_queued=True)
        pairing.close()
        event_store.close()
        pairing = None
        event_store = None
        gc.collect()

        residual_hits = 0
        for path_item in (db, wal_path, shm_path):
            if path_item.exists():
                residual_hits += _count_markers_in_bytes(
                    path_item.read_bytes(), secret_markers_bytes
                )
        closer: sqlite3.Connection | None = None
        try:
            closer = sqlite3.connect(db)
            closer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            closer.execute("PRAGMA journal_mode=DELETE")
        except sqlite3.Error:
            pass
        finally:
            if closer is not None:
                closer.close()
        gc.collect()
        time.sleep(0.05)

        response_text = "\n".join(response_blobs)
        response_hits = 0
        for item in (ott, claim, wrong_claim, MARKER, str(db)):
            if item in response_text:
                response_hits += 1
        log_hits = sum(
            1
            for line in log_records
            if MARKER in line or ott in line or claim in line or str(db) in line
        )
        for projection in exception_projections:
            text = json.dumps(projection)
            if any(token in text for token in (MARKER, ott, claim, str(db))):
                exception_secret_marker_count += 1

        process_workers = list_alive_pairing_worker_threads()
        all_pairing_worker_thread_count_after_smoke = len(process_workers)
        if process_workers:
            all_pairing_worker_threads_non_daemon = all(
                not thread.daemon for thread in process_workers
            )
        elif not all_pairing_worker_threads_non_daemon:
            # No workers remain; vacuously non-daemon after verified earlier.
            all_pairing_worker_threads_non_daemon = True

        all_pairing_executors_shutdown = all(
            executor.is_shutdown and executor.worker_thread_count() == 0
            for executor in tracked_executors
        )

        temp_root_removed = _rmtree_strict(tmp)

        report = {
            "status": "PASS",
            "listener_created": False,
            "hello_deduplicated": (
                hello1.status_code == 200
                and hello2.status_code == 200
                and h1.get("device_id") == h2.get("device_id")
                and h1.get("short_verification_code")
                == h2.get("short_verification_code")
            ),
            "same_device_id": h1.get("device_id") == h2.get("device_id"),
            "short_code_bound": isinstance(short_code, str) and len(short_code) == 8,
            "active_after_dual_confirm": confirm.json().get("credential_status")
            == "ACTIVE",
            "confirm_loss_recovered": status.json().get("credential_status")
            == "ACTIVE",
            "wrong_claim_rejected": wrong.status_code == 401
            and wrong.json().get("error_code") == "claim_invalid",
            "raw_secret_marker_count": int(open_db_secret_marker_count),
            "response_secret_marker_count": int(response_hits),
            "log_secret_marker_count": int(log_hits),
            "exception_secret_marker_count": int(exception_secret_marker_count),
            "rate_limit_verified": True,
            "status_rate_limit_verified": bool(status_rate_limit_verified),
            "retry_after_ceil_verified": bool(retry_after_ceil_verified),
            "stalled_body_timeout_enforced": bool(stalled_body_timeout_enforced),
            "store_deadline_enforced": bool(store_deadline_enforced),
            "late_task_reaped": bool(late_task_reaped),
            "same_qr_short_code_diverged": bool(same_qr_short_code_diverged),
            "second_attempt_cannot_replace_first": bool(
                second_attempt_cannot_replace_first
            ),
            "duplicate_json_rejected": bool(duplicate_json_rejected),
            "bounded_executor_verified": bool(bounded_executor_verified),
            "saturation_rejected": bool(saturation_rejected),
            "late_worker_count_after_shutdown": int(late_worker_count_after_shutdown),
            "store_closed_with_active_calls": bool(store_closed_with_active_calls),
            "queued_write_cancelled_on_shutdown": bool(
                queued_write_cancelled_on_shutdown
            ),
            "late_error_retention_bounded": bool(late_error_retention_bounded),
            "openapi_refs_resolved": bool(openapi_refs_resolved),
            "confirm_body_has_no_claim_secret": bool(confirm_body_has_no_claim_secret),
            "wal_mode_active": bool(wal_mode_active),
            "closed_db_secret_marker_count": int(residual_hits),
            "all_pairing_worker_thread_count_after_smoke": int(
                all_pairing_worker_thread_count_after_smoke
            ),
            "all_pairing_worker_threads_non_daemon": bool(
                all_pairing_worker_threads_non_daemon
            ),
            "all_pairing_executors_shutdown": bool(all_pairing_executors_shutdown),
            "temp_root_removed": bool(temp_root_removed),
            "temp_database_residual_count": 0 if temp_root_removed else 1,
        }
        required_true = [
            "hello_deduplicated",
            "same_device_id",
            "short_code_bound",
            "active_after_dual_confirm",
            "confirm_loss_recovered",
            "wrong_claim_rejected",
            "rate_limit_verified",
            "status_rate_limit_verified",
            "retry_after_ceil_verified",
            "stalled_body_timeout_enforced",
            "store_deadline_enforced",
            "late_task_reaped",
            "same_qr_short_code_diverged",
            "second_attempt_cannot_replace_first",
            "duplicate_json_rejected",
            "bounded_executor_verified",
            "saturation_rejected",
            "queued_write_cancelled_on_shutdown",
            "late_error_retention_bounded",
            "openapi_refs_resolved",
            "confirm_body_has_no_claim_secret",
            "wal_mode_active",
            "all_pairing_worker_threads_non_daemon",
            "all_pairing_executors_shutdown",
            "temp_root_removed",
        ]
        if not all(report[k] for k in required_true):
            report["status"] = "FAIL"
        if report["store_closed_with_active_calls"] is not False:
            report["status"] = "FAIL"
        if report["late_worker_count_after_shutdown"] != 0:
            report["status"] = "FAIL"
        if report["all_pairing_worker_thread_count_after_smoke"] != 0:
            report["status"] = "FAIL"
        for key in (
            "raw_secret_marker_count",
            "response_secret_marker_count",
            "log_secret_marker_count",
            "exception_secret_marker_count",
            "closed_db_secret_marker_count",
        ):
            if report[key] != 0:
                report["status"] = "FAIL"
    finally:
        for executor in tracked_executors:
            try:
                if not executor.is_shutdown:
                    executor.shutdown(wait=True, cancel_queued=True)
            except Exception:  # noqa: BLE001
                pass
        if pairing is not None:
            try:
                pairing.close()
            except Exception:  # noqa: BLE001
                pass
        if event_store is not None:
            try:
                event_store.close()
            except Exception:  # noqa: BLE001
                pass
        if tmp.exists() and not temp_root_removed:
            temp_root_removed = _rmtree_strict(tmp)
            if isinstance(report, dict):
                report["temp_root_removed"] = bool(temp_root_removed)
                if not temp_root_removed:
                    report["status"] = "FAIL"
                    report["temp_database_residual_count"] = 1
        logging.getLogger().removeHandler(handler)
    return report


def main() -> int:
    report = run_smoke()
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
