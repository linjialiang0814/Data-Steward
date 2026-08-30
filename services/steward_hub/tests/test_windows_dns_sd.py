from __future__ import annotations

import asyncio
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from steward_hub.supervised_shared_session_runtime import _serve_dual
from steward_hub.windows_dns_sd import (
    DnsSdAdvertisement,
    DnsSdAdvertisementError,
    WindowsDnsSdAdvertiser,
)


class _FakeServer:
    def __init__(self, *, fail: bool = False) -> None:
        self.started = False
        self.should_exit = False
        self.fail = fail

    async def serve(self) -> None:
        if self.fail:
            return
        self.started = True
        while not self.should_exit:
            await asyncio.sleep(0.001)


class _Advertiser:
    def __init__(self, local: _FakeServer, lan: _FakeServer, *, fail: bool = False) -> None:
        self.local = local
        self.lan = lan
        self.fail = fail
        self.start_count = 0
        self.close_count = 0
        self.close_after_stop_signal = False

    def start(self) -> bool:
        self.start_count += 1
        if not (self.local.started and self.lan.started):
            raise AssertionError("advertisement_started_before_listeners")
        if self.fail:
            raise RuntimeError("native_detail_must_not_escape")
        return True

    def close(self) -> None:
        self.close_count += 1
        self.close_after_stop_signal = self.local.should_exit and self.lan.should_exit


class _Registration:
    def __init__(self) -> None:
        self.advertisements: list[DnsSdAdvertisement] = []
        self.closed: list[object] = []

    def register(self, advertisement: DnsSdAdvertisement) -> object:
        self.advertisements.append(advertisement)
        return object()

    def deregister(self, handle: object) -> None:
        self.closed.append(handle)


class WindowsDnsSdAdvertiserTest(unittest.TestCase):
    def test_allow_list_identity_label_and_idempotent_lifecycle(self) -> None:
        registration = _Registration()
        advertiser = WindowsDnsSdAdvertiser(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            private_host="192.168.1.15",
            port=9443,
            registration=registration,
        )
        self.assertTrue(advertiser.start())
        self.assertTrue(advertiser.start())
        self.assertEqual(1, len(registration.advertisements))
        value = registration.advertisements[0]
        self.assertRegex(value.instance_name, r"^DataSteward-[0-9a-f]{12}\._datasteward\._tcp\.local$")
        self.assertRegex(value.host_name, r"^datasteward-[0-9a-f]{12}$")
        self.assertEqual("192.168.1.15", value.private_host)
        self.assertEqual(9443, value.port)
        self.assertEqual(
            {"hub_id", "protocol_version", "cert_fingerprint", "pairing_available"},
            {key for key, _ in value.properties},
        )
        rendered = repr(value)
        for forbidden in ("pairing_token", "claim_secret", "credential", "Authorization"):
            self.assertNotIn(forbidden, rendered)
        advertiser.close()
        advertiser.close()
        self.assertEqual(1, len(registration.closed))

    def test_invalid_or_public_host_fails_before_native_registration(self) -> None:
        registration = _Registration()
        for host in ("127.0.0.1", "8.8.8.8", "not-an-ip"):
            with self.subTest(host=host), self.assertRaises(Exception):
                WindowsDnsSdAdvertiser(
                    hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    cert_fingerprint="a" * 64,
                    private_host=host,
                    port=9443,
                    registration=registration,
                )
        self.assertEqual([], registration.advertisements)

    def test_start_after_close_fails_closed(self) -> None:
        advertiser = WindowsDnsSdAdvertiser(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            private_host="10.0.0.5",
            port=9443,
            registration=_Registration(),
        )
        advertiser.close()
        with self.assertRaisesRegex(DnsSdAdvertisementError, "dns_sd_closed"):
            advertiser.start()

    def test_runtime_advertises_only_after_listeners_and_closes_in_order(self) -> None:
        local = _FakeServer()
        lan = _FakeServer()
        advertiser = _Advertiser(local, lan)
        payload: dict[str, object] = {"event": "fixture_ready"}
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("shutdown\n")), contextlib.redirect_stdout(stdout):
            clean = asyncio.run(
                _serve_dual(
                    local_server=local,  # type: ignore[arg-type]
                    lan_server=lan,  # type: ignore[arg-type]
                    ready_payload=payload,
                    advertiser=advertiser,  # type: ignore[arg-type]
                )
            )
        self.assertTrue(clean)
        self.assertEqual(1, advertiser.start_count)
        self.assertEqual(1, advertiser.close_count)
        self.assertTrue(advertiser.close_after_stop_signal)
        self.assertTrue(json.loads(stdout.getvalue())["lan_discovery_available"])

    def test_advertisement_failure_degrades_without_stopping_hub(self) -> None:
        local = _FakeServer()
        lan = _FakeServer()
        advertiser = _Advertiser(local, lan, fail=True)
        payload: dict[str, object] = {"event": "fixture_ready"}
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("shutdown\n")), contextlib.redirect_stdout(stdout):
            clean = asyncio.run(
                _serve_dual(
                    local_server=local,  # type: ignore[arg-type]
                    lan_server=lan,  # type: ignore[arg-type]
                    ready_payload=payload,
                    advertiser=advertiser,  # type: ignore[arg-type]
                )
            )
        self.assertTrue(clean)
        self.assertFalse(json.loads(stdout.getvalue())["lan_discovery_available"])
        self.assertEqual(1, advertiser.close_count)


if __name__ == "__main__":
    unittest.main()
