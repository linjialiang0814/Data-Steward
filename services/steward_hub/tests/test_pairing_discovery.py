"""Tests for mDNS projection validator (no network)."""

from __future__ import annotations

import unittest

from steward_hub.pairing_discovery import (
    PairingDiscoveryError,
    build_mdns_projection,
    validate_mdns_projection,
)


class PairingDiscoveryTest(unittest.TestCase):
    def test_build_and_validate_private_lan(self) -> None:
        projection = build_mdns_projection(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            host="192.168.1.15",
            port=8443,
            cert_fingerprint="a" * 64,
            pairing_available=True,
        )
        validate_mdns_projection(projection)
        self.assertEqual("192.168.1.15", projection["host"])

    def test_forbidden_fields_fail_closed(self) -> None:
        base = build_mdns_projection(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            host="192.168.1.15",
            port=8443,
            cert_fingerprint="a" * 64,
            pairing_available=False,
        )
        for key, value in (
            ("pairing_token", "x" * 43),
            ("claim_secret", "y" * 43),
            ("device_credential_digest", "b" * 64),
            ("short_verification_code", "2EJ9Y5EW"),
            ("Authorization", "Pairing xxx"),
            ("database_path", "C:/tmp/x.db"),
        ):
            dirty = dict(base)
            dirty[key] = value
            with self.subTest(key=key):
                with self.assertRaises(PairingDiscoveryError):
                    validate_mdns_projection(dirty)

    def test_rejects_non_private_hosts(self) -> None:
        for host in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "localhost"):
            with self.subTest(host=host):
                with self.assertRaises(PairingDiscoveryError):
                    build_mdns_projection(
                        hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
                        host=host,
                        port=8443,
                        cert_fingerprint="a" * 64,
                        pairing_available=True,
                    )


if __name__ == "__main__":
    unittest.main()
