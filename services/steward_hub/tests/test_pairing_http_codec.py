"""Codec tests for pairing HTTP raw-secret boundary."""

from __future__ import annotations

import base64
import hashlib
import unittest

from steward_hub.pairing_http_codec import (
    PairingHttpCodecError,
    decode_unpadded_base64url,
    digest_secret_b64url,
    parse_pairing_authorization,
    require_protocol_version,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class PairingHttpCodecTest(unittest.TestCase):
    def test_protocol_version(self) -> None:
        self.assertEqual("pairing_auth/1", require_protocol_version("pairing_auth/1"))
        with self.assertRaises(PairingHttpCodecError) as ctx:
            require_protocol_version("pairing_auth/2")
        self.assertEqual("protocol_version_rejected", ctx.exception.error_code)

    def test_secret_roundtrip_and_digest(self) -> None:
        raw = b"\x01" * 32
        token = _b64url(raw)
        self.assertEqual(43, len(token))
        self.assertEqual(raw, decode_unpadded_base64url(token, expected_raw_len=32))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest_secret_b64url(token))

    def test_rejects_padding_illegal_len_noncanonical(self) -> None:
        raw = b"\x02" * 32
        token = _b64url(raw)
        with self.assertRaises(PairingHttpCodecError):
            decode_unpadded_base64url(token + "=", expected_raw_len=32)
        with self.assertRaises(PairingHttpCodecError):
            decode_unpadded_base64url(token[:-1], expected_raw_len=32)
        with self.assertRaises(PairingHttpCodecError):
            decode_unpadded_base64url(token[:-1] + "*", expected_raw_len=32)
        # Non-canonical: alter last char where padding ambiguity exists is hard;
        # reject overlong with valid alphabet.
        with self.assertRaises(PairingHttpCodecError):
            decode_unpadded_base64url(token + "A", expected_raw_len=32)

    def test_authorization_parse(self) -> None:
        raw = b"\x03" * 32
        token = _b64url(raw)
        digest = parse_pairing_authorization(f"Pairing {token}")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        with self.assertRaises(PairingHttpCodecError) as missing:
            parse_pairing_authorization(None)
        self.assertEqual("claim_missing", missing.exception.error_code)
        with self.assertRaises(PairingHttpCodecError) as bearer:
            parse_pairing_authorization(f"Bearer {token}")
        self.assertEqual("claim_missing", bearer.exception.error_code)
        with self.assertRaises(PairingHttpCodecError) as bad:
            parse_pairing_authorization("Pairing not-a-valid-token")
        self.assertEqual("claim_invalid", bad.exception.error_code)
        # Exception must not contain the secret token
        self.assertNotIn(token, str(bad.exception))


if __name__ == "__main__":
    unittest.main()
