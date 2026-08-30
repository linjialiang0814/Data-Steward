"""Product TLS certificate generation and policy verification (cryptography)."""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from .errors import TlsCertificatePolicyError
from .manifest import require_fingerprint_sha256

CERT_VALIDITY_DAYS = 365
NOT_BEFORE_SKEW = timedelta(minutes=5)
# Allow small clock drift when validating measured validity span.
MAX_VALIDITY_SPAN = timedelta(days=CERT_VALIDITY_DAYS) + NOT_BEFORE_SKEW + timedelta(minutes=1)
MAX_NOT_BEFORE_FUTURE_SKEW = timedelta(minutes=1)
SUBJECT_CN = "DataSteward Local Hub"
LOOPBACK_IP = ipaddress.IPv4Address("127.0.0.1")
FIXED_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT_CN)])

# oid -> critical flag required by generation policy
_EXTENSION_CRITICALITY = {
    ExtensionOID.BASIC_CONSTRAINTS: True,
    ExtensionOID.KEY_USAGE: True,
    ExtensionOID.EXTENDED_KEY_USAGE: False,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: False,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: False,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: False,
}
_REQUIRED_EXTENSION_OIDS = frozenset(_EXTENSION_CRITICALITY)


@dataclass(frozen=True)
class GeneratedMaterial:
    """PEM artifacts + fingerprint (no password retained)."""

    cert_pem: bytes
    encrypted_key_pem: bytes
    cert_fingerprint_sha256: str
    not_before: datetime
    not_after: datetime


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_hub_tls_material(
    *,
    password: bytearray,
    clock: Any = None,
) -> GeneratedMaterial:
    """
    Generate ECDSA P-256 key + self-signed Hub certificate.

    ``password`` must be a mutable bytearray of 32 CSPRNG bytes; caller wipes it.
    """
    if not isinstance(password, bytearray) or len(password) != 32:
        raise TlsCertificatePolicyError("password_invalid")
    now = clock() if clock is not None else _utc_now()
    if now.tzinfo is None:
        raise TlsCertificatePolicyError("clock_must_be_utc")
    now = now.astimezone(timezone.utc)
    not_before = now - NOT_BEFORE_SKEW
    not_after = now + timedelta(days=CERT_VALIDITY_DAYS)

    private_key = ec.generate_private_key(ec.SECP256R1())
    if not isinstance(private_key, EllipticCurvePrivateKey):
        raise TlsCertificatePolicyError("key_type_invalid")

    serial = int.from_bytes(secrets.token_bytes(16), "big") | 1
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = (
        x509.CertificateBuilder()
        .subject_name(FIXED_SUBJECT)
        .issuer_name(FIXED_SUBJECT)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(LOOPBACK_IP)]),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski.digest,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    )
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    verify_certificate_policy(certificate)

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = require_fingerprint_sha256(hashlib.sha256(der).hexdigest())

    pwd_bytes = bytes(password)
    try:
        encrypted_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd_bytes),
        )
    finally:
        del pwd_bytes

    if b"BEGIN ENCRYPTED PRIVATE KEY" not in encrypted_key_pem:
        raise TlsCertificatePolicyError("encrypted_key_missing")
    if b"BEGIN PRIVATE KEY" in encrypted_key_pem:
        raise TlsCertificatePolicyError("plaintext_key_forbidden")

    return GeneratedMaterial(
        cert_pem=cert_pem,
        encrypted_key_pem=encrypted_key_pem,
        cert_fingerprint_sha256=fingerprint,
        not_before=not_before,
        not_after=not_after,
    )


def load_certificate_pem(cert_pem: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:  # noqa: BLE001
        raise TlsCertificatePolicyError("cert_unreadable") from exc


def verify_certificate_policy(certificate: x509.Certificate) -> None:
    """Fail-closed policy checks for Hub loopback identity certificates."""
    if certificate.version != x509.Version.v3:
        raise TlsCertificatePolicyError("cert_version_invalid")

    now = _utc_now()
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_before > now + MAX_NOT_BEFORE_FUTURE_SKEW:
        raise TlsCertificatePolicyError("not_before_too_future")
    if not_before > now or not_after < now:
        raise TlsCertificatePolicyError("cert_not_currently_valid")
    if not_after <= not_before:
        raise TlsCertificatePolicyError("cert_validity_inverted")
    if (not_after - not_before) > MAX_VALIDITY_SPAN:
        raise TlsCertificatePolicyError("cert_validity_too_long")

    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TlsCertificatePolicyError("key_type_invalid")
    if public_key.curve.name != "secp256r1":
        raise TlsCertificatePolicyError("curve_invalid")

    if certificate.subject != FIXED_SUBJECT or certificate.issuer != FIXED_SUBJECT:
        raise TlsCertificatePolicyError("subject_issuer_invalid")
    if certificate.signature_hash_algorithm is None or (
        certificate.signature_hash_algorithm.name != "sha256"
    ):
        raise TlsCertificatePolicyError("signature_hash_invalid")
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception as exc:  # noqa: BLE001
        raise TlsCertificatePolicyError("signature_invalid") from exc

    if certificate.serial_number <= 0:
        raise TlsCertificatePolicyError("serial_invalid")

    present: dict[Any, x509.Extension] = {}
    for extension in certificate.extensions:
        oid = extension.oid
        if oid in present:
            raise TlsCertificatePolicyError("extension_duplicate")
        present[oid] = extension
    if set(present) != _REQUIRED_EXTENSION_OIDS:
        raise TlsCertificatePolicyError("extension_set_invalid")
    for oid, expected_critical in _EXTENSION_CRITICALITY.items():
        if present[oid].critical is not expected_critical:
            raise TlsCertificatePolicyError("extension_criticality_invalid")

    basic = present[ExtensionOID.BASIC_CONSTRAINTS].value
    assert isinstance(basic, x509.BasicConstraints)
    if basic.ca or basic.path_length is not None:
        raise TlsCertificatePolicyError("basic_constraints_invalid")

    usage = present[ExtensionOID.KEY_USAGE].value
    assert isinstance(usage, x509.KeyUsage)
    if not usage.digital_signature:
        raise TlsCertificatePolicyError("key_usage_missing_digital_signature")
    if (
        usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or usage.key_cert_sign
        or usage.crl_sign
    ):
        raise TlsCertificatePolicyError("key_usage_extra")

    eku = present[ExtensionOID.EXTENDED_KEY_USAGE].value
    assert isinstance(eku, x509.ExtendedKeyUsage)
    if list(eku) != [ExtendedKeyUsageOID.SERVER_AUTH]:
        raise TlsCertificatePolicyError("eku_invalid")

    san = present[ExtensionOID.SUBJECT_ALTERNATIVE_NAME].value
    assert isinstance(san, x509.SubjectAlternativeName)
    ips = list(san.get_values_for_type(x509.IPAddress))
    dns = list(san.get_values_for_type(x509.DNSName))
    if dns or len(ips) != 1 or ips[0] != LOOPBACK_IP:
        raise TlsCertificatePolicyError("san_invalid")

    expected_ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    ski = present[ExtensionOID.SUBJECT_KEY_IDENTIFIER].value
    assert isinstance(ski, x509.SubjectKeyIdentifier)
    if ski.digest != expected_ski.digest:
        raise TlsCertificatePolicyError("ski_mismatch")

    aki = present[ExtensionOID.AUTHORITY_KEY_IDENTIFIER].value
    assert isinstance(aki, x509.AuthorityKeyIdentifier)
    if aki.key_identifier != ski.digest:
        raise TlsCertificatePolicyError("aki_key_identifier_mismatch")
    if aki.authority_cert_issuer is not None or aki.authority_cert_serial_number is not None:
        raise TlsCertificatePolicyError("aki_issuer_serial_present")


def certificate_fingerprint_sha256(certificate: x509.Certificate) -> str:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return require_fingerprint_sha256(hashlib.sha256(der).hexdigest())
