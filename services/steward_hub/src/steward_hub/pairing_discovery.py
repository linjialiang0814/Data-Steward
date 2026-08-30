"""Pure-data mDNS advertisement projection (no network I/O)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .pairing_codec import PROTOCOL_VERSION

ALLOWED_MDNS_KEYS = frozenset(
    {
        "hub_id",
        "protocol_version",
        "host",
        "port",
        "cert_fingerprint",
        "pairing_available",
    }
)
FORBIDDEN_MDNS_KEYS = frozenset(
    {
        "pairing_token",
        "ott",
        "claim_secret",
        "device_credential_secret",
        "device_credential_digest",
        "credential_digest",
        "short_verification_code",
        "authorization",
        "Authorization",
        "qr_json",
        "database_path",
        "db_path",
    }
)

_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class PairingDiscoveryError(Exception):
    def __init__(self, message: str = "mdns_projection_invalid") -> None:
        super().__init__(message)


def build_mdns_projection(
    *,
    hub_id: str,
    host: str,
    port: int,
    cert_fingerprint: str,
    pairing_available: bool,
    protocol_version: str = PROTOCOL_VERSION,
) -> dict[str, Any]:
    projection = {
        "hub_id": hub_id,
        "protocol_version": protocol_version,
        "host": host,
        "port": port,
        "cert_fingerprint": cert_fingerprint,
        "pairing_available": pairing_available,
    }
    validate_mdns_projection(projection)
    return projection


def validate_mdns_projection(projection: dict[str, Any]) -> None:
    if not isinstance(projection, dict):
        raise PairingDiscoveryError("mdns_projection_invalid")
    keys = set(projection.keys())
    forbidden_hit = keys & FORBIDDEN_MDNS_KEYS
    if forbidden_hit:
        raise PairingDiscoveryError("mdns_forbidden_field")
    if keys != ALLOWED_MDNS_KEYS:
        raise PairingDiscoveryError("mdns_projection_invalid")
    hub_id = projection["hub_id"]
    if not isinstance(hub_id, str) or not _ULID_RE.fullmatch(hub_id):
        raise PairingDiscoveryError("mdns_projection_invalid")
    if projection["protocol_version"] != PROTOCOL_VERSION:
        raise PairingDiscoveryError("mdns_projection_invalid")
    host = projection["host"]
    if not isinstance(host, str):
        raise PairingDiscoveryError("mdns_projection_invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise PairingDiscoveryError("mdns_host_invalid") from None
    if address.version != 4 or not _private_ipv4(address):
        raise PairingDiscoveryError("mdns_host_not_private")
    port = projection["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise PairingDiscoveryError("mdns_projection_invalid")
    fp = projection["cert_fingerprint"]
    if not isinstance(fp, str) or not _DIGEST_RE.fullmatch(fp):
        raise PairingDiscoveryError("mdns_projection_invalid")
    available = projection["pairing_available"]
    if not isinstance(available, bool):
        raise PairingDiscoveryError("mdns_projection_invalid")


def _private_ipv4(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if not isinstance(address, ipaddress.IPv4Address):
        return False
    value = int(address)
    ranges = (
        (int(ipaddress.IPv4Address("10.0.0.0")), 8),
        (int(ipaddress.IPv4Address("172.16.0.0")), 12),
        (int(ipaddress.IPv4Address("192.168.0.0")), 16),
    )
    return any(value >> (32 - prefix) == base >> (32 - prefix) for base, prefix in ranges)
