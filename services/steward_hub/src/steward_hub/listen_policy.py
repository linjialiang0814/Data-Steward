"""Fail-closed listener policy for loopback and explicitly authorized LAN modes."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

LISTEN_DISABLED = "disabled"
LISTEN_LOOPBACK_ONLY = "loopback-only"
LISTEN_PAIRING_ONLY = "pairing-only"
LISTEN_AUTHENTICATED_SERVICE = "authenticated-service"
LISTEN_MODES = frozenset(
    {
        LISTEN_DISABLED,
        LISTEN_LOOPBACK_ONLY,
        LISTEN_PAIRING_ONLY,
        LISTEN_AUTHENTICATED_SERVICE,
    }
)

LOOPBACK_HOST = "127.0.0.1"
TRANSPORT_SCOPE_LOOPBACK = "loopback_only"
TRANSPORT_SCOPE_PRIVATE_LAN_PAIRING = "private_lan_pairing_only"
TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED = "private_lan_authenticated_service"

_PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class ListenPolicyError(ValueError):
    """Stable pre-listen policy rejection with no host value in the message."""


@dataclass(frozen=True)
class ListenPolicy:
    mode: str
    host: str
    listener_enabled: bool
    private_lan: bool
    business_routes_enabled: bool
    transport_scope: str


def resolve_listen_policy(
    *,
    mode: object,
    host: object,
    private_lan_authorized: object = False,
) -> ListenPolicy:
    """Validate all listener choices before identity, database, or socket work."""
    if not isinstance(mode, str) or mode not in LISTEN_MODES:
        raise ListenPolicyError("listen_mode_invalid")
    if not isinstance(host, str) or not host or host != host.strip():
        raise ListenPolicyError("bind_host_invalid")
    if not isinstance(private_lan_authorized, bool):
        raise ListenPolicyError("private_lan_authorization_invalid")

    if mode in {LISTEN_DISABLED, LISTEN_LOOPBACK_ONLY}:
        if host != LOOPBACK_HOST:
            raise ListenPolicyError("loopback_bind_required")
        if private_lan_authorized:
            raise ListenPolicyError("private_lan_authorization_unexpected")
        return ListenPolicy(
            mode=mode,
            host=host,
            listener_enabled=mode != LISTEN_DISABLED,
            private_lan=False,
            business_routes_enabled=True,
            transport_scope=TRANSPORT_SCOPE_LOOPBACK,
        )

    if not private_lan_authorized:
        raise ListenPolicyError("private_lan_authorization_required")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ListenPolicyError("private_lan_ipv4_required") from None
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in _PRIVATE_IPV4_NETWORKS
    ):
        raise ListenPolicyError("private_lan_ipv4_required")

    pairing_only = mode == LISTEN_PAIRING_ONLY
    return ListenPolicy(
        mode=mode,
        host=str(address),
        listener_enabled=True,
        private_lan=True,
        business_routes_enabled=not pairing_only,
        transport_scope=(
            TRANSPORT_SCOPE_PRIVATE_LAN_PAIRING
            if pairing_only
            else TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED
        ),
    )
