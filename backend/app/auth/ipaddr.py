"""Client-IP resolution that refuses spoofable forwarder headers.

The ``X-Forwarded-For`` header can be set by anyone, so it must never be
trusted blindly. We only honour it when the socket peer (the client we
actually talked to) is a configured reverse proxy; otherwise we use the peer's
address. This stops attackers from rotating the header to bypass rate limits
or from poisoning the IP recorded in the audit log.
"""

import ipaddress

from fastapi import Request

from app.config import get_settings


def _is_trusted(peer_ip: str, trusted: list[str]) -> bool:
    """Return True when ``peer_ip`` is inside any configured proxy network."""
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for entry in trusted:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


def client_ip(request: Request) -> str | None:
    """Return the effective client IP for rate limiting and audit records."""
    peer = request.client.host if request.client else None
    if peer is None:
        return None

    settings = get_settings()
    trusted = [entry.strip() for entry in settings.TRUSTED_PROXIES.split(",") if entry.strip()]
    if not _is_trusted(peer, trusted):
        return peer

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return peer