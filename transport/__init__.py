"""
Transport module - Transport layer abstraction (Cloudflare, Tor, WireGuard, LAN)
"""

from .cloudflare import (
    cloudflared_exists,
    start_cloudflare_tunnel,
    stop_cloudflare_tunnel,
    build_relay_link,
    strip_fragment,
    parse_invite,
    CloudflareTunnel
)

__all__ = [
    'cloudflared_exists',
    'start_cloudflare_tunnel',
    'stop_cloudflare_tunnel',
    'build_relay_link',
    'strip_fragment',
    'parse_invite',
    'CloudflareTunnel'
]
