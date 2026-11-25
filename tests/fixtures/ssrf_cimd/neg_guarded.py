import ipaddress
import socket
from urllib.parse import urlparse

import httpx

def _check(url: str) -> None:
    p = urlparse(url)
    if p.scheme != "https":
        raise ValueError("https only")
    for info in socket.getaddrinfo(p.hostname, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("blocked")

def fetch_client_metadata(client_id: str) -> dict:
    _check(client_id)
    return httpx.get(client_id, follow_redirects=False, timeout=5).json()
