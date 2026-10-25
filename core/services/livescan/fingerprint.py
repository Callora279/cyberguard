"""Read-only version fingerprinting from benign HTTP responses.
A couple of ordinary GET/HEAD requests — the same bytes `curl -I` sends.
No auth bypass, no injection, no crafted/oversized payloads."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
import httpx

_PHP = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)
_NGINX = re.compile(r"nginx/(\d+\.\d+\.\d+)", re.I)
_APACHE = re.compile(r"Apache/(\d+\.\d+\.\d+)", re.I)

@dataclass
class Fingerprint:
    target_url: str
    reachable: bool = False
    server: str | None = None
    powered_by: str | None = None
    php_version: str | None = None
    nginx_version: str | None = None
    apache_version: str | None = None
    headers: dict = field(default_factory=dict)

async def fingerprint(target_url: str, timeout: float = 5.0) -> Fingerprint:
    fp = Fingerprint(target_url=target_url)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False,
            headers={"User-Agent": "CyberGuard-LiveScan/1.0"},
        ) as c:
            resp = await c.head(target_url)
            if resp.status_code >= 400 or "server" not in {k.lower() for k in resp.headers}:
                resp = await c.get(target_url)          # plain GET fallback, nothing crafted
            fp.reachable = True
            fp.headers = dict(resp.headers)
            fp.server = resp.headers.get("Server")
            fp.powered_by = resp.headers.get("X-Powered-By")
            blob = f"{fp.server or ''} {fp.powered_by or ''}"
            if m := _PHP.search(blob): fp.php_version = m.group(1)
            if m := _NGINX.search(blob): fp.nginx_version = m.group(1)
            if m := _APACHE.search(blob): fp.apache_version = m.group(1)
    except (httpx.HTTPError, OSError):
        fp.reachable = False
    return fp
