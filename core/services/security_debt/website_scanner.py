"""Lightweight external website security scan (ShieldGuard-style).

Non-intrusive: a small number of GET requests to the target origin. Checks
transport security, response-header hardening, cookie flags, information
disclosure and a couple of common exposed-path mistakes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from core.utils.logger import get_logger

logger = get_logger("security_debt.website_scanner")

_SECURITY_HEADERS = {
    "strict-transport-security": ("high", "HSTS not set — connections can be downgraded to HTTP"),
    "content-security-policy": ("high", "No Content-Security-Policy — limited XSS mitigation"),
    "x-frame-options": ("medium", "No X-Frame-Options / frame-ancestors — clickjacking risk"),
    "x-content-type-options": ("low", "No X-Content-Type-Options: nosniff — MIME sniffing"),
    "referrer-policy": ("low", "No Referrer-Policy — referrer data may leak to third parties"),
    "permissions-policy": ("low", "No Permissions-Policy — browser features not restricted"),
}
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-runtime")
_EXPOSED_PATHS = {
    "/.git/HEAD": ("critical", "Git repository exposed at /.git/"),
    "/.env": ("critical", "Environment file exposed at /.env"),
    "/.well-known/security.txt": None,  # informational: presence is good
}
_SEVERITY_WEIGHT = {"critical": 40, "high": 22, "medium": 12, "low": 5, "info": 0}


def _finding(check: str, severity: str, title: str, detail: str = "") -> dict:
    return {"check": check, "severity": severity, "title": title, "detail": detail}


def scan(url: str, *, timeout: float = 12.0) -> dict:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("invalid website URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    https_origin = f"https://{parsed.netloc}"

    findings: list[dict] = []
    checks_run = 0
    reachable = True

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "CyberGuard-Scanner/1.0"}) as c:
            # 1. HTTPS reachability + certificate
            try:
                resp = c.get(https_origin)
                checks_run += 1
            except httpx.ConnectError as exc:
                findings.append(_finding("https", "high", "HTTPS not available", str(exc)))
                resp = c.get(origin)
            except httpx.HTTPError as exc:
                reachable = False
                logger.warning("website scan could not reach %s: %s", url, exc)
                return _result(url, origin, [_finding("reachability", "info", "Target not reachable", str(exc))], 0, False)

            final_url = str(resp.url)
            if not final_url.startswith("https://"):
                findings.append(_finding("tls-redirect", "high", "Site does not enforce HTTPS", f"landed on {final_url}"))

            # 2. HTTP -> HTTPS redirect
            try:
                http_resp = c.get(f"http://{parsed.netloc}", follow_redirects=False)
                checks_run += 1
                loc = http_resp.headers.get("location", "")
                if not (http_resp.status_code in (301, 302, 307, 308) and loc.startswith("https://")):
                    findings.append(_finding("http-redirect", "medium", "HTTP is not redirected to HTTPS",
                                             f"status {http_resp.status_code}"))
            except httpx.HTTPError:
                pass

            # 3. security headers
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for name, (sev, msg) in _SECURITY_HEADERS.items():
                checks_run += 1
                if name not in headers:
                    findings.append(_finding(f"header:{name}", sev, msg))

            # 4. information disclosure
            for h in _DISCLOSURE_HEADERS:
                if h in headers and headers[h].strip():
                    findings.append(_finding(f"disclosure:{h}", "low",
                                             f"Server reveals technology via '{h}' header", headers[h][:120]))

            # 5. cookie flags
            for cookie in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
                lc = cookie.lower()
                missing = [flag for flag in ("secure", "httponly") if flag not in lc]
                if missing:
                    findings.append(_finding("cookie", "medium",
                                             f"Cookie missing {', '.join(missing)} flag(s)", cookie.split("=")[0]))
                if "samesite" not in lc:
                    findings.append(_finding("cookie", "low", "Cookie has no SameSite attribute", cookie.split("=")[0]))

            # 6. exposed paths
            for path, meta in _EXPOSED_PATHS.items():
                checks_run += 1
                try:
                    r = c.get(urljoin(origin + "/", path.lstrip("/")), follow_redirects=False)
                except httpx.HTTPError:
                    continue
                if meta is None:
                    continue
                sev, title = meta
                if r.status_code == 200 and r.text and "<!doctype html" not in r.text[:200].lower():
                    findings.append(_finding(f"exposed:{path}", sev, title, f"HTTP 200 at {path}"))
    except Exception as exc:  # noqa: BLE001
        logger.exception("website scan failed for %s", url)
        return _result(url, origin, [_finding("error", "info", "Scan error", str(exc))], checks_run, reachable)

    return _result(url, origin, findings, checks_run, reachable)


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _result(url: str, origin: str, findings: list[dict], checks_run: int, reachable: bool) -> dict:
    penalty = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    score = max(0.0, 100.0 - penalty)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "url": url,
        "origin": origin,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "reachable": reachable,
        "checks_run": checks_run,
        "score": round(score, 1),
        "grade": _grade(score),
        "by_severity": by_sev,
        "findings": sorted(findings, key=lambda f: _SEVERITY_WEIGHT.get(f["severity"], 0), reverse=True),
    }
