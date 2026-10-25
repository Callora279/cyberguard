"""Build a digital replica (graph) of the target system.

The twin captures endpoints, authentication flows, data stores and network
topology so the simulation engine can reason about attack paths without
touching production.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from core.utils.logger import get_logger

logger = get_logger("cyber_twin.builder")

_ROUTE_PATTERNS = [
    re.compile(r"@(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),  # express
]


def _discover_endpoints(root: Path) -> list[dict]:
    endpoints: list[dict] = []
    for path in list(root.rglob("*.py")) + list(root.rglob("*.js")) + list(root.rglob("*.ts")):
        if any(p in path.parts for p in ("node_modules", ".venv", "venv")):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for pat in _ROUTE_PATTERNS:
            for m in pat.finditer(text):
                method, route = m.group(1).upper(), m.group(2)
                endpoints.append(
                    {
                        "id": f"{method} {route}",
                        "method": method,
                        "path": route,
                        "file": str(path.relative_to(root)),
                        "auth_required": bool(
                            re.search(r"(Depends\(.*(auth|current_user)|requireAuth|@login_required)", text)
                        ),
                        "handles_input": method in ("POST", "PUT", "PATCH"),
                    }
                )
    return endpoints


def _discover_datastores(root: Path) -> list[dict]:
    stores: list[dict] = []
    seen: set[str] = set()
    for path in root.rglob("*"):
        if path.name in {"docker-compose.yml", "docker-compose.yaml"}:
            text = path.read_text(errors="ignore").lower()
            for kind, label in (("postgres", "PostgreSQL"), ("mysql", "MySQL"),
                                ("redis", "Redis"), ("mongo", "MongoDB")):
                if kind in text and label not in seen:
                    seen.add(label)
                    stores.append({"id": label, "type": label, "network": "internal", "encrypted_at_rest": "false"})
        if path.suffix in {".py", ".js", ".ts"} and path.is_file():
            t = path.read_text(errors="ignore")
            if "sqlite" in t.lower() and "SQLite" not in seen:
                seen.add("SQLite")
                stores.append({"id": "SQLite", "type": "SQLite", "network": "local", "encrypted_at_rest": "false"})
    return stores


def _auth_flows(endpoints: list[dict]) -> list[dict]:
    flows = []
    for e in endpoints:
        if re.search(r"login|token|auth|register|oauth", e["path"], re.IGNORECASE):
            flows.append({"id": e["id"], "path": e["path"], "type": "credential" if "login" in e["path"] else "token"})
    return flows


def build(root: str | Path, *, name: str | None = None) -> dict:
    root = Path(root)
    endpoints = _discover_endpoints(root)
    stores = _discover_datastores(root)
    twin = {
        "name": name or root.name,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "nodes": {
            "endpoints": endpoints,
            "auth_flows": _auth_flows(endpoints),
            "data_stores": stores,
        },
        "topology": {
            "internet_facing": [e["id"] for e in endpoints if not e["path"].startswith("/internal")],
            "internal_only": [e["id"] for e in endpoints if e["path"].startswith("/internal")],
            "trust_boundaries": ["internet->api", "api->datastore"],
        },
        "stats": {
            "endpoint_count": len(endpoints),
            "unauthenticated_endpoints": sum(1 for e in endpoints if not e["auth_required"]),
            "datastore_count": len(stores),
        },
    }
    logger.info("built cyber twin '%s' with %d endpoints", twin["name"], len(endpoints))
    return twin


def save(twin: dict, out_dir: str = ".cyberguard/twins") -> str:
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    fpath = p / f"{twin['name']}.json"
    fpath.write_text(json.dumps(twin, indent=2))
    return str(fpath)


# ---------------------------------------------------------------------------
# URL-based twin: build a twin by crawling a live target instead of reading
# local source. Produces the same ``nodes.endpoints`` shape as build() above
# so simulation_engine's existing simulators work against either twin kind
# unmodified.
# ---------------------------------------------------------------------------
_LOGIN_RE = re.compile(r"login|signin|sign-in|auth|oauth|sso", re.IGNORECASE)
_API_PROBE_PATHS = ["/api", "/api/v1", "/api/v2", "/graphql", "/.well-known/security.txt"]
_MAX_CRAWL_PAGES = 25
_CRAWL_TIMEOUT = 8.0


class _PageExtractor(HTMLParser):
    """Pulls links, forms (+ their inputs) and script sources out of one page."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.scripts: list[str] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._current_form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(), "inputs": []}
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower()})
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlsplit(base), urlsplit(candidate)
    return (not c.netloc) or c.netloc == b.netloc


def _normalise_path(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    return path


def _crawl(start_url: str, *, max_pages: int = _MAX_CRAWL_PAGES) -> dict:
    """Breadth-first same-origin crawl. Returns endpoints, auth flows and
    discovered input fields — no traffic leaves the target's own origin, and
    nothing is submitted (GET-only discovery, safe against production)."""
    root = urlsplit(start_url)
    origin = urlunsplit((root.scheme, root.netloc, "", "", ""))
    seen: set[str] = set()
    queue: list[str] = [start_url]
    endpoints: dict[str, dict] = {}
    api_hints: list[str] = []

    with httpx.Client(follow_redirects=True, timeout=_CRAWL_TIMEOUT, headers={"User-Agent": "CyberGuardAI-CyberTwin/1.0"}) as client:
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            path = _normalise_path(url)
            if path in seen:
                continue
            seen.add(path)
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                logger.info("cyber_twin crawl: %s unreachable (%s)", url, exc)
                continue

            auth_required = resp.status_code in (401, 403)
            handles_input = False
            input_fields: list[dict] = []
            forms_here: list[dict] = []

            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type:
                parser = _PageExtractor()
                try:
                    parser.feed(resp.text)
                except Exception:  # noqa: BLE001 — malformed HTML must not abort the crawl
                    pass
                forms_here = parser.forms
                for form in parser.forms:
                    handles_input = handles_input or bool(form["inputs"])
                    input_fields.extend(form["inputs"])
                for link in parser.links:
                    absolute = urljoin(url, link)
                    if absolute.startswith(("mailto:", "tel:", "javascript:", "#")):
                        continue
                    if _same_origin(origin, absolute) and _normalise_path(absolute) not in seen:
                        queue.append(absolute)

            endpoints[path] = {
                "id": f"GET {path}",
                "method": "GET",
                "path": path,
                "status": resp.status_code,
                "auth_required": auth_required,
                "handles_input": handles_input,
                "input_fields": input_fields,
                "is_login_form": any(any(i["type"] == "password" for i in f["inputs"]) for f in forms_here),
            }
            # a form's own action is a distinct (likely POST) endpoint
            for form in forms_here:
                action_path = _normalise_path(urljoin(url, form["action"])) if form["action"] else path
                method = form["method"] if form["method"] in ("GET", "POST", "PUT", "PATCH", "DELETE") else "POST"
                key = f"{method} {action_path}"
                endpoints[key] = {
                    "id": key,
                    "method": method,
                    "path": action_path,
                    "auth_required": any(i["type"] == "password" for i in form["inputs"]),
                    "handles_input": bool(form["inputs"]),
                    "input_fields": form["inputs"],
                    "is_login_form": any(i["type"] == "password" for i in form["inputs"]),
                }

        for probe in _API_PROBE_PATHS:
            try:
                resp = client.get(urljoin(origin, probe))
            except httpx.HTTPError:
                continue
            if resp.status_code < 404:
                api_hints.append(probe)
                key = f"GET {probe}"
                endpoints.setdefault(
                    key,
                    {
                        "id": key, "method": "GET", "path": probe, "status": resp.status_code,
                        "auth_required": resp.status_code in (401, 403), "handles_input": False,
                        "input_fields": [], "is_login_form": False, "is_api": True,
                    },
                )

    return {"endpoints": list(endpoints.values()), "api_hints": api_hints, "pages_crawled": len(seen)}


def build_from_url(url: str, *, name: str | None = None, max_pages: int = _MAX_CRAWL_PAGES) -> dict:
    """Map the attack surface of a live target: crawl it, discover endpoints,
    identify auth mechanisms (login forms / 401-gated pages), find input
    fields, and flag anything that looks like an API endpoint."""
    if not re.match(r"^https?://", url):
        url = f"https://{url}"
    crawl = _crawl(url, max_pages=max_pages)
    endpoints = crawl["endpoints"]
    login_flows = [
        {"id": e["id"], "path": e["path"], "type": "credential" if e.get("is_login_form") else "endpoint"}
        for e in endpoints
        if e.get("is_login_form") or _LOGIN_RE.search(e["path"])
    ]

    twin = {
        "name": name or urlsplit(url).netloc.replace(":", "_"),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source": "url",
        "target_url": url,
        "nodes": {
            "endpoints": endpoints,
            "auth_flows": login_flows,
            "data_stores": [],  # not directly observable from outside a black-box crawl
        },
        "topology": {
            "internet_facing": [e["id"] for e in endpoints],
            "internal_only": [],
            "trust_boundaries": ["internet->application"],
        },
        "stats": {
            "endpoint_count": len(endpoints),
            "unauthenticated_endpoints": sum(1 for e in endpoints if not e["auth_required"]),
            "datastore_count": 0,
            "pages_crawled": crawl["pages_crawled"],
            "api_endpoints_found": len(crawl["api_hints"]),
        },
    }
    logger.info("built cyber twin from %s: %d endpoints across %d pages", url, len(endpoints), crawl["pages_crawled"])
    return twin
