"""Build a digital replica (graph) of the target system.

The twin captures endpoints, authentication flows, data stores and network
topology so the simulation engine can reason about attack paths without
touching production.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

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
