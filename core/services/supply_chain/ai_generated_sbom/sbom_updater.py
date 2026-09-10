"""Keep a stored SBOM in sync as the codebase changes (per commit / push)."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.services.supply_chain.ai_generated_sbom import sbom_generator
from core.utils.logger import get_logger

logger = get_logger("supply_chain.sbom_updater")

_STATE_DIR = Path(os.getenv("CYBERGUARD_STATE_DIR", ".cyberguard")) / "sbom"


def _store_path(org_id: str) -> Path:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    return _STATE_DIR / f"{org_id}.cdx.json"


def _index(doc: dict) -> dict[str, str]:
    return {c["name"]: c.get("version", "") for c in doc.get("components", [])}


def diff(old: dict, new: dict) -> dict:
    old_idx, new_idx = _index(old), _index(new)
    added = [n for n in new_idx if n not in old_idx]
    removed = [n for n in old_idx if n not in new_idx]
    changed = [
        {"name": n, "from": old_idx[n], "to": new_idx[n]}
        for n in new_idx
        if n in old_idx and old_idx[n] != new_idx[n]
    ]
    return {"added": added, "removed": removed, "changed": changed}


def update(org_id: str, repo_path: str, *, commit: str | None = None) -> dict:
    path = _store_path(org_id)
    old = json.loads(path.read_text()) if path.exists() else {"components": []}
    new = sbom_generator.generate(repo_path, use_ai=False)
    delta = diff(old, new)

    new.setdefault("metadata", {})["updatedAt"] = datetime.now(timezone.utc).isoformat()
    if commit:
        new["metadata"]["commit"] = commit
    path.write_text(json.dumps(new, indent=2))

    changed = bool(delta["added"] or delta["removed"] or delta["changed"])
    logger.info(
        "SBOM for %s updated (commit=%s): +%d -%d ~%d",
        org_id, commit, len(delta["added"]), len(delta["removed"]), len(delta["changed"]),
    )
    return {"org_id": org_id, "commit": commit, "changed": changed, "delta": delta,
            "component_count": len(new.get("components", []))}


def current(org_id: str) -> dict | None:
    path = _store_path(org_id)
    return json.loads(path.read_text()) if path.exists() else None
