"""Auto-generate a CycloneDX SBOM from a codebase.

Combines deterministic manifest parsing with an AI pass that identifies
components not declared in manifests (vendored code, system tools, model
weights, container base images, ...).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.services.ai_governance.real_time_enforcer import guarded_chat
from core.services.supply_chain import dependency_scanner
from core.utils.exceptions import CyberGuardError
from core.utils.logger import get_logger

logger = get_logger("supply_chain.sbom_generator")


def _base_document() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "iRaTech", "name": "CyberGuard AI", "version": "0.1.0"}],
        },
        "components": [],
    }


def _component(name: str, version: str, ecosystem: str, *, scope: str = "required") -> dict:
    purl_eco = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven", "RubyGems": "gem"}.get(ecosystem, "generic")
    return {
        "type": "library",
        "name": name,
        "version": version or "0.0.0",
        "scope": scope,
        "purl": f"pkg:{purl_eco}/{name}@{version or '0.0.0'}",
    }


def _ai_supplement(root: Path, known: set[str]) -> list[dict]:
    """Ask the model to spot non-manifest components from key project files."""
    hints = []
    for fname in ("Dockerfile", "Dockerfile.api", "docker-compose.yml", "README.md"):
        for p in root.rglob(fname):
            hints.append(f"--- {p} ---\n{p.read_text(errors='ignore')[:2000]}")
            break
    if not hints:
        return []
    prompt = (
        "From these project files, list software components (base images, system "
        "packages, CLIs, services, model artifacts) that would NOT appear in a "
        "language package manifest. Return JSON: {\"components\": [{\"name\":..., "
        "\"version\":..., \"type\":\"application|library|container|framework\"}]}. "
        f"Already known: {sorted(known)[:50]}\n\n" + "\n\n".join(hints)
    )
    try:
        record = guarded_chat(
            prompt, org_id="system", system="Return only JSON.",
            purpose="sbom_generation", max_tokens=800,
        )
        data = json.loads(record.response[record.response.find("{") : record.response.rfind("}") + 1])
        out = []
        for c in data.get("components", []):
            if c.get("name") and c["name"] not in known:
                out.append(
                    {
                        "type": c.get("type", "library"),
                        "name": c["name"],
                        "version": str(c.get("version") or "unknown"),
                        "scope": "required",
                        "properties": [{"name": "cyberguard:source", "value": "ai-identified"}],
                    }
                )
        return out
    except (CyberGuardError, json.JSONDecodeError, ValueError) as exc:
        logger.warning("AI SBOM supplement skipped: %s", exc)
        return []


def generate(root: str | Path, *, use_ai: bool = True) -> dict:
    root = Path(root)
    doc = _base_document()
    known: set[str] = set()

    for manifest in dependency_scanner.discover_manifests(root):
        for dep in dependency_scanner.parse_manifest(manifest):
            if dep["name"] in known:
                continue
            known.add(dep["name"])
            doc["components"].append(
                _component(
                    dep["name"], dep["version"], dep["ecosystem"],
                    scope="required" if dep["direct"] else "optional",
                )
            )

    if use_ai:
        doc["components"].extend(_ai_supplement(root, known))

    doc["metadata"]["component"] = {"type": "application", "name": root.name}
    logger.info("generated SBOM with %d components", len(doc["components"]))
    return doc


def to_json(doc: dict) -> str:
    return json.dumps(doc, indent=2)
