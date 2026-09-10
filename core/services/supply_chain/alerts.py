"""Persist supply-chain scan results and raise alerts on new/critical CVEs."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import Alert, SBOMComponent
from core.services.supply_chain import dependency_scanner, vendor_risk
from core.utils.logger import get_logger

logger = get_logger("supply_chain.alerts")


def run_scan(org_id: str, path: str) -> dict:
    vulns = dependency_scanner.scan_path(path)
    manifests = dependency_scanner.discover_manifests(path)

    # aggregate per component
    components: dict[tuple[str, str], dict] = {}
    for manifest in manifests:
        for dep in dependency_scanner.parse_manifest(manifest):
            key = (dep["name"], dep["version"])
            components.setdefault(
                key,
                {
                    "name": dep["name"],
                    "version": dep["version"],
                    "ecosystem": dep["ecosystem"],
                    "direct": dep["direct"],
                    "cves": [],
                },
            )
    for v in vulns:
        key = (v["package"], v["version"])
        components.setdefault(key, {"name": v["package"], "version": v["version"], "ecosystem": v["ecosystem"], "direct": v.get("direct", True), "cves": []})
        components[key]["cves"].append(v)

    critical: list[dict] = []
    with session_scope() as db:
        db.query(SBOMComponent).filter(SBOMComponent.org_id == org_id).delete()
        for comp in components.values():
            max_cvss = max((c["cvss"] for c in comp["cves"]), default=0.0)
            vr = vendor_risk.score_component(
                name=comp["name"],
                cve_count=len(comp["cves"]),
                max_cvss=max_cvss,
            )
            db.add(
                SBOMComponent(
                    org_id=org_id,
                    name=comp["name"],
                    version=comp["version"],
                    ecosystem=comp["ecosystem"],
                    cve_count=len(comp["cves"]),
                    max_cvss=max_cvss,
                    vendor_risk_score=vr["risk_score"],
                    direct=comp["direct"],
                )
            )
            for c in comp["cves"]:
                if c["severity"] in ("critical", "high"):
                    critical.append(c)

        if critical:
            db.add(
                Alert(
                    org_id=org_id,
                    module="supply_chain",
                    severity="critical" if any(c["severity"] == "critical" for c in critical) else "high",
                    title=f"{len(critical)} high/critical dependency vulnerabilities",
                    body="; ".join(f"{c['package']} {c['id']}" for c in critical[:5]),
                    context={"cves": [c["id"] for c in critical]},
                )
            )

    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "components_scanned": len(components),
        "vulnerable_components": sum(1 for c in components.values() if c["cves"]),
        "total_cves": len(vulns),
        "critical_or_high": len(critical),
        "module_score": module_score(list(components.values())),
    }


def module_score(components: list[dict]) -> float:
    if not components:
        return 100.0
    penalty = 0.0
    for c in components:
        for cve in c.get("cves", []):
            penalty += {"critical": 25, "high": 15, "medium": 6, "low": 2}.get(cve["severity"], 4)
    return round(max(0.0, 100.0 - penalty ** 0.5 * 5.0), 2)


def list_components(org_id: str) -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(
            select(SBOMComponent).where(SBOMComponent.org_id == org_id).order_by(
                SBOMComponent.vendor_risk_score.desc()
            )
        ).all()
        return [
            {
                "id": r.id, "name": r.name, "version": r.version, "ecosystem": r.ecosystem,
                "license": r.license, "cve_count": r.cve_count, "max_cvss": r.max_cvss,
                "vendor_risk_score": r.vendor_risk_score, "direct": r.direct,
            }
            for r in rows
        ]
