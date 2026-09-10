"""Supply Chain API: scan, SBOM, vendors, generate-sbom."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from core.api.middleware.auth import Principal, get_principal
from core.services.supply_chain import alerts, sbom_parser, vendor_risk
from core.services.supply_chain.ai_generated_sbom import sbom_generator, sbom_updater
from core.utils.exceptions import ValidationError

router = APIRouter()
_DEFAULT_PATH = os.getenv("SCAN_TARGET_PATH", ".")


class ScanIn(BaseModel):
    path: str | None = None


class SBOMIn(BaseModel):
    raw: str


class GenerateIn(BaseModel):
    path: str | None = None
    use_ai: bool = True
    persist: bool = True


@router.post("/scan")
def scan(body: ScanIn, principal: Principal = Depends(get_principal)) -> dict:
    path = body.path or _DEFAULT_PATH
    if not os.path.isdir(path):
        raise ValidationError(f"path not found: {path}")
    return alerts.run_scan(principal.org_id, path)


@router.get("/sbom")
def get_sbom(principal: Principal = Depends(get_principal)) -> dict:
    current = sbom_updater.current(principal.org_id)
    return {"sbom": current, "component_count": len(current.get("components", [])) if current else 0}


@router.post("/sbom/parse")
def parse_sbom(body: SBOMIn) -> dict:
    parsed = sbom_parser.parse(body.raw)
    return {
        "parsed": parsed.as_dict(),
        "completeness": sbom_parser.validate_completeness(parsed),
        "nhs_compliance": sbom_parser.nhs_compliance_check(parsed),
    }


@router.get("/vendors")
def vendors(principal: Principal = Depends(get_principal)) -> dict:
    components = alerts.list_components(principal.org_id)
    scored = [
        vendor_risk.score_component(
            name=c["name"], license=c["license"], cve_count=c["cve_count"], max_cvss=c["max_cvss"]
        )
        for c in components
    ]
    scored.sort(key=lambda s: s["risk_score"], reverse=True)
    return {"vendors": scored, "count": len(scored)}


@router.post("/generate-sbom")
def generate_sbom(body: GenerateIn, principal: Principal = Depends(get_principal)) -> dict:
    path = body.path or _DEFAULT_PATH
    if not os.path.isdir(path):
        raise ValidationError(f"path not found: {path}")
    doc = sbom_generator.generate(path, use_ai=body.use_ai)
    if body.persist:
        sbom_updater.update(principal.org_id, path)
    return {"sbom": doc, "component_count": len(doc["components"])}
