"""Cyber Twin API: build, simulate, scenarios."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from core.api.middleware.auth import Principal, get_principal
from core.services.cyber_twin import attack_scenarios, simulation_engine, twin_builder
from core.utils.exceptions import ValidationError

router = APIRouter()
_DEFAULT_PATH = os.getenv("SCAN_TARGET_PATH", ".")

# in-memory twin cache per org (twins are also written to disk by twin_builder)
_TWINS: dict[str, dict] = {}


class BuildIn(BaseModel):
    path: str | None = None
    name: str | None = None


class SimulateIn(BaseModel):
    attacks: list[str] | None = None
    scenario: str | None = None


@router.post("/build")
def build(body: BuildIn, principal: Principal = Depends(get_principal)) -> dict:
    path = body.path or _DEFAULT_PATH
    if not os.path.isdir(path):
        raise ValidationError(f"path not found: {path}")
    twin = twin_builder.build(path, name=body.name or f"org-{principal.org_id[:8]}")
    twin_builder.save(twin)
    _TWINS[principal.org_id] = twin
    return twin


@router.post("/simulate")
def simulate(body: SimulateIn, principal: Principal = Depends(get_principal)) -> dict:
    twin = _TWINS.get(principal.org_id)
    if not twin:
        twin = twin_builder.build(_DEFAULT_PATH, name=f"org-{principal.org_id[:8]}")
        _TWINS[principal.org_id] = twin
    return simulation_engine.simulate(twin, body.attacks, scenario=body.scenario)


@router.get("/scenarios")
def scenarios(scenario_id: str | None = None) -> dict:
    if scenario_id:
        return attack_scenarios.get(scenario_id)
    return {"scenarios": attack_scenarios.list_scenarios()}
