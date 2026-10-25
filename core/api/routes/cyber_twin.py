"""Cyber Twin API: build, simulate, scenarios."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from core.api.middleware.auth import Principal, get_principal
from core.database.org_repo import connected_repo
from core.services.cyber_twin import attack_scenarios, simulation_engine, twin_builder
from core.utils.exceptions import ValidationError

router = APIRouter()


def _build_from_connected_repo(org_id: str, name: str) -> dict:
    """Build a twin from the org's connected repo. Never falls back to this
    server's own source tree for an org-scoped twin."""
    import tempfile

    from core.utils.github import download_repo, parse_repo_url

    repo_url, token = connected_repo(org_id)
    if not repo_url:
        raise ValidationError(
            "no path or url given, and this org has no connected repo configured"
        )
    with tempfile.TemporaryDirectory(prefix="cg-twin-") as tmp:
        root = str(download_repo(parse_repo_url(repo_url), token, Path(tmp)))
        return twin_builder.build(root, name=name)

# in-memory twin cache per org (twins are also written to disk by twin_builder)
_TWINS: dict[str, dict] = {}


class BuildIn(BaseModel):
    path: str | None = None
    url: str | None = None  # live target — crawls it instead of reading local source
    name: str | None = None


class SimulateIn(BaseModel):
    attacks: list[str] | None = None
    scenario: str | None = None
    ai_analysis: bool = True  # narrate the run with the org's AI provider (falls back to heuristic-only)


@router.post("/build")
def build(body: BuildIn, principal: Principal = Depends(get_principal)) -> dict:
    name = body.name or f"org-{principal.org_id[:8]}"
    if body.url:
        twin = twin_builder.build_from_url(body.url, name=name)
    elif body.path:
        if not os.path.isdir(body.path):
            raise ValidationError(f"path not found: {body.path}")
        twin = twin_builder.build(body.path, name=name)
    else:
        twin = _build_from_connected_repo(principal.org_id, name)
    twin_builder.save(twin)
    _TWINS[principal.org_id] = twin
    return twin


@router.post("/simulate")
def simulate(body: SimulateIn, principal: Principal = Depends(get_principal)) -> dict:
    twin = _TWINS.get(principal.org_id)
    if not twin:
        twin = _build_from_connected_repo(principal.org_id, f"org-{principal.org_id[:8]}")
        _TWINS[principal.org_id] = twin
    if body.scenario and body.ai_analysis:
        return simulation_engine.simulate_with_ai(twin, body.scenario, org_id=principal.org_id)
    return simulation_engine.simulate(twin, body.attacks, scenario=body.scenario)


@router.get("/scenarios")
def scenarios(scenario_id: str | None = None) -> dict:
    if scenario_id:
        return attack_scenarios.get(scenario_id)
    return {"scenarios": attack_scenarios.list_scenarios()}
