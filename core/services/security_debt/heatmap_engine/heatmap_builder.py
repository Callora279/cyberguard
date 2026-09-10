"""Build a risk heatmap of the codebase from security findings."""
from __future__ import annotations

from collections import defaultdict

_SEVERITY_RISK = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}


def _bucket(score: float) -> str:
    if score >= 80:
        return "red"
    if score >= 50:
        return "orange"
    if score >= 25:
        return "yellow"
    if score > 0:
        return "green"
    return "grey"


def build(findings: list[dict]) -> dict:
    """Return per-file and per-directory risk aggregates."""
    files: dict[str, dict] = defaultdict(lambda: {"risk": 0.0, "findings": 0, "by_severity": defaultdict(int)})
    dirs: dict[str, float] = defaultdict(float)

    for f in findings:
        path = f.get("file_path") or "(unknown)"
        sev = f.get("severity", "medium")
        risk = _SEVERITY_RISK.get(sev, 40)
        files[path]["risk"] += risk
        files[path]["findings"] += 1
        files[path]["by_severity"][sev] += 1
        parts = path.split("/")
        for i in range(1, len(parts)):
            dirs["/".join(parts[:i])] += risk

    file_cells = []
    for path, data in files.items():
        capped = min(100.0, data["risk"])
        file_cells.append(
            {
                "path": path,
                "risk_score": round(capped, 1),
                "colour": _bucket(capped),
                "findings": data["findings"],
                "by_severity": dict(data["by_severity"]),
            }
        )
    file_cells.sort(key=lambda c: c["risk_score"], reverse=True)

    dir_cells = [
        {"path": d, "risk_score": round(min(100.0, r), 1), "colour": _bucket(min(100.0, r))}
        for d, r in sorted(dirs.items(), key=lambda kv: kv[1], reverse=True)
    ]

    return {
        "files": file_cells,
        "directories": dir_cells,
        "hottest_file": file_cells[0]["path"] if file_cells else None,
        "total_risk": round(sum(c["risk_score"] for c in file_cells), 1),
    }
