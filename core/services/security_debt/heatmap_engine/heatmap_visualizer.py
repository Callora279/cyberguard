"""Render the risk heatmap as a standalone HTML treemap-ish grid."""
from __future__ import annotations

_COLOURS = {
    "red": "#c0392b",
    "orange": "#e67e22",
    "yellow": "#f1c40f",
    "green": "#27ae60",
    "grey": "#7f8c8d",
}


def to_html(heatmap: dict, *, title: str = "CyberGuard Security-Debt Heatmap") -> str:
    cells = "".join(
        f'<div class="cell" style="background:{_COLOURS.get(c["colour"], "#555")}" '
        f'title="{c["path"]} — risk {c["risk_score"]} — {c["findings"]} findings">'
        f'<span>{c["path"].split("/")[-1]}</span>'
        f'<small>{c["risk_score"]}</small></div>'
        for c in heatmap.get("files", [])[:200]
    )
    legend = "".join(
        f'<span class="lg"><i style="background:{v}"></i>{k}</span>'
        for k, v in _COLOURS.items()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{title}</title><style>
body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;margin:0;padding:24px}}
h1{{font-size:18px}}
.grid{{display:flex;flex-wrap:wrap;gap:6px;margin-top:16px}}
.cell{{width:120px;height:70px;border-radius:6px;padding:8px;display:flex;
flex-direction:column;justify-content:space-between;overflow:hidden;font-size:11px}}
.cell span{{font-weight:600;word-break:break-all}}
.legend{{margin-top:16px;display:flex;gap:16px;font-size:12px}}
.lg i{{display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:6px}}
</style></head><body>
<h1>{title}</h1>
<p>Total risk: {heatmap.get('total_risk', 0)} &nbsp;|&nbsp; Hottest: {heatmap.get('hottest_file') or 'n/a'}</p>
<div class="legend">{legend}</div>
<div class="grid">{cells}</div>
</body></html>"""


def to_ascii(heatmap: dict, *, limit: int = 20) -> str:
    lines = ["RISK  FINDINGS  FILE"]
    for c in heatmap.get("files", [])[:limit]:
        bar = "█" * int(c["risk_score"] / 5)
        lines.append(f"{c['risk_score']:>5.0f}  {c['findings']:>8}  {bar} {c['path']}")
    return "\n".join(lines)
