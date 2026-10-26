import useSWR from "swr";
import { fetcher } from "../lib/api";

const COLORS = { red: "#ef4444", orange: "#f97316", yellow: "#eab308", green: "#22c55e", grey: "#3a4152" };

export default function ThreatHeatmap() {
  const { data } = useSWR("/security-debt/heatmap", fetcher);
  const files = data?.files || [];

  return (
    <div className="card">
      <h3>Codebase Risk Heatmap</h3>
      {files.length === 0 && <p className="muted">Run a security-debt scan to populate the heatmap.</p>}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 8 }}>
        {files.slice(0, 120).map((f) => {
          const name = f.path.split("/").pop();
          return (
            <div
              key={f.path}
              title={`${f.path} — risk ${f.risk_score} — ${f.findings} findings`}
              aria-label={`${f.path}: risk ${f.risk_score}, ${f.findings} findings`}
              style={{
                minWidth: 26, height: 26, borderRadius: 4, padding: "0 6px",
                maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                fontSize: 10, lineHeight: "26px", color: "#0b0e14",
                background: COLORS[f.colour] || "#3a4152",
              }}
            >
              {name}
            </div>
          );
        })}
      </div>
    </div>
  );
}
