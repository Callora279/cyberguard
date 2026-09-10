const GRADE_COLOR = { "A+": "#22c55e", A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };

export default function RiskScoreCard({ score, grade, forecast }) {
  return (
    <div className="card" style={{ gridColumn: "span 2" }}>
      <h3>Unified Risk Score</h3>
      <div className="row" style={{ alignItems: "baseline", gap: 16 }}>
        <span className="big" style={{ color: GRADE_COLOR[grade] || "#e6e9ef" }}>
          {score ?? "—"}
        </span>
        <span className="badge" style={{ background: "rgba(79,140,255,.15)", color: "#4f8cff" }}>
          Grade {grade ?? "?"}
        </span>
      </div>
      {forecast?.predicted != null && (
        <p className="muted" style={{ marginTop: 10 }}>
          {forecast.horizon_days}-day forecast: <strong>{forecast.predicted}</strong> ({forecast.direction})
        </p>
      )}
    </div>
  );
}
