import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import RiskScoreCard from "../components/RiskScoreCard";
import ComplianceStatus from "../components/ComplianceStatus";
import AlertFeed from "../components/AlertFeed";
import ThreatHeatmap from "../components/ThreatHeatmap";
import { useRiskScore } from "../hooks/useRiskScore";

export default function Dashboard() {
  const { score, grade, breakdown, trend, forecast, recommendations, error } = useRiskScore();

  return (
    <div className="grid" style={{ gap: 20 }}>
      <h2>Dashboard</h2>
      {error && <div className="card" style={{ color: "var(--crit)" }}>API error: {String(error.message)}</div>}

      <div className="grid cards">
        <RiskScoreCard score={score} grade={grade} forecast={forecast} />
        <ComplianceStatus breakdown={breakdown} />
      </div>

      <div className="card">
        <h3>30-day Risk Trend</h3>
        <div style={{ width: "100%", height: 240 }}>
          <ResponsiveContainer>
            <LineChart data={trend.map((p) => ({ ...p, t: p.t.slice(5, 10) }))}>
              <CartesianGrid stroke="#232b3a" />
              <XAxis dataKey="t" stroke="#8b94a7" />
              <YAxis domain={[0, 100]} stroke="#8b94a7" />
              <Tooltip contentStyle={{ background: "#141924", border: "1px solid #232b3a" }} />
              <Line type="monotone" dataKey="score" stroke="#4f8cff" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <AlertFeed />
        <div className="card">
          <h3>Improvement Recommendations</h3>
          <ul>
            {recommendations.map((r) => (
              <li key={r.module} style={{ marginBottom: 8 }}>
                <strong>{r.module.replace(/_/g, " ")}</strong> ({r.score}): {r.action}
              </li>
            ))}
            {recommendations.length === 0 && <li className="muted">All modules healthy</li>}
          </ul>
        </div>
      </div>

      <ThreatHeatmap />
    </div>
  );
}
