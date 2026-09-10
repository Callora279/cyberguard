import { useState } from "react";
import Link from "next/link";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import RiskScoreCard from "../components/RiskScoreCard";
import ComplianceStatus from "../components/ComplianceStatus";
import AlertFeed from "../components/AlertFeed";
import ThreatHeatmap from "../components/ThreatHeatmap";
import { useRiskScore } from "../hooks/useRiskScore";
import { useOnboarding } from "../hooks/useOnboarding";
import { api } from "../lib/api";

export default function Dashboard() {
  const { score, grade, breakdown, trend, forecast, recommendations, error, refresh } = useRiskScore();
  const { completed, currentStep, steps, scanCount, openFindings, refresh: refreshOnb } = useOnboarding();
  const [scanning, setScanning] = useState(false);

  const noScans = scanCount === 0;

  async function runFirstScan() {
    setScanning(true);
    try {
      await api("/security-debt/scan", { method: "POST", body: {} });
      await Promise.all([refresh(), refreshOnb()]);
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <h2>Dashboard</h2>

      {!completed && (
        <div className="card banner">
          <div>
            <strong>Complete your setup</strong>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              {steps.filter((s) => s.done).length} of {steps.length} steps done — finish onboarding to get full coverage.
            </p>
          </div>
          <Link href="/onboarding"><button>Resume setup (step {currentStep})</button></Link>
        </div>
      )}

      {completed && noScans && (
        <div className="card banner">
          <div>
            <strong>Run your first scan</strong>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              No scans yet — your score below is a baseline. Run a scan to see real findings.
            </p>
          </div>
          <button onClick={runFirstScan} disabled={scanning}>
            {scanning ? "Scanning…" : "Run your first scan"}
          </button>
        </div>
      )}

      {error && <div className="card" style={{ color: "var(--crit)" }}>API error: {String(error.message)}</div>}

      <div className="grid cards">
        <RiskScoreCard score={score} grade={grade} forecast={forecast} />
        <ComplianceStatus breakdown={breakdown} />
      </div>

      <p className="muted" style={{ margin: "-8px 0 0" }}>
        Your security score: <strong style={{ color: "var(--text)" }}>{score ?? "—"}/100</strong>
        {" · "}{openFindings} open finding{openFindings === 1 ? "" : "s"} to fix
        {" · "}{scanCount} scan{scanCount === 1 ? "" : "s"} run
      </p>

      <div className="card">
        <h3>30-day Risk Trend</h3>
        {trend.length < 2 ? (
          <p className="muted">Not enough history yet — the trend line appears after a few daily score snapshots.</p>
        ) : (
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
        )}
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <AlertFeed />
        <div className="card">
          <h3>Findings to fix</h3>
          <ul>
            {recommendations.map((r) => (
              <li key={r.module} style={{ marginBottom: 8 }}>
                <strong>{r.module.replace(/_/g, " ")}</strong> ({r.score}): {r.action}
              </li>
            ))}
            {recommendations.length === 0 && <li className="muted">All modules healthy — nothing urgent to fix.</li>}
          </ul>
        </div>
      </div>

      <ThreatHeatmap />
    </div>
  );
}
