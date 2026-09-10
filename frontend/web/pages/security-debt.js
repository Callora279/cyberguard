import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";
import ThreatHeatmap from "../components/ThreatHeatmap";

export default function SecurityDebt() {
  const { data: scan, mutate } = useSWR("/security-debt/scan", fetcher);
  const { data: rem } = useSWR("/security-debt/remediation?use_ai=false", fetcher);
  const [busy, setBusy] = useState(false);

  async function runScan() {
    setBusy(true);
    try { await api("/security-debt/scan", { method: "POST", body: {} }); await mutate(); }
    finally { setBusy(false); }
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Security Debt</h2>
        <button onClick={runScan} disabled={busy}>{busy ? "Scanning…" : "Run Scan"}</button>
      </div>

      <div className="grid cards">
        <div className="card"><h3>Total Findings</h3><div className="big">{scan?.total_findings ?? "—"}</div></div>
        <div className="card"><h3>Module Score</h3><div className="big">{scan?.module_score ?? "—"}</div></div>
        {["critical", "high", "medium", "low"].map((s) => (
          <div className="card" key={s}><h3>{s}</h3><div className="big">{scan?.by_severity?.[s] ?? 0}</div></div>
        ))}
      </div>

      <ThreatHeatmap />

      <div className="card">
        <h3>Prioritised Remediation Queue</h3>
        <table>
          <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>File</th><th>Fix (min)</th></tr></thead>
          <tbody>
            {(rem?.queue || []).map((q, i) => (
              <tr key={q.finding_id || i}>
                <td>{i + 1}</td>
                <td><span className={`badge ${q.severity}`}>{q.severity}</span></td>
                <td>{q.title}</td>
                <td className="muted">{q.recommended_fix?.slice(0, 60)}…</td>
                <td>{q.estimated_fix_minutes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
