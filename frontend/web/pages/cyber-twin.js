import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export default function CyberTwin() {
  const { data: scenarios } = useSWR("/cyber-twin/scenarios", fetcher);
  const [target, setTarget] = useState("");
  const [twin, setTwin] = useState(null);
  const [sim, setSim] = useState(null);
  const [scenario, setScenario] = useState("");
  const [busy, setBusy] = useState(false);

  async function build() {
    setBusy(true);
    try {
      const body = target ? { url: target } : {};
      setTwin(await api("/cyber-twin/build", { method: "POST", body }));
      setSim(null);
    } finally { setBusy(false); }
  }
  async function simulate() {
    setBusy(true);
    try {
      setSim(await api("/cyber-twin/simulate", { method: "POST", body: scenario ? { scenario } : {} }));
    } finally { setBusy(false); }
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
        <h2>Cyber Twin</h2>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <input
            className="auth-input"
            style={{ width: 240 }}
            placeholder="Target URL (blank = scan this codebase)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <button onClick={build} disabled={busy}>{busy ? "Working…" : "Build Twin"}</button>
          <select value={scenario} onChange={(e) => setScenario(e.target.value)} style={{ padding: 8, background: "#1c2330", color: "#e6e9ef", border: "1px solid #232b3a", borderRadius: 8 }}>
            <option value="">All techniques</option>
            {(scenarios?.scenarios || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button className="ghost" onClick={simulate} disabled={busy}>Run Simulation</button>
        </div>
      </div>

      {twin && (
        <div className="card">
          <h3>Infrastructure Map — {twin.name}</h3>
          <p className="muted">
            {twin.source === "url" ? `Crawled ${twin.stats.pages_crawled} page(s) at ${twin.target_url} · ` : ""}
            {twin.stats.endpoint_count} endpoints · {twin.stats.unauthenticated_endpoints} unauthenticated
            {twin.stats.datastore_count != null && <> · {twin.stats.datastore_count} data stores</>}
            {twin.stats.api_endpoints_found != null && <> · {twin.stats.api_endpoints_found} API endpoint(s) found</>}
          </p>
          <pre style={{ maxHeight: 220, overflow: "auto" }}>{JSON.stringify(twin.topology, null, 2)}</pre>
        </div>
      )}

      {sim && (
        <div className="card">
          <h3>Simulation Results — {sim.verdict?.toUpperCase()} (risk {sim.twin_risk_score})</h3>
          {sim.scenario_name && <p className="muted">Scenario: {sim.scenario_name}</p>}
          <table>
            <thead><tr><th>Technique</th><th>Success</th><th>Outcome</th></tr></thead>
            <tbody>
              {sim.results.map((r, i) => (
                <tr key={i}>
                  <td>{r.technique}</td>
                  <td><span className={`badge ${r.success ? "critical" : "low"}`}>{r.success ? "yes" : "no"}</span></td>
                  <td className="muted">{r.outcome}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {sim.ai_analysis && (
            <div style={{ marginTop: 16 }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <h4>Attacker Narrative</h4>
                <span className="muted" style={{ fontSize: 12 }}>
                  exploitation difficulty: <strong>{sim.ai_analysis.exploitation_difficulty}</strong>
                  {sim.ai_analysis.source === "heuristic" && " (AI unavailable — heuristic summary shown)"}
                </span>
              </div>

              <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 8 }}>
                <div>
                  <h5>Attack steps</h5>
                  <ol>{sim.ai_analysis.attack_steps.map((s, i) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{s}</li>)}</ol>
                </div>
                <div>
                  <h5>Vulnerabilities found</h5>
                  <ul>{sim.ai_analysis.vulnerabilities_found.map((s, i) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{s}</li>)}</ul>
                </div>
              </div>

              <h5 style={{ marginTop: 8 }}>Recommended defences</h5>
              <ul>{sim.ai_analysis.recommended_defences.map((s, i) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{s}</li>)}</ul>
              {sim.ai_analysis.source === "ai" && (
                <p className="muted" style={{ fontSize: 11, marginTop: 8 }}>
                  Powered by {sim.ai_analysis.provider || "groq"} · {sim.ai_analysis.model}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      <div className="card">
        <h3>Scenario Library</h3>
        <ul>
          {(scenarios?.scenarios || []).map((s) => (
            <li key={s.id}><strong>{s.name}</strong> <span className="muted">({s.framework}, {s.step_count} steps)</span></li>
          ))}
        </ul>
      </div>
    </div>
  );
}
