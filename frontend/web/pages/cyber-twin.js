import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export default function CyberTwin() {
  const { data: scenarios } = useSWR("/cyber-twin/scenarios", fetcher);
  const [twin, setTwin] = useState(null);
  const [sim, setSim] = useState(null);
  const [scenario, setScenario] = useState("");

  async function build() { setTwin(await api("/cyber-twin/build", { method: "POST", body: {} })); }
  async function simulate() {
    setSim(await api("/cyber-twin/simulate", { method: "POST", body: scenario ? { scenario } : {} }));
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Cyber Twin</h2>
        <div className="row">
          <button onClick={build}>Build Twin</button>
          <select value={scenario} onChange={(e) => setScenario(e.target.value)} style={{ padding: 8, background: "#1c2330", color: "#e6e9ef", border: "1px solid #232b3a", borderRadius: 8 }}>
            <option value="">All techniques</option>
            {(scenarios?.scenarios || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button className="ghost" onClick={simulate}>Run Simulation</button>
        </div>
      </div>

      {twin && (
        <div className="card">
          <h3>Infrastructure Map — {twin.name}</h3>
          <p className="muted">
            {twin.stats.endpoint_count} endpoints · {twin.stats.unauthenticated_endpoints} unauthenticated · {twin.stats.datastore_count} data stores
          </p>
          <pre style={{ maxHeight: 220, overflow: "auto" }}>{JSON.stringify(twin.topology, null, 2)}</pre>
        </div>
      )}

      {sim && (
        <div className="card">
          <h3>Simulation Results — {sim.verdict?.toUpperCase()} (risk {sim.twin_risk_score})</h3>
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
