import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export default function AIGovernance() {
  const { data: status } = useSWR("/ai-governance/status", fetcher, { refreshInterval: 20000 });
  const { data: audit } = useSWR("/ai-governance/audit-log?limit=50", fetcher);
  const { data: fp } = useSWR("/ai-governance/fingerprints", fetcher);
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState(null);

  async function testPrompt() {
    try {
      setResult(await api("/ai-governance/proxy-chat", { method: "POST", body: { prompt } }));
    } catch (e) {
      setResult({ error: e.message });
    }
  }

  const usage = status?.usage || {};
  return (
    <div className="grid" style={{ gap: 20 }}>
      <h2>AI Governance</h2>

      <div className="grid cards">
        <div className="card"><h3>AI Calls (30d)</h3><div className="big">{usage.calls ?? "—"}</div></div>
        <div className="card"><h3>Tokens</h3><div className="big">{usage.total_tokens ?? "—"}</div></div>
        <div className="card"><h3>Est. Cost</h3><div className="big">${usage.estimated_cost_usd ?? 0}</div></div>
        <div className="card"><h3>Blocked</h3><div className="big" style={{ color: "var(--crit)" }}>{usage.blocked_calls ?? 0}</div></div>
      </div>

      <div className="card">
        <h3>Policy Enforcement Test</h3>
        <div className="row">
          <input value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Enter a prompt to run through the enforcer…" />
          <button onClick={testPrompt}>Run</button>
        </div>
        {result && <pre style={{ marginTop: 12, overflow: "auto" }}>{JSON.stringify(result, null, 2)}</pre>}
      </div>

      <div className="card">
        <h3>Behavioural Fingerprint</h3>
        <p className="muted">Sample size: {fp?.current?.sample_size ?? 0} · Drift: {fp?.drift?.drift ? "detected" : "none"}</p>
        <pre style={{ overflow: "auto" }}>{JSON.stringify(fp?.current?.tokens || {}, null, 2)}</pre>
      </div>

      <div className="card">
        <h3>Audit Log</h3>
        <table>
          <thead><tr><th>Time</th><th>Model</th><th>Tokens</th><th>Risk</th><th>Decision</th></tr></thead>
          <tbody>
            {(audit?.entries || []).map((e) => (
              <tr key={e.id}>
                <td className="muted">{String(e.timestamp).slice(0, 19)}</td>
                <td>{e.model}</td>
                <td>{e.total_tokens}</td>
                <td>{Math.round(e.risk_score)}</td>
                <td><span className={`badge ${e.policy_decision === "block" ? "critical" : e.policy_decision === "flag" ? "medium" : "low"}`}>{e.policy_decision}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
