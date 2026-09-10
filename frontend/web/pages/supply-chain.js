import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export default function SupplyChain() {
  const { data: vendors, mutate: mv } = useSWR("/supply-chain/vendors", fetcher);
  const { data: sbom, mutate: ms } = useSWR("/supply-chain/sbom", fetcher);
  const [busy, setBusy] = useState(false);

  async function scan() {
    setBusy(true);
    try { await api("/supply-chain/scan", { method: "POST", body: {} }); await mv(); }
    finally { setBusy(false); }
  }
  async function genSbom() {
    await api("/supply-chain/generate-sbom", { method: "POST", body: { use_ai: false } });
    await ms();
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Supply Chain</h2>
        <div className="row">
          <button onClick={scan} disabled={busy}>{busy ? "Scanning…" : "Scan Dependencies"}</button>
          <button className="ghost" onClick={genSbom}>Generate SBOM</button>
        </div>
      </div>

      <div className="card">
        <h3>Vendor / Dependency Risk Matrix</h3>
        <table>
          <thead><tr><th>Component</th><th>Risk</th><th>Grade</th><th>Maintenance</th><th>Sec. history</th></tr></thead>
          <tbody>
            {(vendors?.vendors || []).map((v) => (
              <tr key={v.component}>
                <td>{v.component}</td>
                <td>{v.risk_score}</td>
                <td><span className={`badge ${v.grade === "high" ? "critical" : v.grade === "elevated" ? "high" : "low"}`}>{v.grade}</span></td>
                <td>{v.factors?.maintenance}</td>
                <td>{v.factors?.security_history}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>SBOM ({sbom?.component_count ?? 0} components)</h3>
        <pre style={{ maxHeight: 320, overflow: "auto" }}>
          {JSON.stringify((sbom?.sbom?.components || []).slice(0, 40), null, 2)}
        </pre>
      </div>
    </div>
  );
}
