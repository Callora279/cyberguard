import { useState } from "react";
import useSWR from "swr";
import { api, fetcher } from "../lib/api";

const SAMPLE = {
  subject: "acme-vendor-invoice-4471",
  identity: { email: "billing9931@mailinator.com", phone: "0000000000", full_name: "John Doe" },
  transaction: { amount: 48000, account_avg: 5200, new_beneficiary: true, cross_border: true },
  invoice: { id: "INV-4471", vendor: "Acme Ltd", amount: 48000, date: "2026-09-06", iban: "GB00NEW00000000" },
  context: { ip_country: "NG", billing_country: "GB", device_change: true },
};

export default function FraudDetection() {
  const { data, mutate } = useSWR("/fraud-detection/alerts", fetcher);
  const [result, setResult] = useState(null);

  async function analyze() {
    setResult(await api("/fraud-detection/analyze", { method: "POST", body: SAMPLE }));
    await mutate();
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Fraud Detection</h2>
        <button onClick={analyze}>Analyze Sample Case</button>
      </div>

      {result && (
        <div className="card">
          <h3>Fusion Result — {result.verdict?.toUpperCase()} ({result.fused_fraud_score})</h3>
          <p className="muted">Firing detectors: {(result.firing_detectors || []).join(", ") || "none"}</p>
          <pre style={{ overflow: "auto" }}>{JSON.stringify(result.breakdown, null, 2)}</pre>
        </div>
      )}

      <div className="card">
        <h3>Fraud Alert Feed</h3>
        <table>
          <thead><tr><th>Type</th><th>Subject</th><th>Risk</th><th>Status</th><th>Created</th></tr></thead>
          <tbody>
            {(data?.alerts || []).map((a) => (
              <tr key={a.id}>
                <td>{a.type}</td>
                <td>{a.subject}</td>
                <td>{Math.round(a.risk_score)}</td>
                <td><span className={`badge ${a.risk_score >= 70 ? "critical" : a.risk_score >= 40 ? "high" : "low"}`}>{a.status}</span></td>
                <td className="muted">{String(a.created_at).slice(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
