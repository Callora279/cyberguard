import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export default function MachineIdentity() {
  const { data: reg, mutate } = useSWR("/machine-identity/registry", fetcher);
  const { data: alerts } = useSWR("/machine-identity/alerts", fetcher);
  const { data: hist } = useSWR("/machine-identity/history", fetcher);

  async function rotate(id) {
    await api("/machine-identity/rotate", { method: "POST", body: { identity_id: id } });
    await mutate();
  }

  return (
    <div className="grid" style={{ gap: 20 }}>
      <h2>Machine Identity</h2>

      <div className="card">
        <h3>Identity Registry ({reg?.count ?? 0})</h3>
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Owner</th><th>Status</th><th>Expires</th><th></th></tr></thead>
          <tbody>
            {(reg?.identities || []).map((i) => (
              <tr key={i.id}>
                <td>{i.name}</td>
                <td>{i.type}</td>
                <td className="muted">{i.owner || "—"}</td>
                <td><span className={`badge ${i.status === "expired" || i.status === "revoked" ? "critical" : i.status === "expiring" ? "medium" : "low"}`}>{i.status}</span></td>
                <td className="muted">{i.expires_at ? String(i.expires_at).slice(0, 10) : "—"}</td>
                <td><button className="ghost" onClick={() => rotate(i.id)}>Rotate</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="card">
          <h3>Anomaly / Expiry Alerts</h3>
          <ul>
            {(alerts?.alerts || []).map((a) => (
              <li key={a.id}><span className={`badge ${a.severity}`}>{a.severity}</span> {a.title}</li>
            ))}
            {(alerts?.alerts || []).length === 0 && <li className="muted">None</li>}
          </ul>
        </div>
        <div className="card">
          <h3>Rotation History</h3>
          <table>
            <tbody>
              {(hist?.rotations || []).slice(-10).reverse().map((r, i) => (
                <tr key={i}><td>{r.name}</td><td className="muted">{String(r.rotated_at).slice(0, 19)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
