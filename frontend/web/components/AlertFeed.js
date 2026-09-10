import { useAlerts } from "../hooks/useAlerts";

export default function AlertFeed({ limit = 8, module }) {
  const { alerts, acknowledge, loading } = useAlerts(module ? { module } : {});
  const shown = alerts.slice(0, limit);

  return (
    <div className="card">
      <h3>Recent Alerts {loading ? "…" : `(${alerts.length})`}</h3>
      {shown.length === 0 && <p className="muted">No open alerts</p>}
      <table>
        <tbody>
          {shown.map((a) => (
            <tr key={a.id}>
              <td><span className={`badge ${a.severity}`}>{a.severity}</span></td>
              <td>
                <div>{a.title}</div>
                <div className="muted" style={{ fontSize: 11 }}>{a.module}</div>
              </td>
              <td style={{ textAlign: "right" }}>
                {!a.acknowledged && (
                  <button className="ghost" onClick={() => acknowledge(a.id)}>Ack</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
