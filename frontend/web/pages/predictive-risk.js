import useSWR from "swr";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { fetcher } from "../lib/api";

export default function PredictiveRisk() {
  const { data } = useSWR("/risk-score/forecast?horizon_days=30", fetcher, { refreshInterval: 60000 });
  const incident = data?.incident_forecast;
  const multi = data?.multi_horizon;

  const chartData = (incident?.predictions || []).map((p) => ({
    vector: p.vector.replace(/_/g, " "),
    probability: Math.round(p.probability * 100),
  }));

  return (
    <div className="grid" style={{ gap: 20 }}>
      <h2>Predictive Risk</h2>

      <div className="card">
        <h3>Headline</h3>
        <div className="big" style={{ fontSize: 22 }}>{incident?.headline || "…"}</div>
      </div>

      <div className="card">
        <h3>Attack Probability (next 30 days)</h3>
        <div style={{ width: "100%", height: 260 }}>
          <ResponsiveContainer>
            <BarChart data={chartData} layout="vertical" margin={{ left: 60 }}>
              <CartesianGrid stroke="#232b3a" />
              <XAxis type="number" domain={[0, 100]} stroke="#8b94a7" />
              <YAxis type="category" dataKey="vector" width={140} stroke="#8b94a7" />
              <Tooltip contentStyle={{ background: "#141924", border: "1px solid #232b3a" }} />
              <Bar dataKey="probability" fill="#f97316" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        {["30d", "60d", "90d"].map((h) => (
          <div className="card" key={h}>
            <h3>{h} outlook</h3>
            <p>{multi?.horizons?.[h]?.headline}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>Threat Intelligence Feed</h3>
        <ul>
          {(data?.multi_horizon?.threat_landscape?.emerging_vectors || []).map((v) => <li key={v}>{v}</li>)}
        </ul>
        <h3 style={{ marginTop: 16 }}>Proactive Recommendations</h3>
        <ul>
          {(multi?.proactive_recommendations || []).map((r) => <li key={r}>{r}</li>)}
        </ul>
      </div>
    </div>
  );
}
