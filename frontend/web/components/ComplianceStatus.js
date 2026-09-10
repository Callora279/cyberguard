export default function ComplianceStatus({ breakdown = {} }) {
  const modules = Object.entries(breakdown);
  return (
    <div className="card">
      <h3>Module Breakdown</h3>
      <table>
        <tbody>
          {modules.map(([name, score]) => (
            <tr key={name}>
              <td style={{ texttransform: "capitalize" }}>{name.replace(/_/g, " ")}</td>
              <td style={{ width: "50%" }}>
                <div style={{ background: "#1c2330", borderRadius: 4, overflow: "hidden" }}>
                  <div
                    style={{
                      width: `${score}%`,
                      height: 8,
                      background: score >= 80 ? "#22c55e" : score >= 60 ? "#eab308" : "#ef4444",
                    }}
                  />
                </div>
              </td>
              <td style={{ textAlign: "right" }}>{Math.round(score)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
