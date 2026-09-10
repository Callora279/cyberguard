import { useState } from "react";
import useSWR from "swr";
import { api, fetcher, clearToken } from "../lib/api";

export default function Settings() {
  const { data: me } = useSWR("/users/me", fetcher);
  const { data: settings, mutate: mutateSettings } = useSWR("/settings", fetcher);
  const { data: billing } = useSWR("/settings/billing", fetcher);
  const { data: team, mutate: mutateTeam } = useSWR("/users", fetcher);
  const { data: tokens, mutate: mutateTokens } = useSWR("/settings/api-tokens", fetcher);

  return (
    <div className="grid" style={{ gap: 20, maxWidth: 720 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Settings</h2>
        <span className="muted">{me?.email} · {me?.role}
          {"  "}
          <a href="#" onClick={(e) => { e.preventDefault(); clearToken(); location.href = "/login"; }}>Sign out</a>
        </span>
      </div>

      <BillingCard billing={billing} />
      <IntegrationsCard settings={settings} onSaved={mutateSettings} />
      <NotificationsCard settings={settings} onSaved={mutateSettings} />
      <TeamCard team={team} onChanged={mutateTeam} />
      <ApiTokensCard tokens={tokens} onChanged={mutateTokens} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
function BillingCard({ billing }) {
  if (!billing) return null;
  const b = billing;
  return (
    <div className="card">
      <h3>Plan &amp; billing</h3>
      <div className="row" style={{ gap: 24 }}>
        <div><span className="big" style={{ fontSize: 22, textTransform: "capitalize" }}>{b.plan}</span>
          <div className="muted">current plan</div></div>
        {b.trial_days_left != null && (
          <div><span className="big" style={{ fontSize: 22 }}>{b.trial_days_left}</span>
            <div className="muted">trial days left</div></div>
        )}
        <div><span className="big" style={{ fontSize: 22 }}>{b.limits?.repos === -1 ? "∞" : b.limits?.repos}</span>
          <div className="muted">repos</div></div>
        <div><span className="big" style={{ fontSize: 22 }}>{b.limits?.scans_per_day === -1 ? "∞" : b.limits?.scans_per_day}</span>
          <div className="muted">scans / day</div></div>
      </div>
      {b.plan === "trial" && (
        <p className="muted" style={{ marginTop: 12 }}>
          Enter a license key on the <strong>Integrations</strong> of your account manager to upgrade, or contact sales.
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function IntegrationsCard({ settings, onSaved }) {
  const [repo, setRepo] = useState("");
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState(false);
  const gh = settings?.github || {};

  async function save() {
    await api("/settings", { method: "PUT", body: {
      github_repo_url: repo || undefined,
      github_token: token || undefined,
    }});
    setToken("");
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    onSaved();
  }

  return (
    <div className="card">
      <h3>GitHub integration</h3>
      <p className="muted">
        {gh.connected ? `Connected: ${gh.repo_url}` : "Not connected"}
        {gh.token ? ` · token ${gh.token}` : ""}
      </p>
      <label className="auth-label">Repository URL</label>
      <input className="auth-input" defaultValue={gh.repo_url || ""} onChange={(e) => setRepo(e.target.value)}
        placeholder="https://github.com/org/repo" />
      <label className="auth-label">Access token</label>
      <input className="auth-input" type="password" value={token} onChange={(e) => setToken(e.target.value)}
        placeholder="ghp_… (leave blank to keep current)" />
      <div className="row" style={{ marginTop: 14 }}>
        <button onClick={save}>Save</button>
        {saved && <span className="muted">Saved ✓</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function NotificationsCard({ settings, onSaved }) {
  const a = settings?.alerts || {};
  const [slack, setSlack] = useState("");
  const [email, setEmail] = useState("");
  const [threshold, setThreshold] = useState(a.alert_threshold || "high");
  const [saved, setSaved] = useState(false);

  async function save() {
    await api("/settings", { method: "PUT", body: {
      slack_webhook_url: slack || undefined,
      report_email: email || undefined,
      alert_threshold: threshold,
    }});
    setSlack(""); setEmail("");
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    onSaved();
  }

  return (
    <div className="card">
      <h3>Notifications</h3>
      <label className="auth-label">Slack webhook {a.slack_webhook_url ? `(current: ${a.slack_webhook_url})` : ""}</label>
      <input className="auth-input" value={slack} onChange={(e) => setSlack(e.target.value)}
        placeholder="https://hooks.slack.com/services/…" />
      <label className="auth-label">Weekly report email {a.report_email ? `(current: ${a.report_email})` : ""}</label>
      <input className="auth-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
        placeholder="security@yourcompany.com" />
      <label className="auth-label">Alert severity threshold</label>
      <select className="auth-input" value={threshold} onChange={(e) => setThreshold(e.target.value)}>
        <option value="critical">Critical only</option>
        <option value="high">High and above</option>
        <option value="medium">Medium and above</option>
        <option value="low">Everything</option>
      </select>
      <div className="row" style={{ marginTop: 14 }}>
        <button onClick={save}>Save</button>
        {saved && <span className="muted">Saved ✓</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function TeamCard({ team, onChanged }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState(null);

  async function invite() {
    setError(null);
    try {
      await api("/users", { method: "POST", body: { email, password, role } });
      setEmail(""); setPassword("");
      onChanged();
    } catch (e) { setError(e.message); }
  }

  return (
    <div className="card">
      <h3>Team members</h3>
      <table>
        <thead><tr><th>Email</th><th>Role</th><th>Status</th></tr></thead>
        <tbody>
          {(team || []).map((u) => (
            <tr key={u.id}>
              <td>{u.email}</td>
              <td>{u.role}</td>
              <td>{u.is_active ? "active" : "disabled"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="onb-idrow" style={{ marginTop: 12 }}>
        <input className="auth-input" placeholder="teammate@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input className="auth-input" type="password" placeholder="temp password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <select className="auth-input" value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="viewer">viewer</option>
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
        <button onClick={invite} disabled={!email || password.length < 8}>Add</button>
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function ApiTokensCard({ tokens, onChanged }) {
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState(null);

  async function create() {
    const r = await api("/settings/api-tokens", { method: "POST", body: { name: name || "CLI token" } });
    setFresh(r);
    setName("");
    onChanged();
  }
  async function revoke(id) {
    await api(`/settings/api-tokens/${id}`, { method: "DELETE" });
    onChanged();
  }

  return (
    <div className="card">
      <h3>API keys (CLI access)</h3>
      <p className="muted">Use with the CyberGuard CLI: <code>cyberguard --token &lt;token&gt; scan</code></p>
      {fresh && (
        <div className="auth-error" style={{ color: "var(--low)", background: "rgba(34,197,94,.12)", borderColor: "rgba(34,197,94,.35)" }}>
          New token — copy it now, it won't be shown again:<br />
          <code style={{ wordBreak: "break-all" }}>{fresh.token}</code>
        </div>
      )}
      <table>
        <tbody>
          {(tokens?.tokens || []).map((t) => (
            <tr key={t.id}>
              <td>{t.name}</td>
              <td className="muted"><code>{t.prefix}…</code></td>
              <td className="muted">{t.last_used_at ? String(t.last_used_at).slice(0, 10) : "never used"}</td>
              <td style={{ textAlign: "right" }}><button className="ghost" onClick={() => revoke(t.id)}>Revoke</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row" style={{ marginTop: 12 }}>
        <input className="auth-input" style={{ maxWidth: 240 }} placeholder="Token name" value={name} onChange={(e) => setName(e.target.value)} />
        <button onClick={create}>Create token</button>
      </div>
    </div>
  );
}
