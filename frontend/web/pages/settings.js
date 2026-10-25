import { useState } from "react";
import useSWR from "swr";
import { api, fetcher, clearToken, downloadFile } from "../lib/api";

export default function Settings() {
  const { data: me } = useSWR("/users/me", fetcher);
  const { data: settings, mutate: mutateSettings } = useSWR("/settings", fetcher);
  const { data: billing } = useSWR("/settings/billing", fetcher);
  const { data: team, mutate: mutateTeam } = useSWR("/users", fetcher);
  const { data: tokens, mutate: mutateTokens } = useSWR("/settings/api-tokens", fetcher);
  const { data: aiSettings, mutate: mutateAiSettings } = useSWR("/settings/ai", fetcher);
  const { data: aiProviders } = useSWR("/settings/ai/providers", fetcher);

  return (
    <div className="grid" style={{ gap: 20, maxWidth: 760 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Settings</h2>
        <span className="muted">{me?.email} · {me?.role}
          {"  "}
          <a href="#" onClick={(e) => { e.preventDefault(); clearToken(); location.href = "/login"; }}>Sign out</a>
        </span>
      </div>

      <IntegrationStatus settings={settings} />
      <BillingCard billing={billing} />
      <AIProviderCard aiSettings={aiSettings} providers={aiProviders?.providers} onSaved={mutateAiSettings} />
      <GitHubCard settings={settings} onSaved={mutateSettings} />
      <SlackCard settings={settings} onSaved={mutateSettings} />
      <EmailCard settings={settings} onSaved={mutateSettings} />
      <JiraCard settings={settings} onSaved={mutateSettings} />
      <TeamCard team={team} onChanged={mutateTeam} />
      <ApiTokensCard tokens={tokens} onChanged={mutateTokens} />
      <ComplianceReportsCard />
    </div>
  );
}

/* ------------------------------------------------------------------ */
function useSave(onSaved) {
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);
  async function save(body) {
    setError(null);
    try {
      await api("/settings", { method: "PUT", body });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      onSaved && onSaved();
    } catch (e) { setError(e.message || "Save failed"); }
  }
  return { save, saved, error };
}

function TestButton({ integration }) {
  const [state, setState] = useState(null); // null | "…" | "ok" | "fail"
  const [detail, setDetail] = useState("");
  async function run() {
    setState("…"); setDetail("");
    try {
      const r = await api("/settings/integrations/test", { method: "POST", body: { integration } });
      setState(r.ok ? "ok" : "fail");
      setDetail(typeof r.detail === "string" ? r.detail : JSON.stringify(r.detail || {}));
    } catch (e) { setState("fail"); setDetail(e.message); }
  }
  return (
    <span className="row" style={{ gap: 8, alignItems: "center" }}>
      <button className="ghost" onClick={run} disabled={state === "…"}>
        {state === "…" ? "Testing…" : "Test connection"}
      </button>
      {state === "ok" && <span style={{ color: "var(--low)" }}>✓ connected</span>}
      {state === "fail" && <span style={{ color: "var(--crit)" }}>✗ {detail}</span>}
    </span>
  );
}

const STATUS_DOT = (ok) => (
  <span style={{
    display: "inline-block", width: 9, height: 9, borderRadius: "50%",
    background: ok ? "var(--low)" : "var(--muted)", marginRight: 8,
  }} />
);

/* ------------------------------------------------------------------ */
function IntegrationStatus({ settings }) {
  if (!settings) return null;
  const rows = [
    ["GitHub", settings.github?.connected],
    ["Slack", !!settings.alerts?.slack_webhook_url],
    ["Email", !!settings.email?.notification_email],
    ["Jira", settings.jira?.connected],
  ];
  return (
    <div className="card">
      <h3>Integrations</h3>
      <div className="row" style={{ gap: 24, flexWrap: "wrap" }}>
        {rows.map(([name, ok]) => (
          <span key={name}>{STATUS_DOT(ok)}{name} <span className="muted">{ok ? "connected" : "not set up"}</span></span>
        ))}
      </div>
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
    </div>
  );
}

/* ------------------------------------------------------------------ */
function AITestButton() {
  const [state, setState] = useState(null); // null | "…" | "ok" | "fail"
  const [detail, setDetail] = useState("");
  async function run() {
    setState("…"); setDetail("");
    try {
      const r = await api("/settings/ai/test", { method: "POST" });
      setState(r.ok ? "ok" : "fail");
      setDetail(r.ok ? `${r.provider} / ${r.model} · ${r.latency_ms}ms` : (r.error || "unknown error"));
    } catch (e) { setState("fail"); setDetail(e.message); }
  }
  return (
    <span className="row" style={{ gap: 8, alignItems: "center" }}>
      <button className="ghost" onClick={run} disabled={state === "…"}>
        {state === "…" ? "Testing…" : "Test connection"}
      </button>
      {state === "ok" && <span style={{ color: "var(--low)" }}>✓ {detail}</span>}
      {state === "fail" && <span style={{ color: "var(--crit)" }}>✗ {detail}</span>}
    </span>
  );
}

function AIProviderCard({ aiSettings, providers, onSaved }) {
  const { save, saved, error } = useSave(onSaved);
  const [provider, setProvider] = useState(null);
  const [model, setModel] = useState(null);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [temperature, setTemperature] = useState(null);
  const [maxTokens, setMaxTokens] = useState(null);

  const activeProvider = provider ?? aiSettings?.provider ?? "groq";
  const activeModel = model ?? aiSettings?.model ?? "";
  const activeTemp = temperature ?? aiSettings?.temperature ?? 0.2;
  const activeMaxTokens = maxTokens ?? aiSettings?.max_tokens ?? 1024;
  const catalog = providers?.[activeProvider];

  if (!aiSettings || !providers) return null;

  async function doSave() {
    await save({
      provider: activeProvider,
      model: activeModel || catalog?.default_model || "",
      api_key: apiKey || undefined,
      base_url: activeProvider === "custom" ? baseUrl || aiSettings.base_url || undefined : undefined,
      max_tokens: activeMaxTokens,
      temperature: activeTemp,
    });
    setApiKey("");
  }

  return (
    <div className="card">
      <h3>AI Provider</h3>
      <p className="muted">
        {aiSettings.using_system_default
          ? "Using the CyberGuard AI system default (Groq)."
          : `Using your own ${providers[aiSettings.provider]?.label || aiSettings.provider} key.`}
        {" "}Bring your own key to keep data with your preferred provider, control costs, or use an
        on-premise / self-hosted model.
      </p>

      <label className="auth-label">Provider</label>
      <select className="auth-input" value={activeProvider} onChange={(e) => { setProvider(e.target.value); setModel(""); }}>
        {Object.entries(providers).map(([id, p]) => <option key={id} value={id}>{p.label}</option>)}
      </select>

      <label className="auth-label">
        API key {aiSettings.api_key_configured ? `(current: ${aiSettings.api_key_masked})` : catalog?.requires_key ? "(required)" : "(optional)"}
      </label>
      <input className="auth-input" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
        placeholder={activeProvider === "groq" ? "Leave blank to use the system default key" : "Leave blank to keep current"} />

      {catalog?.requires_base_url && (
        <>
          <label className="auth-label">Base URL</label>
          <input className="auth-input" defaultValue={aiSettings.base_url || ""} onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://localhost:11434/v1  (Ollama, LM Studio, Azure OpenAI, ...)" />
          {catalog.hint && <p className="muted" style={{ fontSize: 12 }}>{catalog.hint}</p>}
        </>
      )}

      <label className="auth-label">Model</label>
      {catalog?.models?.length ? (
        <select className="auth-input" value={activeModel || catalog.default_model} onChange={(e) => setModel(e.target.value)}>
          {catalog.models.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
        </select>
      ) : (
        <input className="auth-input" value={activeModel} onChange={(e) => setModel(e.target.value)}
          placeholder="model name" />
      )}

      <details style={{ marginTop: 10 }}>
        <summary className="muted" style={{ cursor: "pointer" }}>Advanced</summary>
        <div className="row" style={{ gap: 16, marginTop: 8 }}>
          <div>
            <label className="auth-label">Temperature</label>
            <input className="auth-input" type="number" min="0" max="2" step="0.1" style={{ width: 90 }}
              value={activeTemp} onChange={(e) => setTemperature(parseFloat(e.target.value))} />
          </div>
          <div>
            <label className="auth-label">Max tokens</label>
            <input className="auth-input" type="number" min="1" max="32000" step="1" style={{ width: 110 }}
              value={activeMaxTokens} onChange={(e) => setMaxTokens(parseInt(e.target.value, 10))} />
          </div>
        </div>
      </details>

      <div className="row" style={{ marginTop: 14, gap: 12 }}>
        <button onClick={doSave}>Save</button>
        <AITestButton />
        {saved && <span className="muted">Saved ✓</span>}
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function ComplianceReportsCard() {
  const REPORTS = [
    ["nhs_dsp_toolkit", "NHS DSP Toolkit"],
    ["gdpr_article_32", "GDPR Article 32"],
    ["cyber_essentials", "Cyber Essentials"],
  ];
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function download(framework) {
    setBusy(framework); setError(null);
    try {
      await downloadFile(`/compliance/report/${framework}`, `${framework}.pdf`);
    } catch (e) { setError(e.message); }
    setBusy(null);
  }

  return (
    <div className="card">
      <h3>Compliance Reports</h3>
      <p className="muted">Download an evidence-backed PDF compliance pack, generated live from your current scan results.</p>
      <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
        {REPORTS.map(([id, label]) => (
          <button key={id} className="ghost" onClick={() => download(id)} disabled={busy === id}>
            {busy === id ? "Generating…" : `${label} PDF`}
          </button>
        ))}
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function GitHubCard({ settings, onSaved }) {
  const gh = settings?.github || {};
  const { save, saved, error } = useSave(onSaved);
  const [repo, setRepo] = useState("");
  const [token, setToken] = useState("");
  const [secret, setSecret] = useState("");

  return (
    <div className="card">
      <h3>{STATUS_DOT(gh.connected)}GitHub</h3>
      <p className="muted">{gh.connected ? `Connected: ${gh.repo_url}` : "Not connected"}
        {gh.token ? ` · token ${gh.token}` : ""}</p>

      <label className="auth-label">Repository URL</label>
      <input className="auth-input" defaultValue={gh.repo_url || ""} onChange={(e) => setRepo(e.target.value)}
        placeholder="https://github.com/org/repo" />
      <label className="auth-label">GitHub token</label>
      <input className="auth-input" type="password" value={token} onChange={(e) => setToken(e.target.value)}
        placeholder="ghp_… (leave blank to keep current)" />
      <label className="auth-label">Webhook secret {gh.webhook_secret ? `(current: ${gh.webhook_secret})` : ""}</label>
      <input className="auth-input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)}
        placeholder="shared secret for X-Hub-Signature-256" />
      <p className="muted" style={{ fontSize: 12 }}>
        Add a webhook in GitHub → Settings → Webhooks pointing at
        {" "}<code>{typeof location !== "undefined" ? location.origin : ""}{gh.webhook_url}</code>
        {" "}(content type <code>application/json</code>), using the secret above.
      </p>

      <div className="row" style={{ marginTop: 14, gap: 12 }}>
        <button onClick={() => save({
          github_repo_url: repo || undefined,
          github_token: token || undefined,
          github_webhook_secret: secret || undefined,
        })}>Save</button>
        <TestButton integration="github" />
        {saved && <span className="muted">Saved ✓</span>}
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function SlackCard({ settings, onSaved }) {
  const a = settings?.alerts || {};
  const { save, saved, error } = useSave(onSaved);
  const [slack, setSlack] = useState("");
  const [threshold, setThreshold] = useState(a.alert_threshold || "high");
  const [digest, setDigest] = useState(!!a.slack_daily_digest);

  return (
    <div className="card">
      <h3>{STATUS_DOT(!!a.slack_webhook_url)}Slack</h3>
      <label className="auth-label">Webhook URL {a.slack_webhook_url ? `(current: ${a.slack_webhook_url})` : ""}</label>
      <input className="auth-input" value={slack} onChange={(e) => setSlack(e.target.value)}
        placeholder="https://hooks.slack.com/services/…" />
      <label className="auth-label">Alert severity threshold</label>
      <select className="auth-input" value={threshold} onChange={(e) => setThreshold(e.target.value)}>
        <option value="critical">Critical only</option>
        <option value="high">High and above</option>
        <option value="medium">Medium and above</option>
        <option value="low">Everything</option>
      </select>
      <label className="row" style={{ gap: 8, marginTop: 10, alignItems: "center" }}>
        <input type="checkbox" checked={digest} onChange={(e) => setDigest(e.target.checked)} />
        Send a daily digest to Slack (08:00 UTC)
      </label>
      <div className="row" style={{ marginTop: 14, gap: 12 }}>
        <button onClick={() => save({
          slack_webhook_url: slack || undefined,
          alert_threshold: threshold,
          slack_daily_digest: digest,
        })}>Save</button>
        <TestButton integration="slack" />
        {saved && <span className="muted">Saved ✓</span>}
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
const ALERT_TYPES = [
  ["critical_finding", "Critical security finding"],
  ["fraud_alert", "Fraud alert (score > 0.7)"],
  ["credential_expiring", "Credential expiring in 7 days"],
  ["risk_drop", "Risk score dropped significantly"],
];

function EmailCard({ settings, onSaved }) {
  const e0 = settings?.email || {};
  const { save, saved, error } = useSave(onSaved);
  const [email, setEmail] = useState("");
  const [types, setTypes] = useState(new Set(e0.notify_types || []));
  const [weekly, setWeekly] = useState(e0.weekly_digest !== false);

  function toggle(t) {
    const n = new Set(types);
    n.has(t) ? n.delete(t) : n.add(t);
    setTypes(n);
  }

  return (
    <div className="card">
      <h3>{STATUS_DOT(!!e0.notification_email)}Email</h3>
      <label className="auth-label">Notification email {e0.notification_email ? `(current: ${e0.notification_email})` : ""}</label>
      <input className="auth-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
        placeholder="security@yourcompany.com" />
      <label className="auth-label">Alert types to receive <span className="muted" style={{ textTransform: "none" }}>— none selected = all</span></label>
      {ALERT_TYPES.map(([t, label]) => (
        <label key={t} className="row" style={{ gap: 8, alignItems: "center" }}>
          <input type="checkbox" checked={types.has(t)} onChange={() => toggle(t)} /> {label}
        </label>
      ))}
      <label className="row" style={{ gap: 8, marginTop: 10, alignItems: "center" }}>
        <input type="checkbox" checked={weekly} onChange={(e) => setWeekly(e.target.checked)} />
        Weekly security digest (Mondays 09:00 UTC)
      </label>
      <div className="row" style={{ marginTop: 14, gap: 12 }}>
        <button onClick={() => save({
          notification_email: email || undefined,
          notify_types: [...types],
          weekly_digest: weekly,
        })}>Save</button>
        <TestButton integration="email" />
        {saved && <span className="muted">Saved ✓</span>}
      </div>
      {error && <div className="auth-error">{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function JiraCard({ settings, onSaved }) {
  const j = settings?.jira || {};
  const { save, saved, error } = useSave(onSaved);
  const [url, setUrl] = useState("");
  const [user, setUser] = useState("");
  const [token, setToken] = useState("");
  const [project, setProject] = useState("");

  return (
    <div className="card">
      <h3>{STATUS_DOT(j.connected)}Jira</h3>
      <label className="auth-label">Jira URL</label>
      <input className="auth-input" defaultValue={j.url || ""} onChange={(e) => setUrl(e.target.value)}
        placeholder="https://your-org.atlassian.net" />
      <label className="auth-label">Username / email</label>
      <input className="auth-input" defaultValue={j.user || ""} onChange={(e) => setUser(e.target.value)}
        placeholder="you@company.com" />
      <label className="auth-label">API token {j.token ? `(current: ${j.token})` : ""}</label>
      <input className="auth-input" type="password" value={token} onChange={(e) => setToken(e.target.value)}
        placeholder="Atlassian API token" />
      <label className="auth-label">Project key</label>
      <input className="auth-input" defaultValue={j.project_key || ""} onChange={(e) => setProject(e.target.value)}
        placeholder="SEC" />
      <div className="row" style={{ marginTop: 14, gap: 12 }}>
        <button onClick={() => save({
          jira_url: url || undefined,
          jira_user: user || undefined,
          jira_token: token || undefined,
          jira_project_key: project || undefined,
        })}>Save</button>
        <TestButton integration="jira" />
        {saved && <span className="muted">Saved ✓</span>}
      </div>
      {error && <div className="auth-error">{error}</div>}
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
