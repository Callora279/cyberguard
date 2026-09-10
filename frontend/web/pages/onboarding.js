import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../lib/api";

const STEPS = [
  { n: 1, title: "Connect GitHub", blurb: "Scan your code for security debt & build an SBOM" },
  { n: 2, title: "Scan your website", blurb: "Check transport security and header hardening" },
  { n: 3, title: "Machine identities", blurb: "Track API keys & certs before they expire" },
  { n: 4, title: "Set up alerts", blurb: "Where should we send security notifications?" },
];

export default function Onboarding() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [serverStep, setServerStep] = useState(1);

  useEffect(() => {
    api("/onboarding/status")
      .then((s) => {
        if (s.completed) router.replace("/");
        else {
          setServerStep(s.current_step);
          setStep(s.current_step);
        }
      })
      .catch(() => {});
  }, [router]);

  function goto(n) {
    setStep(Math.min(4, Math.max(1, n)));
  }

  async function skip() {
    await api("/onboarding/skip", { method: "POST", body: { step } }).catch(() => {});
    goto(step + 1);
  }

  async function finish() {
    await api("/onboarding/complete", { method: "POST" }).catch(() => {});
    router.push("/");
  }

  return (
    <div className="onb-wrap">
      <div className="onb-head">
        <div className="auth-brand"><span className="auth-mark">🛡️</span><span>CyberGuard AI</span></div>
        <button className="ghost" onClick={finish}>Skip setup &rarr;</button>
      </div>

      <div className="onb-progress">
        {STEPS.map((s) => (
          <div key={s.n} className={`onb-dot ${step === s.n ? "active" : ""} ${s.n < step || s.n < serverStep ? "done" : ""}`}>
            <span>{s.n < step ? "✓" : s.n}</span>
            <label>{s.title}</label>
          </div>
        ))}
      </div>

      <div className="onb-card">
        <h2>{STEPS[step - 1].title}</h2>
        <p className="muted">{STEPS[step - 1].blurb}</p>

        {step === 1 && <StepGitHub onDone={() => goto(2)} onSkip={skip} />}
        {step === 2 && <StepWebsite onDone={() => goto(3)} onSkip={skip} />}
        {step === 3 && <StepIdentities onDone={() => goto(4)} onSkip={skip} />}
        {step === 4 && <StepAlerts onFinish={finish} onBack={() => goto(3)} />}
      </div>

      <p className="onb-foot">Step {step} of 4</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function StepGitHub({ onDone, onSkip }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function connect() {
    setBusy(true);
    setError(null);
    try {
      const r = await api("/onboarding/github", {
        method: "POST",
        body: { repo_url: repoUrl, token: token || null },
      });
      setResult(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    const d = result.security_debt || {};
    const s = result.supply_chain || {};
    return (
      <div className="onb-body">
        <div className="onb-results">
          <Stat label="Security findings" value={d.total_findings ?? 0} />
          <Stat label="Critical / High" value={(d.by_severity?.critical || 0) + (d.by_severity?.high || 0)} tone="crit" />
          <Stat label="Vulnerable deps" value={s.vulnerable_components ?? 0} />
          <Stat label="SBOM components" value={result.sbom_components ?? 0} />
          <Stat label="Risk score" value={result.risk_score ?? "—"} />
        </div>
        <p className="muted">Repository <code>{result.repo}</code> connected and scanned.</p>
        <div className="row"><button onClick={onDone}>Continue &rarr;</button></div>
      </div>
    );
  }

  return (
    <div className="onb-body">
      <label className="auth-label">GitHub repository URL</label>
      <input className="auth-input" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
        placeholder="https://github.com/your-org/your-repo" />
      <label className="auth-label">GitHub access token <span className="muted" style={{ textTransform: "none", fontWeight: 400 }}>— needs contents:read</span></label>
      <input className="auth-input" type="password" value={token} onChange={(e) => setToken(e.target.value)}
        placeholder="ghp_… (leave blank for public repos)" />
      {error && <div className="auth-error">{error}</div>}
      <div className="row" style={{ marginTop: 18 }}>
        <button onClick={connect} disabled={busy || !repoUrl}>
          {busy ? "Scanning repository…" : "Connect & scan"}
        </button>
        <button className="ghost" onClick={onSkip} disabled={busy}>Skip for now</button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function StepWebsite({ onDone, onSkip }) {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const r = await api("/onboarding/website", { method: "POST", body: { url } });
      setReport(r.report);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (report) {
    return (
      <div className="onb-body">
        <div className="onb-results">
          <Stat label="Security score" value={`${report.score}/100`} />
          <Stat label="Grade" value={report.grade} />
          <Stat label="Checks run" value={report.checks_run} />
          <Stat label="Issues" value={report.findings.filter((f) => f.severity !== "info").length} tone="crit" />
        </div>
        <table>
          <thead><tr><th>Severity</th><th>Issue</th></tr></thead>
          <tbody>
            {report.findings.slice(0, 10).map((f, i) => (
              <tr key={i}>
                <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
                <td>{f.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: 14 }}><button onClick={onDone}>Continue &rarr;</button></div>
      </div>
    );
  }

  return (
    <div className="onb-body">
      <label className="auth-label">Your website URL</label>
      <input className="auth-input" value={url} onChange={(e) => setUrl(e.target.value)}
        placeholder="https://yourcompany.com" />
      {error && <div className="auth-error">{error}</div>}
      <div className="row" style={{ marginTop: 18 }}>
        <button onClick={run} disabled={busy || !url}>{busy ? "Scanning…" : "Run security scan"}</button>
        <button className="ghost" onClick={onSkip} disabled={busy}>Skip for now</button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
const ID_TYPES = ["api_key", "service_account", "cert", "oauth", "ssh_key"];

function StepIdentities({ onDone, onSkip }) {
  const [name, setName] = useState("");
  const [type, setType] = useState("api_key");
  const [expiry, setExpiry] = useState("");
  const [added, setAdded] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      await api("/machine-identity/register", {
        method: "POST",
        body: {
          identity_type: type,
          name,
          expires_at: expiry ? new Date(expiry).toISOString() : null,
        },
      });
      setAdded((a) => [...a, { name, type, expiry }]);
      setName("");
      setExpiry("");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="onb-body">
      <p className="muted">We'll alert you before any of these expire.</p>
      <div className="onb-idrow">
        <input className="auth-input" placeholder="Name (e.g. Stripe prod key)" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="auth-input" value={type} onChange={(e) => setType(e.target.value)}>
          {ID_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
        </select>
        <input className="auth-input" type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
        <button onClick={add} disabled={busy || !name}>Add</button>
      </div>
      {error && <div className="auth-error">{error}</div>}
      {added.length > 0 && (
        <table>
          <tbody>
            {added.map((a, i) => (
              <tr key={i}><td>{a.name}</td><td className="muted">{a.type}</td><td className="muted">{a.expiry || "no expiry"}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="row" style={{ marginTop: 18 }}>
        <button onClick={onDone}>{added.length ? "Continue" : "Continue"} &rarr;</button>
        <button className="ghost" onClick={onSkip}>Skip for now</button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function StepAlerts({ onFinish, onBack }) {
  const [slack, setSlack] = useState("");
  const [email, setEmail] = useState("");
  const [threshold, setThreshold] = useState("high");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await api("/onboarding/alerts", {
        method: "POST",
        body: {
          slack_webhook_url: slack.trim() || null,
          report_email: email.trim() || null,
          alert_threshold: threshold,
        },
      });
      await onFinish();
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }

  return (
    <div className="onb-body">
      <label className="auth-label">Slack webhook URL</label>
      <input className="auth-input" value={slack} onChange={(e) => setSlack(e.target.value)}
        placeholder="https://hooks.slack.com/services/…" />
      <label className="auth-label">Email for weekly reports</label>
      <input className="auth-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
        placeholder="security@yourcompany.com" />
      <label className="auth-label">Alert me at severity</label>
      <select className="auth-input" value={threshold} onChange={(e) => setThreshold(e.target.value)}>
        <option value="critical">Critical only</option>
        <option value="high">High and above</option>
        <option value="medium">Medium and above</option>
        <option value="low">Everything</option>
      </select>
      {error && <div className="auth-error">{error}</div>}
      <div className="row" style={{ marginTop: 18 }}>
        <button className="ghost" onClick={onBack} disabled={busy}>&larr; Back</button>
        <button onClick={save} disabled={busy}>{busy ? "Finishing…" : "Finish setup"}</button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function Stat({ label, value, tone }) {
  return (
    <div className="onb-stat">
      <span className="big" style={{ fontSize: 26, color: tone === "crit" ? "var(--crit)" : "var(--text)" }}>{value}</span>
      <label className="muted">{label}</label>
    </div>
  );
}
