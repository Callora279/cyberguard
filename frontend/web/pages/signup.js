import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { api, setToken } from "../lib/api";

export default function Signup() {
  const router = useRouter();
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [licenseKey, setLicenseKey] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function register(startTrial) {
    setError(null);
    if (password.length < 8) return setError("Password must be at least 8 characters");
    if (password !== confirm) return setError("Passwords do not match");
    setBusy(true);
    try {
      const res = await api("/auth/register", {
        method: "POST",
        auth: false,
        body: {
          email,
          password,
          org_name: orgName || "My Organisation",
          license_key: startTrial ? null : licenseKey.trim() || null,
          start_trial: startTrial,
        },
      });
      setToken(res.access_token);
      router.push("/onboarding");
    } catch (err) {
      setError(err.message || "Sign up failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={(e) => { e.preventDefault(); register(true); }}>
        <div className="auth-brand">
          <span className="auth-mark">🛡️</span>
          <span>CyberGuard AI</span>
        </div>
        <p className="auth-tagline">Create your security console</p>

        <label className="auth-label">Organisation name</label>
        <input className="auth-input" value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Inc." />

        <label className="auth-label">Work email</label>
        <input
          className="auth-input" type="email" autoComplete="username" required
          value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com"
        />

        <label className="auth-label">Password</label>
        <input
          className="auth-input" type="password" autoComplete="new-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters"
        />

        <label className="auth-label">Confirm password</label>
        <input
          className="auth-input" type="password" autoComplete="new-password" required
          value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Re-enter password"
        />

        <label className="auth-label">License key <span className="muted" style={{ textTransform: "none", fontWeight: 400 }}>— optional, for paid plans</span></label>
        <input
          className="auth-input" value={licenseKey}
          onChange={(e) => setLicenseKey(e.target.value)} placeholder="CG-XXXX-XXXX-XXXX"
        />

        {error && <div className="auth-error">{error}</div>}

        {licenseKey.trim() ? (
          <button className="auth-btn" type="button" disabled={busy} onClick={() => register(false)}>
            {busy ? "Activating…" : "Activate license & continue"}
          </button>
        ) : (
          <button className="auth-btn" type="submit" disabled={busy}>
            {busy ? "Creating account…" : "Start free 14-day trial"}
          </button>
        )}

        <p className="auth-alt">No credit card required · full access during the trial</p>
        <p className="auth-alt">
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      </form>
      <p className="auth-foot">🛡️ CyberGuard AI · unified AI-era cyber risk</p>
    </div>
  );
}
