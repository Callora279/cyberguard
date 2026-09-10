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
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    setBusy(true);
    try {
      const res = await api("/auth/register", {
        method: "POST",
        auth: false,
        body: { email, password, org_name: orgName || "My Organisation" },
      });
      setToken(res.access_token);
      router.push("/");
    } catch (err) {
      setError(err.message || "Sign up failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">
          <span className="auth-mark">🛡️</span>
          <span>CyberGuard AI</span>
        </div>
        <p className="auth-tagline">Create your security console</p>

        <label className="auth-label">Organisation</label>
        <input
          className="auth-input"
          value={orgName}
          onChange={(e) => setOrgName(e.target.value)}
          placeholder="Acme Inc."
        />

        <label className="auth-label">Email</label>
        <input
          className="auth-input"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          required
        />

        <label className="auth-label">Password</label>
        <input
          className="auth-input"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="At least 8 characters"
          required
        />

        <label className="auth-label">Confirm password</label>
        <input
          className="auth-input"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Re-enter password"
          required
        />

        {error && <div className="auth-error">{error}</div>}

        <button className="auth-btn" type="submit" disabled={busy}>
          {busy ? "Creating account…" : "Create account"}
        </button>

        <p className="auth-alt">
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      </form>
      <p className="auth-foot">🛡️ CyberGuard AI · unified AI-era cyber risk</p>
    </div>
  );
}
