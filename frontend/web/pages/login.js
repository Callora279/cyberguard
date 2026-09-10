import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { api, setToken } from "../lib/api";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api("/auth/login", {
        method: "POST",
        auth: false,
        body: { email, password },
      });
      setToken(res.access_token);
      router.push("/");
    } catch (err) {
      setError(err.message || "Login failed");
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
        <p className="auth-tagline">Sign in to your security console</p>

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
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
          required
        />

        {error && <div className="auth-error">{error}</div>}

        <button className="auth-btn" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <p className="auth-alt">
          New to CyberGuard? <Link href="/signup">Create an account</Link>
        </p>
      </form>
      <p className="auth-foot">🛡️ CyberGuard AI · unified AI-era cyber risk</p>
    </div>
  );
}
