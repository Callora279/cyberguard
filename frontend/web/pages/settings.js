import { useEffect, useState } from "react";
import useSWR from "swr";
import { api, fetcher, getToken, setToken, clearToken } from "../lib/api";

export default function Settings() {
  const [email, setEmail] = useState("admin@cyberguard.ai");
  const [password, setPassword] = useState("cyberguard-demo");
  const [authed, setAuthed] = useState(false);
  const { data: me } = useSWR(authed ? "/users/me" : null, fetcher);
  const { data: policyStatus } = useSWR(authed ? "/ai-governance/status" : null, fetcher);

  useEffect(() => { setAuthed(!!getToken()); }, []);

  async function login() {
    const res = await api("/auth/login", { method: "POST", auth: false, body: { email, password } });
    setToken(res.access_token);
    setAuthed(true);
  }

  return (
    <div className="grid" style={{ gap: 20, maxWidth: 560 }}>
      <h2>Settings</h2>

      <div className="card">
        <h3>Authentication</h3>
        {authed ? (
          <>
            <p>Signed in as <strong>{me?.email}</strong> ({me?.role})</p>
            <button className="ghost" onClick={() => { clearToken(); setAuthed(false); }}>Sign out</button>
          </>
        ) : (
          <div className="grid" style={{ gap: 10 }}>
            <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
            <button onClick={login}>Sign in</button>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Active AI Policy</h3>
        <pre style={{ overflow: "auto" }}>{JSON.stringify(policyStatus?.active_policy || {}, null, 2)}</pre>
      </div>

      <div className="card">
        <h3>Integrations</h3>
        <ul className="muted">
          <li>Chakra Intelligence — GET /internal/health-score</li>
          <li>LiveGuard — error forwarding enabled</li>
          <li>GitHub / GitLab / Jira / Slack agents — configured via environment</li>
        </ul>
      </div>
    </div>
  );
}
