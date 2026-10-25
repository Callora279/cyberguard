// Tiny fetch wrapper with bearer-token auth stored in localStorage.
//
// All requests use RELATIVE URLs ("/api/..."). In production nginx proxies
// /api/ to the backend; in local dev the next.config.js rewrite does the same.
// No API host is ever hardcoded or baked into the bundle.

export function getToken() {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("cg_token");
}

export function setToken(token) {
  window.localStorage.setItem("cg_token", token);
}

export function clearToken() {
  window.localStorage.removeItem("cg_token");
}

export async function api(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  const token = auth ? getToken() : null;
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.message || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

// SWR fetcher
export const fetcher = (path) => api(path);

// Authenticated file download (e.g. a compliance PDF) — a plain <a href>
// can't carry the bearer token, so fetch as a blob and trigger a save.
export async function downloadFile(path, fallbackName = "download") {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`/api${path}`, { headers });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.message || `${res.status} ${res.statusText}`);
  }
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : fallbackName;

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
