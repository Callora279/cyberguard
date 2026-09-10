/** @type {import('next').NextConfig} */
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8090";

const nextConfig = {
  reactStrictMode: true,
  env: { NEXT_PUBLIC_API_BASE: API_BASE },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_BASE}/api/:path*` }];
  },
};

module.exports = nextConfig;
