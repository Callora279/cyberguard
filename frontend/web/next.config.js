/** @type {import('next').NextConfig} */

// The app always calls relative "/api/..." URLs.
//   - production: nginx proxies /api/ -> backend (nothing to configure here)
//   - local dev:  this rewrite proxies /api/ -> the backend so `next dev` works
//                 without nginx. Override the target with API_PROXY_TARGET.
const DEV_API_TARGET = process.env.API_PROXY_TARGET || "http://localhost:8090";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    if (process.env.NODE_ENV !== "development") return [];
    return [{ source: "/api/:path*", destination: `${DEV_API_TARGET}/api/:path*` }];
  },
};

module.exports = nextConfig;
