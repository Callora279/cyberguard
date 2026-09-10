import "../styles/globals.css";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Navbar from "../components/Navbar";
import { getToken } from "../lib/api";

// Pages rendered without the app chrome (sidebar).
const BARE_ROUTES = ["/login", "/signup", "/onboarding"];
// Pages that don't require authentication.
const PUBLIC_ROUTES = ["/login", "/signup"];

export default function App({ Component, pageProps }) {
  const router = useRouter();
  const { pathname } = router;
  const [ready, setReady] = useState(PUBLIC_ROUTES.includes(pathname));

  useEffect(() => {
    if (PUBLIC_ROUTES.includes(pathname)) {
      setReady(true);
      return;
    }
    if (!getToken()) {
      router.replace(`/login?next=${encodeURIComponent(router.asPath)}`);
      return;
    }
    setReady(true);
  }, [pathname, router]);

  if (!ready) return null;

  if (BARE_ROUTES.includes(pathname)) {
    return <Component {...pageProps} />;
  }

  return (
    <div className="layout">
      <Navbar />
      <main className="content">
        <Component {...pageProps} />
      </main>
    </div>
  );
}
