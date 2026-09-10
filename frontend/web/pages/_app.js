import "../styles/globals.css";
import { useRouter } from "next/router";
import Navbar from "../components/Navbar";

const BARE_ROUTES = ["/login", "/signup"];

export default function App({ Component, pageProps }) {
  const { pathname } = useRouter();

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
