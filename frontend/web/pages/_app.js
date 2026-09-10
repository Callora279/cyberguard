import "../styles/globals.css";
import Navbar from "../components/Navbar";

export default function App({ Component, pageProps }) {
  return (
    <div className="layout">
      <Navbar />
      <main className="content">
        <Component {...pageProps} />
      </main>
    </div>
  );
}
