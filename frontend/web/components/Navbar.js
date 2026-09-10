import Link from "next/link";
import { useRouter } from "next/router";

const LINKS = [
  ["/", "Dashboard"],
  ["/ai-governance", "AI Governance"],
  ["/security-debt", "Security Debt"],
  ["/supply-chain", "Supply Chain"],
  ["/machine-identity", "Machine Identity"],
  ["/fraud-detection", "Fraud Detection"],
  ["/predictive-risk", "Predictive Risk"],
  ["/cyber-twin", "Cyber Twin"],
  ["/settings", "Settings"],
];

export default function Navbar() {
  const { pathname } = useRouter();
  return (
    <nav className="nav">
      <h1>🛡️ CyberGuard AI</h1>
      {LINKS.map(([href, label]) => (
        <Link key={href} href={href} className={pathname === href ? "active" : ""}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
