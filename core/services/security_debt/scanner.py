"""Static scanner for security debt in a code tree.

Detects:
    * hardcoded secrets (regex + entropy)
    * outdated / vulnerable dependencies (delegates to supply_chain)
    * insecure function usage (eval, pickle, md5, subprocess shell=True, ...)
    * common OWASP violations (SQL string concat, missing TLS verify, ...)
    * technical-debt hotspots (TODO/FIXME/HACK density, very long files)
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.utils.logger import get_logger

logger = get_logger("security_debt.scanner")

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next"}
_TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".c",
    ".cpp", ".cs", ".yml", ".yaml", ".env", ".sh", ".tf", ".dart", ".sql",
}

_SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "groq_key": r"gsk_[A-Za-z0-9]{30,}",
    "github_pat": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "generic_secret": r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
}

_INSECURE_FUNCS = {
    "python": [
        (r"\beval\s*\(", "use of eval()"),
        (r"\bexec\s*\(", "use of exec()"),
        (r"pickle\.loads?\s*\(", "insecure deserialization via pickle"),
        (r"hashlib\.md5\s*\(", "weak hash MD5"),
        (r"hashlib\.sha1\s*\(", "weak hash SHA1"),
        (r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True", "shell=True command injection risk"),
        (r"yaml\.load\s*\((?!.*Loader)", "unsafe yaml.load without SafeLoader"),
        (r"verify\s*=\s*False", "TLS verification disabled"),
        (r"DEBUG\s*=\s*True", "debug mode enabled"),
    ],
    "javascript": [
        (r"\beval\s*\(", "use of eval()"),
        (r"dangerouslySetInnerHTML", "raw HTML injection (XSS)"),
        (r"child_process.*exec\(", "command execution"),
        (r"Math\.random\(\).*(token|secret|password)", "insecure randomness for secrets"),
    ],
}

_OWASP_PATTERNS = [
    (r"(?i)(select|insert|update|delete)\s+.*\+\s*(req\.|request\.|params|user_input|f['\"])", "A03 possible SQL injection (string concatenation)"),
    (r"(?i)cors\([^)]*origin\s*:\s*['\"]\*", "A05 permissive CORS wildcard"),
    (r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", "A05 permissive CORS wildcard"),
    (r"(?i)http://[a-z0-9.-]+/(api|login|auth)", "A02 cleartext transport for sensitive endpoint"),
    (r"(?i)md5|sha1", "A02 weak cryptographic primitive referenced"),
]

_DEBT_MARKERS = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b")


@dataclass
class Finding:
    type: str
    title: str
    file_path: str
    line: int
    severity: str
    snippet: str = ""
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _lang_for(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    return "other"


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in _TEXT_EXT or p.name in {"requirements.txt", "package.json", "go.mod", "Gemfile", "pom.xml", "Dockerfile"}:
            yield p


def scan_path(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        lines = text.splitlines()
        debt_hits = 0

        for i, line in enumerate(lines, start=1):
            for name, pat in _SECRET_PATTERNS.items():
                for m in re.finditer(pat, line):
                    token = m.group(0)
                    high_entropy = _shannon_entropy(token) > 3.0
                    findings.append(
                        Finding(
                            type="secret",
                            title=f"Hardcoded secret ({name})",
                            file_path=rel,
                            line=i,
                            severity="critical" if high_entropy or name != "generic_secret" else "high",
                            snippet=_redact(line),
                            metadata={"detector": name, "entropy": round(_shannon_entropy(token), 2)},
                        )
                    )

            for pat, desc in _INSECURE_FUNCS.get(_lang_for(path), []):
                if re.search(pat, line):
                    findings.append(
                        Finding(
                            type="insecure_fn",
                            title=desc,
                            file_path=rel,
                            line=i,
                            severity="high",
                            snippet=line.strip()[:200],
                        )
                    )

            for pat, desc in _OWASP_PATTERNS:
                if re.search(pat, line):
                    findings.append(
                        Finding(
                            type="owasp",
                            title=desc,
                            file_path=rel,
                            line=i,
                            severity="medium",
                            snippet=line.strip()[:200],
                        )
                    )

            if _DEBT_MARKERS.search(line):
                debt_hits += 1

        if debt_hits >= 5 or len(lines) > 800:
            findings.append(
                Finding(
                    type="debt",
                    title="Technical-debt hotspot",
                    file_path=rel,
                    line=1,
                    severity="low",
                    snippet=f"{debt_hits} debt markers, {len(lines)} lines",
                    metadata={"debt_markers": debt_hits, "loc": len(lines)},
                )
            )

    logger.info("scan of %s produced %d findings", root, len(findings))
    return findings


def _redact(line: str) -> str:
    return re.sub(r"(['\"])[^'\"]{6,}(['\"])", r"\1***REDACTED***\2", line).strip()[:200]


def scan_dependencies(root: str | Path) -> list[Finding]:
    """Bridge to the supply-chain dependency scanner for a unified debt view."""
    from core.services.supply_chain import dependency_scanner

    out: list[Finding] = []
    for vuln in dependency_scanner.scan_path(root):
        out.append(
            Finding(
                type="dependency",
                title=f"{vuln['package']} {vuln['version']} - {vuln['id']}",
                file_path=vuln.get("manifest", ""),
                line=0,
                severity=vuln.get("severity", "medium"),
                snippet=vuln.get("summary", "")[:200],
                metadata=vuln,
            )
        )
    return out
