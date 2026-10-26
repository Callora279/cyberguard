"""Static scanner for security debt in a code tree.

Detects:
    * hardcoded secrets (regex + entropy)
    * outdated / vulnerable dependencies (delegates to supply_chain)
    * insecure function usage (eval, pickle, md5, subprocess shell=True, ...)
    * common OWASP violations (SQL string concat, missing TLS verify, ...)
    * technical-debt hotspots (TODO/FIXME/HACK density, very long files)
"""
from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.utils.config import settings
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
    # Captures just the assigned value so entropy is scored on the secret
    # itself, not the surrounding `keyword: "..."` syntax.
    "generic_secret": r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
}

# Test code routinely assigns literal password/token/key values as fixtures
# ("password: 'test-password'"). Those aren't secrets to rotate, so findings
# from the low-confidence generic_secret heuristic are downgraded (not
# dropped -- a real leaked credential pasted into a test is still worth
# seeing, just not at critical priority) when the file lives under a test
# path. Format-specific detectors (AWS keys, PATs, JWTs, ...) stay at full
# severity everywhere: they're precise enough that a match in a test file is
# still worth flagging at full severity.
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|specs?|__tests__|__mocks__)(?:/|$)|\.(?:test|spec)\.[jt]sx?$",
    re.IGNORECASE,
)



def is_ignored_path(rel_path: str, patterns: list[str] | None = None) -> bool:
    """True when a repo-relative path matches the configured ignore list.

    Entries ending in "/" match a directory name anywhere in the path; other
    entries are globs matched against the filename.
    """
    patterns = settings.SCAN_IGNORE_PATHS if patterns is None else patterns
    parts = rel_path.replace("\\", "/").split("/")
    dirs, name = parts[:-1], parts[-1]
    for pat in patterns:
        if pat.endswith("/"):
            if pat.rstrip("/") in dirs:
                return True
        elif fnmatch.fnmatch(name, pat):
            return True
    return False


def _is_placeholder(value: str) -> bool:
    """Obvious placeholder values ("changeme", "test-password", "xxxxxxxx", ...)."""
    words = settings.SCAN_PLACEHOLDER_VALUES
    if not words:
        return False
    alt = "|".join(re.escape(w) for w in words)
    return bool(re.search(rf"(?:^|[^a-z])(?:{alt})", value.lower()))


_INSECURE_FUNCS = {
    "python": [
        (r"\beval\s*\(", "use of eval()"),
        (r"\bexec\s*\(", "use of exec()"),
        (r"pickle\.loads?\s*\(", "insecure deserialization via pickle"),
        (r"\bos\.system\s*\(", "use of os.system()"),
        (r"\bos\.popen\s*\(", "use of os.popen()"),
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

# Fix guidance keyed by finding type (falls back to a generic message).
_RECOMMENDATIONS = {
    "secret": "Remove the hardcoded credential, rotate it immediately, and load it "
    "from an environment variable or secret manager.",
    "insecure_fn": "Replace the dangerous call with a safe alternative "
    "(e.g. subprocess with a list argv and shell=False, json/yaml.safe_load, "
    "hashlib.sha256) and validate all inputs.",
    "owasp": "Use parameterised queries / an ORM, enforce HTTPS, and restrict "
    "CORS to an explicit origin allowlist.",
    "dependency": "Upgrade the affected package to the fixed version and "
    "regenerate the SBOM.",
    "debt": "Schedule refactoring for this hotspot and break the file into "
    "smaller, tested units.",
}


@dataclass
class Finding:
    type: str
    title: str
    file_path: str
    line: int
    severity: str
    snippet: str = ""
    description: str = ""
    recommendation: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.description:
            self.description = self.title
        if not self.recommendation:
            self.recommendation = _RECOMMENDATIONS.get(
                self.type, "Review this finding and remediate per your secure-coding standard."
            )

    def as_dict(self) -> dict:
        d = asdict(self)
        d["code_snippet"] = d["snippet"]  # spec alias
        return d


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
        if is_ignored_path(rel):
            continue
        is_test_file = bool(_TEST_PATH_RE.search(rel))
        lines = text.splitlines()
        debt_hits = 0

        for i, line in enumerate(lines, start=1):
            for name, pat in _SECRET_PATTERNS.items():
                for m in re.finditer(pat, line):
                    value = m.group(1) if m.groups() else m.group(0)
                    if _is_placeholder(value):
                        continue
                    entropy = _shannon_entropy(value)
                    if name == "generic_secret":
                        if is_test_file:
                            severity = "low"
                        else:
                            severity = "high" if entropy > 3.5 else "medium"
                    else:
                        # Format-specific detectors (AWS keys, PATs, JWTs, ...)
                        # match a precise shape, so they stay critical
                        # regardless of location or entropy.
                        severity = "critical"
                    findings.append(
                        Finding(
                            type="secret",
                            title=f"Hardcoded secret ({name})",
                            file_path=rel,
                            line=i,
                            severity=severity,
                            snippet=_redact(line),
                            metadata={"detector": name, "entropy": round(entropy, 2), "test_file": is_test_file},
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


def scan_github_repo(
    repo_url: str, *, token: str | None = None, include_dependencies: bool = True
) -> dict:
    """Clone a GitHub repo to a temp dir, scan it, and return findings + heatmap."""
    import tempfile

    from core.services.security_debt.heatmap_engine import heatmap_builder
    from core.utils.github import download_repo, parse_repo_url

    repo = parse_repo_url(repo_url)
    with tempfile.TemporaryDirectory(prefix="cg-debt-") as tmp:
        scan_root = download_repo(repo, token, Path(tmp))
        findings = [f.as_dict() for f in scan_path(scan_root)]
        if include_dependencies:
            findings += [f.as_dict() for f in scan_dependencies(scan_root)]

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "repo": repo,
        "total_findings": len(findings),
        "by_severity": by_sev,
        "findings": findings,
        "heatmap": heatmap_builder.build(findings),
    }


def scan_dependencies(root: str | Path) -> list[Finding]:
    """Bridge to the supply-chain dependency scanner for a unified debt view."""
    from core.services.supply_chain import dependency_scanner

    out: list[Finding] = []
    for vuln in dependency_scanner.scan_path(root):
        if is_ignored_path(vuln.get("manifest", "")):
            continue
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
