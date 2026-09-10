# Module: Security Debt

**Package:** `core/services/security_debt`

| File | Responsibility |
|---|---|
| `scanner.py` | walk a code tree for hardcoded secrets (regex + Shannon entropy), insecure functions (`eval`, `pickle`, `md5`, `shell=True`, `verify=False`…), OWASP patterns (SQLi concat, wildcard CORS, cleartext transport), technical-debt hotspots (TODO/FIXME density, oversized files). `scan_dependencies()` bridges to the supply-chain scanner |
| `prioritizer.py` | score each finding by severity, exploitability, business impact and fix effort → ranked remediation backlog; `module_score()` |
| `remediation_assistant.py` | AI fix suggestions (`guarded_chat`) with a deterministic playbook fallback; `create_jira_tickets()` via the Jira agent |
| `reporting.py` | `run_scan()` persists findings to `security_findings`, raises alerts on criticals, produces the summary |
| `heatmap_engine/heatmap_builder.py` | per-file and per-directory risk aggregation, colour bucketing |
| `heatmap_engine/heatmap_visualizer.py` | standalone HTML grid + ASCII heatmap |

**Endpoints:** `GET/POST /api/security-debt/scan`, `/heatmap`, `/remediation`.
