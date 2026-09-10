# CyberGuard AI — API Specification

Base URL: `http://localhost:8090`  ·  Interactive docs: `/docs`

All `/api/*` routes except auth + health require `Authorization: Bearer <jwt>`.
Rate limit: 120 req/min per token/IP (configurable).

## Auth

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/auth/register` | `{email, password, org_name}` | creates org + admin, returns token |
| POST | `/api/auth/login` | `{email, password}` | returns `{access_token, org_id, role}` |
| GET | `/api/health` | — | liveness + dependency checks |

## AI Governance — `/api/ai-governance`

| Method | Path | Purpose |
|---|---|---|
| GET | `/status` | enforcement state + active policy + 30d usage |
| POST | `/policy` | define/replace the org AI usage policy (admin) |
| GET | `/audit-log` | AI interaction audit trail + human review queue |
| GET | `/audit-log/{id}/explain` | explainability report for one decision |
| GET | `/compliance-export?fmt=json\|csv` | evidence export (admin) |
| GET | `/fingerprints` | current behavioural fingerprint + drift |
| POST | `/proxy-chat` | run a prompt through the real-time enforcer |

## Security Debt — `/api/security-debt`

| GET `/scan` | latest scan summary |
| POST `/scan` `{path?, include_dependencies?}` | run a scan |
| GET `/heatmap?fmt=json\|html\|ascii` | codebase risk heatmap |
| GET `/remediation?use_ai=true` | AI fix suggestions for the top backlog |
| POST `/remediation/jira` | create Jira tickets for the top findings |

## Supply Chain — `/api/supply-chain`

| POST `/scan` `{path?}` | dependency + CVE scan (OSV) |
| GET `/sbom` | stored CycloneDX SBOM |
| POST `/sbom/parse` `{raw}` | parse SPDX/CycloneDX + NHS compliance check |
| GET `/vendors` | vendor/dependency risk matrix |
| POST `/generate-sbom` `{path?, use_ai?}` | AI-assisted SBOM generation |

## Machine Identity — `/api/machine-identity`

| GET `/registry` | all machine identities |
| POST `/register` `{identity_type, name, owner?, scopes?, secret_material?, expires_at?}` |
| POST `/rotate` `{identity_id, grace_period_hours?, dry_run?}` |
| POST `/rotate-due` | rotate all stale/expiring credentials |
| GET `/alerts` | expiry sweep + anomaly alerts |
| GET `/history?identity_id=` | rotation history |
| POST `/access-request` `{identity_id, resource, action, ip?, geo?, mfa_present?, …}` | zero-trust decision |
| GET `/{identity_id}/dna` | identity-DNA compromise analysis |

## Fraud Detection — `/api/fraud-detection`

| POST `/analyze` `{identity?, transaction?, invoice?, document?, context?, history?}` | fusion assessment |
| GET `/alerts?status=` | fraud alert feed + pattern timeline |
| PUT `/alerts/{id}` `{status}` | update investigation status |
| GET `/risk-score` | module score + open alert count |

## Unified / Predictive Risk — `/api/risk-score`

| GET `/current?recalculate=true` | unified score + grade + breakdown |
| GET `/dashboard` | score + trend + alerts + recommendations |
| GET `/history?days=30` | historical series + OLS trend + anomaly |
| GET `/forecast?horizon_days=30` | incident probability + 30/60/90d outlook |

## Cyber Twin — `/api/cyber-twin`

| POST `/build` `{path?, name?}` | build the digital twin |
| POST `/simulate` `{attacks?, scenario?}` | run attack simulations |
| GET `/scenarios?scenario_id=` | scenario library (OWASP/MITRE/NHS) |

## Alerts — `/api`

| GET `/alerts?module=&severity=&acknowledged=` | unified alert feed |
| PUT `/alerts/{id}/acknowledge` | acknowledge an alert |

## Internal (Chakra)

| GET `/internal/health-score?chakra_org_id=…` header `X-Sync-Secret` | security score for Chakra Intelligence |
