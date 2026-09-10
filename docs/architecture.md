# CyberGuard AI — Architecture

## Overview

CyberGuard AI is a unified platform for **AI-era cyber risk**. It brings eight
capability areas under one risk score:

1. AI Governance
2. Security Debt
3. Supply Chain
4. Machine Identity
5. AI Fraud Detection
6. Unified Risk Score
7. Predictive Risk
8. Cyber Twin

## Runtime components

```
                    ┌────────────┐        ┌──────────────┐
 Next.js web  ────▶ │            │  ────▶ │ PostgreSQL    │
 Flutter app  ────▶ │  FastAPI   │        └──────────────┘
 Agents       ────▶ │  :8090     │  ────▶ ┌──────────────┐
 Chakra       ────▶ │            │        │ Redis         │◀── Celery worker + beat
                    └─────┬──────┘        └──────────────┘
                          │
                          ▼
                    Groq API (qwen/qwen3.8-27b)  — every call via
                    core.utils.ai_client → AI Governance enforcer
```

- **`core/api`** — FastAPI app, routers, middleware (logging, JWT auth, rate limit).
- **`core/services`** — one package per capability area; pure Python, no web deps.
- **`core/database`** — SQLAlchemy 2.0 models + engine; SQLite dev, PostgreSQL prod.
- **`core/workers`** — Celery app, scheduled sweeps, background scans.
- **`core/utils`** — config, logging (+ LiveGuard forwarding), crypto/JWT, the
  governed `ai_client`, timezone helpers, exception hierarchy.
- **`agents/`** — GitHub, GitLab, Jira, Slack, and AI-usage integration agents.

## Key design decisions

| Decision | Rationale |
|---|---|
| All AI calls funnel through `core.utils.ai_client.chat` | single choke point for governance: monitoring, risk scoring, policy, fingerprinting |
| `real_time_enforcer.guarded_chat` is the public API for AI | policy is evaluated *before* the call; blocked attempts are still audited |
| Every module exposes a `module_score()` 0–100 | the unified score is a weighted mean (20% each of 5 pillars) |
| Redis optional, file fallback everywhere | works on a laptop with zero infra |
| Minimal HS256 JWT in `core.utils.crypto` | no heavy auth dependency; swap for OIDC in prod |
| SQLite returns naive datetimes | `core.utils.timeutil.as_aware` normalises comparisons |

## Data flow: a security-debt scan

1. `POST /api/security-debt/scan` → `services.security_debt.reporting.run_scan`
2. `scanner.scan_path` walks the tree (secrets, insecure funcs, OWASP, debt)
3. `scanner.scan_dependencies` bridges to `supply_chain.dependency_scanner` (OSV)
4. `prioritizer.backlog` scores + ranks; rows persisted to `security_findings`
5. critical findings raise an `alerts` row
6. `heatmap_engine` builds the per-file/dir risk heatmap on demand
7. `unified_risk_score.score_calculator` folds the module score into the posture

## Integrations

- **Chakra** — `GET /internal/health-score?chakra_org_id=…` guarded by
  `X-Sync-Secret`; returns the unified score + breakdown.
- **LiveGuard** — unhandled 5xx errors are POSTed to `LIVEGUARD_URL`.
- **Groq** — OpenAI-compatible chat completions, model `qwen/qwen3.8-27b`.
