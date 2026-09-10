# 🛡️ CyberGuard AI

Unified AI-era cyber-risk platform. Eight capability modules behind one risk
score, grade and forecast.

| Module | What it does |
|---|---|
| **AI Governance** | monitors every AI call, scores it (injection / exfiltration / bias / hallucination), enforces usage policy in real time, fingerprints normal behaviour |
| **Security Debt** | scans code for secrets, insecure functions, OWASP issues and debt hotspots; prioritised backlog + AI fixes + risk heatmap |
| **Supply Chain** | dependency + CVE scan (OSV), SPDX/CycloneDX SBOM parsing + NHS compliance, vendor risk, AI-generated SBOM |
| **Machine Identity** | registry + lifecycle for keys/certs/tokens, zero-downtime rotation, behaviour baselining, zero-trust access decisions, identity "DNA" |
| **AI Fraud Detection** | deepfake/AI-document detection, invoice anomalies, synthetic identities, fused fraud score + cross-time correlation |
| **Unified Risk Score** | weighted 0–100 score (20% × 5 pillars) with A+…F grade, trend model, dashboard |
| **Predictive Risk** | incident probability by vector, 30/60/90-day forecast, CISA-KEV threat landscape |
| **Cyber Twin** | digital replica of endpoints/auth/data stores; safe attack simulation (OWASP / MITRE / NHS scenarios) |

## Tech stack

Python 3.12 · FastAPI · SQLAlchemy (PostgreSQL / SQLite) · Redis · Celery ·
Groq (`qwen/qwen3.8-27b`) · Next.js 14 · Flutter · Docker Compose.

## Quick start (local, no infra)

```bash
cd ~/projects/cyberguard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env                 # then edit .env and add your GROQ_API_KEY etc.
python -m core.database.seed         # creates SQLite db + demo org/user/policy
uvicorn core.api.main:app --reload --port 8090
```

- API docs: http://localhost:8090/docs
- Demo login: `admin@cyberguard.ai` / `cyberguard-demo`

### Web

```bash
cd frontend/web && npm install && npm run dev   # http://localhost:3000
```

### Mobile

```bash
cd frontend/mobile && flutter pub get
flutter run --dart-define=API_BASE=http://10.0.2.2:8090
```

### Everything in Docker

```bash
cd infra/docker && GROQ_API_KEY=... docker compose up --build
# api :8090  ·  web :3000  ·  postgres :5432  ·  redis :6379  ·  celery worker
```

## Tests

```bash
pytest -q            # 25 tests: unit + integration (TestClient) + e2e flow
```

## Layout

```
core/        api (routes + middleware), services (8 modules), database, utils, workers
agents/      github · gitlab · jira · slack · ai_usage
frontend/    web (Next.js) · mobile (Flutter)
infra/       docker · k8s · terraform
tests/       unit · integration · e2e
docs/        architecture · api-spec · threat-model · roadmap · modules/
```

## Integrations

- **Chakra**: `GET /internal/health-score?chakra_org_id=…` with `X-Sync-Secret`.
- **LiveGuard**: unhandled 5xx errors forwarded to `LIVEGUARD_URL`.
- **Groq**: all AI via `core.utils.ai_client` → AI Governance enforcer.

See `docs/` for full detail.
