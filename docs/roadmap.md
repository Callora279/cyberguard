# CyberGuard AI — Roadmap

## Status: v0.1.0 (scaffold + working core)

All eight modules, the API, agents, web + mobile clients, infra and a passing
test suite (unit / integration / e2e) are in place. Services are functional
against SQLite + optional Redis; AI features call Groq live.

## Near term (v0.2)

- [ ] Webhook signature verification (GitHub `X-Hub-Signature-256`, GitLab token)
- [ ] Postgres row-level security per `org_id`
- [ ] Real secret-manager integration for `credential_rotation`
- [ ] NVD + GitHub Advisory enrichment alongside OSV
- [ ] Persist Cyber Twin runs; twin diffing between builds
- [ ] Alembic migrations (replace `create_all`)
- [ ] Web auth guard + login redirect; SSR data fetching

## Mid term (v0.3–0.4)

- [ ] Replace heuristic `score_model` OLS with a trained gradient-boosted model
- [ ] Deepfake detector: wire an image/PDF forensic model (ELA, PRNU, C2PA)
- [ ] Fingerprint store → time-series DB; per-user (not just per-org) baselines
- [ ] Fraud fusion: graph store for ring detection across entities
- [ ] Multi-model AI routing + per-model policy
- [ ] Human review UI with SLA + escalation

## Long term

- [ ] Marketplace of Cyber Twin attack scenarios
- [ ] Continuous compliance mapping (SOC 2, ISO 27001, DSPT, NIS2)
- [ ] Autonomous remediation PRs via the GitHub agent
- [ ] On-prem / air-gapped deployment with a local model
