# CyberGuard AI — Threat Model

## Assets

| Asset | Sensitivity |
|---|---|
| AI prompts / responses (may contain PII, secrets, IP) | High |
| Machine identity secret material + fingerprints | Critical |
| Security findings (unpatched vulns, exposed secrets) | Critical |
| Unified risk scores + Chakra sync | Medium |
| JWT signing secret, Groq API key, GitHub token | Critical |

## Trust boundaries

1. Internet → FastAPI (`/api/*`) — JWT + rate limit + CORS.
2. Chakra → `/internal/health-score` — shared `X-Sync-Secret` only.
3. FastAPI → Groq — outbound TLS, API key in `Authorization`.
4. Agents (GitHub/GitLab webhooks) → platform — signature verification expected
   at the ingress/webhook handler (add HMAC check per provider before prod).
5. Worker → DB/Redis — private network.

## STRIDE highlights

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | forged Chakra sync | constant-time secret compare; rotate secret; IP allow-list at ingress |
| **Tampering** | malicious dependency update | supply-chain scan + SBOM diff on every push; lockfile pinning guidance |
| **Repudiation** | disputed AI decision | full `ai_interactions` audit trail + explainability + compliance export |
| **Information disclosure** | secret in an AI prompt | policy engine `data_classification_rules` blocks `secret`/`pii` patterns pre-call |
| **Information disclosure** | prompt hashes only stored, previews truncated to 500 chars |
| **DoS** | prompt flooding / cost blow-up | rate limit + per-day cost alert (AI-usage agent) + `max_tokens` policy cap |
| **Elevation of privilege** | machine identity requests admin scope | zero-trust engine denies `requested > granted`; DNA analyzer flags read-only→write |
| **Prompt injection** | "ignore previous instructions…" | `risk_scoring` + `policy_engine.prohibited_patterns`; interactions >50 to review queue |

## Residual risks / TODO before production

- Webhook signature verification for GitHub/GitLab is stubbed — enforce HMAC.
- JWT is HS256 with a single secret — move to rotating keys / OIDC.
- Secret material returned by `rotate()` is passed back to the caller — wire to
  a real secret manager (Vault / cloud KMS) and never return plaintext.
- `simulation_engine` reasons over the twin graph only; add opt-in active
  testing with explicit scoping + rate control.
- No row-level tenancy enforcement in the DB — every query filters by `org_id`
  in code; add Postgres RLS.
