# Module: AI Governance

**Package:** `core/services/ai_governance`

Governs every AI call made anywhere in CyberGuard. `core.utils.ai_client.chat`
emits an `AICallRecord`; `monitor.install()` registers an observer so each call
is persisted, risk-scored, anomaly-checked and (on violation) alerted.

| File | Responsibility |
|---|---|
| `monitor.py` | persist `ai_interactions`, rolling-window anomaly detection (token/latency spikes), token + cost roll-ups, raise alerts |
| `audit.py` | audit-log queries, human **review queue**, `explain()` (LLM explainability), `compliance_export()` (JSON/CSV evidence) |
| `policy_engine.py` | resolve org policy (max tokens, allowed models, prohibited regex, data-classification rules); `evaluate()` → allow / flag / block |
| `risk_scoring.py` | 0–100 score from prompt-injection, data-exfiltration, bias, hallucination sub-scores |
| `real_time_enforcer.py` | `guarded_chat()` — evaluate policy → call → fingerprint check; blocked attempts still audited |
| `ai_behavior_fingerprinting/fingerprint_generator.py` | build a statistical profile of normal usage (tokens, latency, cost, model mix, active hours) |
| `ai_behavior_fingerprinting/fingerprint_store.py` | Redis or file-backed persistence + history |
| `ai_behavior_fingerprinting/fingerprint_analyzer.py` | z-score anomaly check vs baseline; `drift_report()` between fingerprints |

**Module score:** `100 − (avg_risk·0.6 + block_rate·40)`.
