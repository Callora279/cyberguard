# Module: Machine Identity

**Package:** `core/services/machine_identity`

Manages non-human identities: API keys, service accounts, certificates, OAuth
tokens, SSH keys.

| File | Responsibility |
|---|---|
| `identity_registry.py` | register/track identities, lifecycle + expiry sweep (`check_expiries`), revoke, record use; seeds identity DNA on registration |
| `credential_rotation.py` | zero-downtime rotation (new secret + grace window), `rotate_due()` for stale credentials, JSONL rotation history, failed-rotation alerts |
| `behaviour_monitor.py` | per-identity baseline of IPs/geos/hours/resources/actions; flags new IP, new geography, off-hours, privilege escalation, unseen resource |
| `zero_trust.py` | `AccessRequest` → `AccessDecision` (allow / step-up / deny) from least-privilege, behaviour, identity-DNA, device posture and auth freshness/MFA |
| `identity_dna/dna_generator.py` | stable trait strand (type, scope shape, automation class, issuance epoch) + evolving behaviour vector (EWMA) |
| `identity_dna/dna_store.py` | Redis / file persistence |
| `identity_dna/dna_analyzer.py` | vector-distance + live-signal checks → compromise score & verdict (healthy / suspicious / compromised) |

**Endpoints:** `/api/machine-identity/registry`, `/register`, `/rotate`, `/rotate-due`, `/alerts`, `/history`, `/access-request`, `/{id}/dna`.
