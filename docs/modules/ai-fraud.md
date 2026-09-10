# Module: AI Fraud Detection

**Package:** `core/services/ai_fraud_detection`

| File | Responsibility |
|---|---|
| `deepfake_detector.py` | LLM-generated document detection (AI phrase markers, burstiness, lexical repetition, optional LLM adjudication); document-metadata tampering signals; combined invoice-document risk |
| `invoice_anomaly.py` | anomalous invoices — unusual amount vs vendor baseline, new vendor, duplicates, round-number patterns, weekend/quarter-end timing, line-item math mismatch, changed IBAN |
| `synthetic_identity.py` | synthetic identities — disposable/role email, low-entropy phone, placeholder address, name/email inconsistency, implausible age, transact-on-signup |
| `fraud_risk_scoring.py` | combined score: transaction 30% · identity 25% · document 25% · behavioural 20%; persists `fraud_alerts`; `module_score()` |
| `fusion_engine/fusion_analyzer.py` | fuse all detectors; amplify when ≥2–3 fire independently; apply correlator boost → allow / review / block |
| `fusion_engine/fusion_correlator.py` | link a case to recent alerts: same subject, 24h burst, shared IP/IBAN (ring detection); `pattern_timeline()` |

**Endpoints:** `POST /api/fraud-detection/analyze`, `GET /alerts`, `PUT /alerts/{id}`, `GET /risk-score`.
