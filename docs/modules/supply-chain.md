# Module: Supply Chain

**Package:** `core/services/supply_chain`

| File | Responsibility |
|---|---|
| `dependency_scanner.py` | parse `requirements.txt`, `package.json`, `Gemfile`, `pom.xml`, `go.mod`; query **OSV.dev** per component; return CVEs with CVSS, severity, fixed version, patch-available |
| `sbom_parser.py` | parse SPDX (tag + JSON) and CycloneDX (JSON + XML); `validate_completeness()` (NTIA minimum elements); `nhs_compliance_check()` |
| `vendor_risk.py` | score each dependency: maintenance (last push / archived), security history (CVE count + max CVSS), license risk (copyleft vs permissive), community health (GitHub stars/issues) |
| `alerts.py` | `run_scan()` aggregates per component, persists `sbom_components`, raises alerts on high/critical CVEs; `module_score()` |
| `ai_generated_sbom/sbom_generator.py` | deterministic manifest parse + AI pass to catch non-manifest components (base images, system packages, model artifacts) → CycloneDX 1.5 |
| `ai_generated_sbom/sbom_updater.py` | keep the stored SBOM in sync per commit; `diff()` added/removed/changed components |

**Endpoints:** `POST /api/supply-chain/scan`, `GET /sbom`, `GET /vendors`, `POST /generate-sbom`, `POST /sbom/parse`.
