# HardenForge — Architecture & Threat Model (v0.1 read-only MVP)

## Layers
```
CLI / FastAPI (token auth) ──► engine (load_rules, run_audit) ──► checks registry ──► OS (read-only)
                          └──► scoring
                          └──► ai.manager (consent gate → redact → adapter → retries/fallback → usage)
secrets.SecretStore (env > Fernet file; master key external)
```
Deterministic results come only from `engine`/`checks`. The AI layer returns advisory text and has no path
into outcomes, rules, or execution.

## Key decisions
- Declarative YAML rules, strict pydantic schema (`extra=forbid`), `yaml.safe_load`, size cap, duplicate-ID and unknown-check-type rejection.
- Only `status: approved` rules run. Drafts (incl. `ai_draft`) report NOT_CHECKED.
- Any check exception → ERROR. ERROR is never PASS and is excluded from the score numerator.
- Paths resolve inside an audit root (traversal → ERROR). `command_output` takes an argv list, no shell, basename allowlist of read-only binaries, minimal env, timeout.
- Evidence is stored with a SHA-256 for integrity comparison.
- Rule IDs, provenance kind (official/community/ai_draft), source, version and original control_ref are kept on every result.

## Threats and mitigations (implemented unless noted)
| Threat | Mitigation | Test |
|---|---|---|
| Malicious rule package executes code | safe_load, schema, no shell, allowlist | test_loader_rejects_bad_rules, test_command_allowlist_and_injection |
| Path traversal via rule | root-confined resolve | test_path_traversal_is_error_not_pass |
| API key leakage | env/Fernet store, masked API, redacted errors, header (not URL) auth to Gemini | test_store_roundtrip…, test_auth_error_not_retried… |
| Data exfiltration to AI | per-category consent gate + redaction | test_consent_required, test_redaction_before_send… |
| Prompt injection via evidence | evidence wrapped as untrusted, advisory-only output, no execution path | structural (no code path); add adversarial corpus tests next |
| Unauthenticated API | bearer token, refuses to start without one | test_api_* |
| Cost runaway | request cap, estimated-cost cap | partially tested |
| **Not yet implemented** | TLS termination, user/role auth, audit-log persistence, rule signing, remediation approval/rollback | — |

## Not implemented yet
Remediation/apply/rollback, DB + migrations, benchmark importers (CIS/MS/NIST), rule signing, Windows and macOS
adapters (schema allows them; no checks written), React/TypeScript dashboard, PDF/HTML/CSV reports, provider model
validation endpoints, SELinux/AppArmor/PAM/package checks, rule versioning/diff UI.

## Next stages (from the spec)
1. Persistence (SQLAlchemy + Alembic), audit log, endpoint inventory.
2. Windows checks (registry, secedit/PowerShell read-only cmdlets) and macOS (defaults, csrutil, fdesetup) with VM fixtures.
3. Benchmark ingestion with version diffing; CIS content only from files the user is licensed to use.
4. Dry-run planner → approval → snapshot → apply → verify → rollback, with lockout guards.
5. Dashboard (React + TS), reports.
