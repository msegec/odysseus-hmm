# Todo List

Rules:
- Agent reads this before each turn.
- Agent updates this before end each turn.
- Keep under 8000 tokens.
- Keep bullets factual, current, short.

## Done

- Created `docs/security-telemetry-visual-concepts.html` as a standalone visual concept artifact for passive safety telemetry.
- Audited docs folder + recent docs against repo evidence.
- Added `docs/CODE_QUALITY_AUDIT.md`.
- Added `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`.
- Pushed docs commit to fork `msegec/odysseus-hmm`:
  `ec5e994 Document Current Audit Findings`.
- Created `fork` remote for user repo.
- Created `AGENT.MD` guide.
- Created this `todolist.md`.
- Reviewed security audit for intended-use fit.
- Marked AUDIT-001 through AUDIT-005 as genuine security boundary risks.
- Moved AUDIT-006 into non-security reliability hardening.
- Reframed next work for single-user personal-agent deployment behind SSL proxy/VPN.
- Decided not to bluntly change XSS/API/SSRF/tool behavior before validating intended functionality.
- Designed passive safety telemetry / risk recorder concept for real-world use.
- Added Provenance Deep-Dive (Concept 3) + Continual Improvement Ledger (Concept 6) to `docs/security-telemetry-visual-concepts.html`; reframed intent/footer around continual improvement + priority order.
- Added Continual Improvement Loop + priority order to `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`.
- Added Continual Improvement Linkage to `docs/CODE_QUALITY_AUDIT.md` (traceable, preserve feature, regression test, priority order).
- Added priority order + improvement loop to `AGENT.MD`.
- Verified AUDIT-001..005 against live code; all 5 confirmed real. Added "Finding Verification and Use-Case Fit" section to `docs/CODE_QUALITY_AUDIT.md` with quantified single-user vs multi-user risk + fix-clash verdict + file:line evidence. Marked the 5 statuses "Open (verified 2026-06-01)".
- Corrected AUDIT-004 fix to authz-only, NO URL filtering: add `require_admin` to set/clear/download/delete embedding handlers. Verified non-breaking — embedding UI is already admin-only (`admin.js`), agent `download_model` uses a separate HF path (`tool_implementations.py:2857`), `require_admin` bypasses for agent internal-tool loopback + localhost. Cloud/local/proxy endpoints stay fully usable (OpenAI/Ollama/vllm/codex/opencode proxy). Also closes part of AUDIT-005 token-reach.
- Added governing constraint to audit doc: harden without breaking ANY feature. Where enforcement could break unknown integrations (AUDIT-005), gate behind observe-first telemetry (log real usage -> derive allowlist -> enforce).
- Confirmed all 5 P0 fixes are non-breaking for intended use: 003 owner_filter is a no-op in single-user (user="") and keeps shared (NULL-owner) endpoints; 002 single-user owner="" passes the gate; 001 keeps report features if scripts move to nonce/external; 004 authz-only; 005 observe-first.

- Hardened Product Goals into measurable G1-G4 (privacy/sovereignty, safe-for-non-experts, reproducible install, accessibility) in `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`; binary + numeric bars; meta-gate = security-first.
- Recorded G1 decision: features-by-default, hardening-by-choice (not private-by-default).
- Designed G1 feature "Privacy & Egress Control" (KISS, OPNsense-style config-history + revert, first-run opt-out, admin-gated). Spec: `docs/superpowers/specs/2026-06-01-privacy-egress-control-design.md`.
- Purged URL/SSRF-filter language to match authz-only AUDIT-004 verdict: `AGENT.MD` (priority order, prefer-list, embeddings line) + AUDIT-004 Impact note now say authz-only, SSRF = accepted residual risk.
- Added security-first reconcile note to `ROADMAP.md` header.

## Doing

- No active task.

## Next

- Priority order for all work: 1) security, 2) new/improved features, 3) maintainability + UX QA/QC.
- Verified `docs/security-telemetry-visual-concepts.html` aligns with `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`: 5-stage loop (observe→decide→codify→verify→preserve), priority order, provenance schema, local-only, observe-only/report-first all match. No doc reconcile needed.
- Built passive safety telemetry — Observe stage (no behavior change), TDD, 14/14 pure-stdlib tests green (`python tests/test_security_telemetry.py`; env has no pytest/sqlalchemy so kept stdlib-only + decoupled):
  - DONE 1. `src/security_telemetry.py`: `record_security_event(...)` + `record_verdict(...)` + `read_events()` + `summary()`. Append-only JSONL under `data/security_telemetry/` (gitignored, verified via `git check-ignore` ✓ — local-only by construction). Provenance per row: raw signals, rule + rule_version, confidence, code_refs, inputs_hash, local ts. Best-effort: never raises into caller path.
  - DONE 4. Provenance is in the schema (replayable inputs_hash + rule_version travels with each event).
  - DONE 3. `src/security_classifiers.py` `scan_report_html(...)`: script/event-handler/`javascript:`/iframe/form/object signals → needs_decision (observe-only, never auto-block), code_ref AUDIT-001.
  - DONE 4(net). `classify_network_target(...)`: loopback/private-LAN/docker → expected; link-local metadata → dangerous (AUDIT-004); public → needs_decision; junk → unknown. No DNS resolve.
  - DONE 7. `routes/security_telemetry_routes.py`: admin-gated (`require_admin`, bearer "api" rejected) READ-ONLY `/api/security/telemetry/summary` + `/events?classification&limit`. Wired in `app.py`.
  - DONE 5(partial). One passive instrumentation point: embedding `set_endpoint` (the AUDIT-004 SSRF surface from Concept 3) records the target verdict before its health-check POST. Observe-only; does NOT add the authz fix (that enforcement is the separately-decided later stage).
- NEXT telemetry steps (still observe-only, no enforcement):
  2. Log API-token route access (scopes, method, route, mutation hint) — middleware hook at `app.py:245` where `current_user="api"` is stamped.
  5. More instrumentation: agent/tool shell+file+network actions, research web-fetch, SearXNG, other model endpoints.
  6. Read-only container posture report: UID/GID, mounts, Docker socket, caps, writable host paths, sensitive env.
  8. Provenance deep-dive view (frontend): replay trigger→instrumentation→signals→classifier→code refs→suggested fix.
  9. Improvement ledger: link trace→decision→regression test; track loop stage.
  - Frontend: build the admin dashboard page that consumes `/api/security/telemetry/*` (mockup = the concept HTML).
- After telemetry shows real usage, decide whether to enforce guardrails for XSS/API/SSRF/tool permissions. Each enforced change must preserve the feature and land a regression test.
- Build G1 "Privacy & Egress Control" feature AFTER telemetry (it consumes telemetry's egress observations). Per spec: egress profile, first-run opt-out, settings CRUD, OPNsense-style config-history+revert (local-only, never git), harden brief. Admin-gated; one regression test per chokepoint category + revert-equality test.
- Add static smoke tests for PWA icons, duplicate module URL, `/backgrounds`.
- Add integration/plugin docs: `docs/EXTENSIONS.md`.
- Never commit telemetry logs to git and ensure they are only ever stored locally for dev purposes.
- Commit and push `AGENT.MD`, `todolist.md`, and audit review changes if user wants.

## Blockers

- Active Python lacks `pytest`; full test suite cannot run until dev env installed.
