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

## Doing

- No active task.

## Next

- Priority order for all work: 1) security, 2) new/improved features, 3) maintainability + UX QA/QC.
- Build passive safety telemetry / risk recorder first, with no behavior changes:
  1. Add central `security_events` storage and `record_security_event(...)` helper. Schema must carry provenance: raw signals, classifier rule + rule version, confidence, code refs, local timestamp.
  2. Log API-token route access with scopes, method, route, mutation hint, and token-aware status.
  3. Add generated report/content risk scanner for scripts, event handlers, iframes, forms, `javascript:` URLs, raw HTML, and permissive CSP.
  4. Add network target classifier for public, localhost, Docker, LAN/private, VPN/private, link-local, metadata IP, configured trusted service.
  5. Instrument agent/tool actions: shell commands, file reads/writes, network targets, source context, confirmation state if available.
  6. Add read-only container posture report: UID/GID, mounts, Docker socket, capabilities, writable host paths, sensitive env exposure.
  7. Add JSON or simple admin report showing expected, needs-decision, dangerous, unknown, and no-evidence-found events.
  8. Add provenance deep-dive view: replay trigger -> instrumentation -> signals -> classifier -> code refs -> suggested fix per event.
  9. Add improvement ledger: link each trace to its decision and the regression test that locks the fix; track loop stage (observe/decide/codify/verify/preserve).
- After telemetry shows real usage, decide whether to enforce guardrails for XSS/API/SSRF/tool permissions. Each enforced change must preserve the feature and land a regression test.
- Add static smoke tests for PWA icons, duplicate module URL, `/backgrounds`.
- Add integration/plugin docs: `docs/EXTENSIONS.md`.
- Never commit telemetry logs to git and ensure they are only ever stored locally for dev purposes.
- Commit and push `AGENT.MD`, `todolist.md`, and audit review changes if user wants.

## Blockers

- Active Python lacks `pytest`; full test suite cannot run until dev env installed.
