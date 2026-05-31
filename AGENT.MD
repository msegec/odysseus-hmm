# Agent Guide

Style: caveman concise. Keep truth. No fluff. Exact paths/errors.

Before each turn:
- Read `AGENT.MD`.
- Read `todolist.md`.
- Check `git status -sb`.
- Protect user work. Never revert unknown changes.

Before end each turn:
- Update `todolist.md`: done, doing, next, blockers.
- Keep `todolist.md` under 8000 tokens.
- Say tests run or why not.

Repo state:
- Upstream source: `pewdiepie-archdaemon/odysseus`.
- User fork: `https://github.com/msegec/odysseus-hmm`.
- Current local branch: `main`.
- `origin` = upstream. `fork` = user fork.
- Commit style from upstream: short Title Case subject, no `docs:` prefix. Body only for useful context.

Current intent:
- Local-first self-hosted AI workspace.
- Keep powerful tools under user/admin control.
- Prefer reliability, security hardening, integration verification, degraded-state UX, docs.
- Do not add big feature before P0 security/auth boundaries fixed.

Priority order (every round, top first):
1. Security: ownership, scopes, sanitization, SSRF/allowlists, admin gates.
2. New/improved features: only after that surface's boundary is correct + tested.
3. Maintainability + UX QA/QC: modularity, smaller files, smoke tests, degraded states, a11y, mobile/modal.

Continual improvement loop (per finding): observe (with provenance) -> decide -> codify (small modular unit, safe-by-design) -> verify (regression test) -> preserve (no feature lost without explicit recorded decision). See `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md` and `docs/security-telemetry-visual-concepts.html`.

Docs now added:
- `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`: feature map + direction.
- `docs/CODE_QUALITY_AUDIT.md`: verified risks + fix order.

Security audit rules:
- Security finding must have code evidence, exploit path, affected boundary.
- Do not call UX/reliability issue security risk.
- Do not break intended use if safer gate can preserve it.
- Prefer owner checks, explicit privileges, route scopes, sanitized rendering, allowlists.
- Return 404 for cross-owner private data where useful.
- Keep admin-only for host/runtime/global mutation: shell, MCP, model serving, embedding endpoint/model admin, webhooks, tokens, backup/vault/settings.

Known current security work:
- Research report XSS: sanitize report HTML + stricter report CSP.
- Research spinoff: require result ownership before read/copy.
- Endpoint ids: owner-filter explicit `endpoint_id` lookups before reading API keys.
- Embeddings: admin or explicit privilege for download/delete/custom endpoint; validate URLs against SSRF.
- API tokens: centrally enforce route scopes; do not treat `current_user="api"` as normal browser user.

Known non-security hardening:
- TTS/STT sync work blocks async handlers.
- Duplicate `chat.js` module URL.
- Missing PWA PNG icons.
- Runtime CDN dependency hurts offline/self-hosted mode.
- Upload metadata JSON can lose concurrent writes.
- `/backgrounds` route points to missing file.

Verification facts:
- `npm audit --audit-level=moderate` passed: 0 vulnerabilities.
- Active `/home/MrS/miniconda/bin/python` lacks `pytest`; full pytest not run here.
- `static/icon-192.png`, `static/icon-512.png`, `static/backgrounds.html` missing.
