# Code Quality Audit Tracker

Audit date: 2026-06-01
Source reviewed: `pewdiepie-archdaemon/odysseus` at `051751a` (`main`)
Scope: security issues, user-experience breaking issues, maintainability risks, and obvious next hardening work.

Status legend: `Open`, `In progress`, `Fixed`, `Needs verification`, `Accepted risk`.

## Security Intent Review

The security findings below are meant to preserve intended self-hosted use, not remove core features. Fixes should narrow access to the correct owner, admin, explicit privilege, or token scope.

- Genuine security boundary issues: AUDIT-001 through AUDIT-005. Each crosses same-origin script execution, owner privacy, API-key isolation, global resource/SSRF control, or API-token scope boundaries.
- Non-security hardening: AUDIT-006 through AUDIT-014. These are reliability, UX, maintainability, install, or data-integrity issues unless paired with a separate exploit path.
- Intended-use guardrail: keep owner access working, keep admin/global tools working for admins, keep `/api/v1/chat` API-token use working for scoped tokens, and add explicit privileges where admin-only would be too coarse.

## Verification Notes

- `npm audit --audit-level=moderate`: passed, 0 vulnerabilities.
- `python -m pytest -q`: not run successfully in this shell because the active Python environment has no `pytest` installed.
- `python -m pip list --outdated`: active environment has many outdated packages, but this is the user's global/miniconda environment, not a project venv. Treat as weak signal only.
- Static size signal: `static/style.css` is about 34k lines and 1.1 MB; top frontend modules include `document.js` at about 9.2k lines and `slashCommands.js` at about 5.9k lines.

## Finding Verification and Use-Case Fit (2026-06-01)

Each P0 finding was re-checked against the live code in this working tree. Risk is rated for the **intended deployment** (single user / small trusted group, self-hosted behind VPN or SSL proxy, owner is admin, `AUTH_ENABLED=true`, `LOCALHOST_BYPASS=false`, agentic computer-use). A separate multi-user note is given where it differs. "Clash" = risk that the suggested fix breaks intended functionality if applied bluntly.

**Governing constraint: harden without breaking ANY feature.** A security fix only removes the exploit path, never an intended capability. Concretely: the owner keeps every workflow; the agent keeps every tool (its internal-tool loopback bypasses `require_admin`); cloud/local/proxy endpoints stay reachable (no destination-URL filtering anywhere); shared/legacy (NULL-owner) records stay visible (`owner_filter(include_shared=True)`); and in single-user mode `owner_filter` is a no-op, so those routes are unchanged. Where enforcement *could* break an unknown integration (AUDIT-005), it is gated behind **observe-first telemetry**: log the real usage, derive the allowlist from it, then enforce — so nothing breaks silently. This is exactly what the passive telemetry / decision-matrix layer in `docs/security-telemetry-visual-concepts.html` exists to enable.

| ID | Verified | Single-user risk | Multi-user risk | Fix clash | Fix verdict |
|----|----------|------------------|-----------------|-----------|-------------|
| 001 | Yes | High | High | **High** | Correct, but highest-effort — must preserve report scripts |
| 002 | Yes | Low | Medium | None | Correct, trivial — helper already exists |
| 003 | Yes | Low | Medium | Low | Correct as written |
| 004 | Yes | High | High | None | Authz-only (admin-gate); **no URL filter** — cloud/local/proxy all keep working |
| 005 | Yes | Medium | Medium | Medium | Correct, but needs a scope map first |

### AUDIT-001 — verified, does not clash with intent if done carefully

- Evidence: `src/visual_report.py:46` renders the report body with `markdown.markdown(..., extensions=["extra", "codehilite", "toc", "tables", "sane_lists"])` and no sanitizer, so raw `<script>`/`onerror` in report markdown survives. `core/middleware.py:66-75` serves `/api/research/report/*` with `script-src 'unsafe-inline'`. Report content includes scraped web pages and LLM output.
- Quantify: same-origin script in the owner's session on an agentic, computer-use app = high impact. Likelihood is non-trivial even single-user because research ingests untrusted web content (no attacker account needed). This is the most relevant single-user P0.
- Clash: **High if applied bluntly.** The report template ships legitimate inline scripts (`src/visual_report.py:790+`: export/PDF menu, keyboard back, image hide/reroll) and an inline `onerror` (`:132`). Dropping `unsafe-inline` or stripping all HTML naively would break export and image management.
- Use-case fit: sanitize the rendered body with a strict allowlist (keep code blocks, tables, TOC, links, images), move the app's own report scripts to nonce or an external static file, and replace the inline `onerror` with a delegated listener. Then drop `unsafe-inline` for report pages. Preserves every report feature.

### AUDIT-002 — verified, no clash

- Evidence: `routes/research_routes.py:463` `research_spinoff` calls only `_require_user`; it reads `get_result` and the on-disk JSON without `_assert_owns_research`. Sibling routes (`report` `:143`, `result` `:116`, `status` `:98`, `stream` `:412`, `result-peek` `:445`) all gate ownership.
- Quantify: single-user has one owner, so impact is low; multi-user allows copying another user's research via a guessed/leaked id (medium, low likelihood).
- Use-case fit: add `_assert_owns_research(session_id, user)` — the helper already exists in the file. In single-user mode `user` resolves to `""` and stored `owner` is `""`, so the gate passes. Zero functionality lost.

### AUDIT-003 — verified, fix as written

- Evidence: `routes/session_routes.py:234` and `:294`, and `routes/research_routes.py:331`, load `ModelEndpoint` by caller-supplied `endpoint_id` with no owner filter, then use `ep.api_key` (`EncryptedText` — used as a bearer credential, not returned in plaintext). `ModelEndpoint.owner` exists (`core/database.py:22`).
- Quantify: single-user owns all endpoints (low). Multi-user lets a user spend another user's paid key (medium; billing/quota abuse rather than plaintext key theft).
- Use-case fit: apply `owner_filter(..., ModelEndpoint, user)` before reading `api_key`. `include_shared=True` keeps NULL-owner shared endpoints working, so intended shared-endpoint use is preserved; only genuinely private endpoints become 404 to non-owners, which is the goal.

### AUDIT-004 — verified, fix is pure authorization (no URL filtering)

- Evidence: every handler in `routes/embedding_routes.py` takes no `Request` and performs no admin/owner check beyond global auth. `set_endpoint` (`:237`) does `httpx.post(url, ...)` to a caller-supplied URL (`:247`). Download/delete mutate global cache; the endpoint is stored globally (env + `data/embedding_endpoint.json`) and resets ChromaDB for the whole app.
- Quantify: in an agentic app the live single-user risk is a prompt-injectable principal (a low-scope API token; AUDIT-005 lets it reach here) driving an endpoint-set to an internal target. Download/delete is global resource abuse by any authenticated caller.
- URL filtering is the wrong lever and is rejected: the endpoint feature is designed to point anywhere — cloud (OpenAI embeddings), local (Ollama/vllm/llama.cpp), or a proxy (codex/opencode-style). The owner already has shell on the host, so destination-IP filtering on a field only the owner sets protects nothing against the owner while risking breakage of legitimate configs. This is an authorization problem, not a URL problem.
- Clash: **None** with the corrected (authz-only) fix. Verified non-breaking:
  - The embedding UI lives entirely in `static/js/admin.js`, whose header declares it an **admin-only** surface — so gating the backend matches existing UI intent.
  - The agent's `download_model` tool uses a **separate HuggingFace/serving path** (`src/tool_implementations.py:2857` `do_download_model`, `repo_id`-based), not `/api/embeddings/*`.
  - `require_admin` (`core/middleware.py:20-44`) already bypasses for the agent's internal-tool loopback, localhost, and `AUTH_ENABLED=false`. Owner + agent + local callers keep working; only an external low-scope bearer token (the bug) is denied.
- Use-case fit: add `Request` to `set_endpoint`/`clear_endpoint`/`download_model`/`delete_model` and call `require_admin(request)` (or a narrow explicit `manage_embeddings` privilege). **No URL validation** — cloud/local/proxy endpoints stay fully usable. This also closes the part of AUDIT-005 where a bearer token reaches these routes.

### AUDIT-005 — verified, needs a scope map before enforcement

- Evidence: `app.py:245` sets `request.state.current_user = "api"` for any valid bearer token and calls `next` for every route. Only `/api/v1/chat` (`routes/webhook_routes.py:194-201`) checks `api_token` + `chat` scope. No other route inspects `request.state.api_token`. With `owner_filter` and `user="api"`, a token matches `owner=="api"` **or** NULL-owner (shared) rows.
- Quantify: a leaked chat-scoped token reaches every authenticated route. Owner-filtered routes limit it to `api`-owned plus shared/legacy (NULL-owner) records; non-owner-filtered global routes (e.g. the AUDIT-004 embedding routes) are fully reachable. `is_admin("api")` is false, so admin routes stay protected. Impact medium.
- Clash: **Medium.** Defaulting bearer tokens to deny-everywhere could break existing automation that legitimately calls more than `/api/v1/chat`.
- Use-case fit (non-breaking path): instrument first — log every bearer-token route hit with token id, scope, route, and method (passive, no behavior change). Build the scope/allowlist map from observed real usage, then enforce centrally (route-level scope metadata, or default-deny bearer on non-token-aware routes). This guarantees no existing integration breaks silently, because enforcement is derived from what tokens actually do. Stop treating `current_user="api"` as a normal browser user. This is the finding the telemetry layer is built to de-risk.

### Lower-tier findings

AUDIT-006 through AUDIT-014 were re-confirmed as reliability / UX / maintainability issues, not security boundaries (priority tier 3). No intended-use clash; they are safe to fix opportunistically with regression coverage.

## P0 / High Severity

### AUDIT-001: Stored XSS Risk In Research Reports

- Status: Open (verified 2026-06-01)
- Severity: High
- Area: Security
- Files: `src/visual_report.py`, `core/middleware.py`
- Evidence: Research report markdown is rendered into HTML while report responses are served with a report-specific CSP that allows `script-src 'unsafe-inline'`. Normal app pages use nonce-based script CSP; this finding is specific to generated research report pages.
- Impact: A malicious source page, prompt-injected report, or compromised generated report can become same-origin stored XSS. Same-origin script can target session-backed app APIs.
- Recommended fix: Sanitize generated report HTML with a strict allowlist such as `bleach`, disable raw HTML in report markdown where possible, and remove `'unsafe-inline'` for report pages. Keep legitimate report interactivity by moving trusted scripts to external static JS or nonce/hash-based inline scripts.
- Suggested test: Persist a report containing `<script>window.__xss=1</script>` and an event-handler payload such as `<img src=x onerror=...>`, then assert rendered report HTML neutralizes them and CSP blocks execution.

### AUDIT-002: Research Spinoff Missing Ownership Check

- Status: Open (verified 2026-06-01)
- Severity: High
- Area: Security / privacy
- File: `routes/research_routes.py`
- Evidence: `/api/research/spinoff/{session_id}` calls `_require_user(request)` but does not verify the caller owns the research task/result before reading in-memory or disk data.
- Impact: Any authenticated user who learns or guesses a research id can copy another user's research report into a new chat session.
- Recommended fix: Capture `user = _require_user(request)` and check `_owns_in_memory(session_id, user)` and/or persisted result ownership before reading result/sources. Return 404 on mismatch. Preserve intended use by allowing the owning user and admins only if admin cross-user research access is an intentional product feature.
- Suggested test: Create two users, seed research result owned by user A, call spinoff as user B, assert 404 and no new session.

### AUDIT-003: Private Endpoint API Keys Can Be Reused By Id

- Status: Open (verified 2026-06-01)
- Severity: High
- Area: Security / secret isolation
- Files: `routes/session_routes.py`, `routes/research_routes.py`
- Evidence: Session creation, session endpoint switching, and research startup load `ModelEndpoint` by direct `endpoint_id` without owner-scoping before reading `api_key`. Some default endpoint resolution paths already owner-filter; this finding is about explicit caller-supplied endpoint ids.
- Impact: A non-admin who obtains or guesses another user's endpoint id can cause Odysseus to use that endpoint's stored API key for chat or research.
- Recommended fix: Use `owner_filter(..., ModelEndpoint, current_user)` for non-admin callers before reading endpoint rows. Reject invisible/private endpoints with 404. Preserve intended shared endpoints by allowing records that the existing owner-filter policy marks visible.
- Suggested test: User A creates endpoint with API key; user B attempts chat/research with A's `endpoint_id`; assert 404 and no Authorization header is stored/used.

### AUDIT-004: Embedding Management Is Not Admin-Gated

- Status: Open (verified 2026-06-01)
- Severity: High
- Area: Security / resource abuse / SSRF
- File: `routes/embedding_routes.py`
- Evidence: Embedding model download/delete and custom embedding endpoint set/clear routes do not require admin authorization.
- Impact: Any authenticated user can trigger large model downloads, delete cached embedding models, or set arbitrary embedding endpoints. Endpoint health check posts to caller-controlled URLs, which can become SSRF against internal services.
- Recommended fix (authz-only, no URL filtering): Add `Request` to the write/delete handlers (`set_endpoint`, `clear_endpoint`, `download_model`, `delete_model`) and require admin or a narrow explicit `manage_embeddings` privilege. Do **not** validate/restrict the destination URL — the feature must reach cloud, local, and proxy endpoints freely. `require_admin` already preserves the owner, the agent's internal-tool loopback, and localhost, so no feature is lost; only an external low-scope bearer token (the AUDIT-005 bug) is denied.
- Suggested test: Non-admin / bearer-token POST/DELETE to embedding routes returns 403; admin (and the internal-tool loopback) succeed. A custom endpoint URL pointing at a public cloud embeddings API, `http://localhost:11434/...`, or a Docker service name all still save successfully — no URL is rejected on range grounds.

### AUDIT-005: API Token Scopes Are Not Enforced Globally

- Status: Open (verified 2026-06-01)
- Severity: High
- Area: Security / auth model
- File: `app.py`
- Evidence: Global auth middleware accepts bearer API tokens and sets `current_user = "api"`. `/api/v1/chat` enforces `chat` scope, but many normal app routes only see an authenticated-ish request and do not reject API-token callers.
- Impact: A leaked low-scope token may reach other authenticated surfaces that were intended for browser sessions only. Owner-filtered routes often see the synthetic owner `"api"`, so the main risk is unintended authenticated route reachability or global mutation, not always direct access to the token owner's records.
- Recommended fix: In middleware, allow bearer tokens only on token-aware routes by default, or add route-level scope metadata and enforce centrally. Avoid treating `current_user = "api"` as a normal user.
- Suggested test: Token with only `chat` scope can call `/api/v1/chat` but gets 403/404 on sessions, uploads, notes, memory, settings, gallery, etc. unless explicitly scoped.

## P1 / Medium Severity

### AUDIT-006: Blocking TTS/STT Work Inside Async Handlers

- Status: Open
- Severity: Medium
- Area: Reliability / UX
- Files: `routes/tts_routes.py`, `services/tts/tts_service.py`, `routes/stt_routes.py`, `services/stt/stt_service.py`
- Evidence: Async FastAPI handlers directly call sync service methods. The services use blocking `httpx.post(..., timeout=60)` and may also perform local model work.
- Impact: A slow TTS/STT request can block the event loop and make unrelated UI requests hang.
- Recommended fix: Run sync synthesis/transcription via `await asyncio.to_thread(...)`, or convert services to async with `httpx.AsyncClient` and offload local CPU/GPU model work.
- Suggested test: Start a delayed fake TTS/STT endpoint, issue synthesize/transcribe request, concurrently call `/api/health`, assert health responds immediately.

### AUDIT-007: Duplicate `chat.js` Module Loading

- Status: Open
- Severity: Medium
- Area: Frontend reliability
- Files: `static/index.html`, `static/app.js`
- Evidence: `static/index.html` loads `/static/js/chat.js?v=20260520m`, while `static/app.js` imports `./js/chat.js`.
- Impact: Browsers treat these as different module URLs, so module state can split. This creates brittle behavior around singleton state, event handlers, and cache invalidation.
- Recommended fix: Use one canonical module specifier. Prefer `/static/js/chat.js` everywhere and rely on `_RevalidatingStatic` no-cache behavior, or introduce a consistent build/versioning strategy for every module.
- Suggested test: Browser smoke test asserts only one `chat.js` module URL is requested.

### AUDIT-008: Runtime CDN Dependency Breaks Offline/Self-Hosted Mode

- Status: Open
- Severity: Medium
- Area: UX / self-hosting
- File: `static/index.html`
- Evidence: KaTeX CSS/JS and Mermaid are loaded from jsDelivr at runtime.
- Impact: Offline installs, blocked CDN networks, privacy-hardened browsers, or air-gapped deployments lose math/diagram rendering without a clear fallback.
- Recommended fix: Vendor these libraries under `static/lib/` like other frontend dependencies, or show a graceful feature-unavailable state when CDN loading fails.
- Suggested test: Block jsDelivr in a browser test and assert app still loads with visible fallback for math/diagram rendering.

### AUDIT-009: PWA Icons 404

- Status: Open
- Severity: Medium
- Area: UX / PWA
- Files: `static/manifest.json`, `static/index.html`
- Evidence: Manifest and apple-touch link reference `/static/icon-192.png` and `/static/icon-512.png`, but these files are absent.
- Impact: Install/bookmark icons fail or fall back unpredictably.
- Recommended fix: Add PNG icons at the referenced paths or change manifest/icon references to existing generated SVG/data icon strategy.
- Suggested test: Static asset smoke test asserts every manifest icon and linked apple-touch icon returns 200.

### AUDIT-010: Unpinned Runtime Dependencies

- Status: Open
- Severity: Medium
- Area: Maintainability / install reproducibility
- Files: `requirements.txt`, `package.json`
- Evidence: Python runtime dependencies are unpinned, and npm dependencies use semver ranges.
- Impact: Fresh installs can silently pull breaking dependency versions. This is especially risky for FastAPI/Pydantic/SQLAlchemy/httpx/Chroma/fastembed and UI tooling.
- Recommended fix: Add a constraints or lock workflow for Python. Pin runtime ranges intentionally. Keep upgrade cadence explicit. For npm, decide whether app installs should use `package-lock.json` only or exact versions in `package.json`.
- Suggested test: CI fresh install from lock/constraints and run smoke tests.

### AUDIT-011: Upload Metadata Is JSON File With Concurrent Writers

- Status: Open
- Severity: Medium
- Area: Data integrity / UX
- Files: `src/upload_handler.py`, `routes/upload_routes.py`
- Evidence: Upload metadata is stored in `uploads.json`; multiple requests can read/modify/write it without file-level locking or atomic write.
- Impact: Concurrent uploads can lose metadata, causing files to exist on disk but become ownerless/unfindable, or breaking duplicate detection.
- Recommended fix: Move upload metadata into SQLite or protect JSON writes with process-wide lock plus atomic write. Prefer DB because the rest of the app already uses SQLAlchemy models for many user-owned records.
- Suggested test: Concurrently upload N files from same/different users, assert all metadata records survive and ownership remains correct.

### AUDIT-012: Very Large Static CSS And Frontend Modules

- Status: Open
- Severity: Medium
- Area: Maintainability / regression risk
- Files: `static/style.css`, `static/js/document.js`, `static/js/slashCommands.js`, `static/js/notes.js`, `static/js/emailLibrary.js`, `static/js/chat.js`
- Evidence: `static/style.css` is about 34k lines; several frontend modules are multi-thousand-line files.
- Impact: CSS/media overrides and shared global state become hard to reason about, matching the roadmap's known CSS/window/mobile concerns. Small fixes can regress distant UI.
- Recommended fix: Introduce scoped CSS sections/components gradually. Add CSS ownership comments for paired desktop/mobile rules. Start with high-churn areas: modals/window manager, gallery/editor, documents, tasks.
- Suggested test: Add Playwright/Bombadil snapshots or smoke flows for modal placement, mobile viewport, Esc close behavior, and core tool opening.

## P2 / Low Severity

### AUDIT-013: Dead `/backgrounds` Route Points To Missing File

- Status: Open
- Severity: Low
- Area: UX / cleanup
- File: `app.py`
- Evidence: `/backgrounds` serves `static/backgrounds.html`, which is absent. The comment says no auth is required, but the route is not auth-exempt when auth middleware is enabled.
- Impact: Route produces a server error or misleading behavior.
- Recommended fix: Remove route, add the file, or return a clean 404. Align the comment with actual auth behavior.
- Suggested test: Static route smoke test verifies all declared HTML routes return 200 or intentional 404.

### AUDIT-014: Test Environment Not Self-Contained

- Status: Open
- Severity: Low
- Area: Developer experience
- Files: `requirements.txt`, `pyproject.toml`, test docs
- Evidence: `python -m pytest -q` failed in this shell because `pytest` was unavailable in active Python, despite `pytest` being listed in `requirements.txt`.
- Impact: New contributors may not know the exact supported install/test path.
- Recommended fix: Document a canonical dev setup command and consider adding `requirements-dev.txt` or `uv`/`pip-tools` workflow. Keep runtime and test dependencies clear.
- Suggested test: CI job installs exactly documented dependencies and runs pytest.

## Positive Security Signals

- Auth defaults are conservative: `AUTH_ENABLED=true`, localhost bypass defaults false, and docs warn against public unauthenticated deployment.
- Many high-risk routes are already admin-gated: shell, MCP management, model/cookbook actions, API tokens, webhooks, backup/vault, and settings.
- Several prior ownership bugs appear to have been fixed and documented inline with `SECURITY:` comments.
- Regression tests exist for security-sensitive behavior including secret storage, upload path handling, auth, owner gates, rate limiting, endpoint resolver, and shell routes.
- Generated image serving validates filename shape and checks gallery ownership when metadata exists.

## Recommended Fix Order

1. Fix AUDIT-002, AUDIT-003, AUDIT-004, and AUDIT-005 first. These are auth/ownership boundary bugs and are likely small patches with high security value.
2. Fix AUDIT-001 next. It may need more care because report HTML includes legitimate formatting/scripts, but stored XSS risk is high.
3. Fix AUDIT-006 with `asyncio.to_thread()` as a narrow first pass.
4. Add static asset/module smoke tests and fix AUDIT-007, AUDIT-009, AUDIT-013.
5. Decide dependency locking strategy and add install smoke CI.
6. Start frontend maintainability work only after the highest-risk behavior bugs are covered by tests.

## Continual Improvement Linkage

These findings are inputs to the continual-improvement loop in `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md` and the telemetry concepts in `docs/security-telemetry-visual-concepts.html`. Every fix tracked here should:

- **Be traceable.** Tie the finding to the observed evidence (and, once telemetry exists, to a provenance trace) rather than a hunch.
- **Preserve the feature.** Narrow access to the correct owner/admin/scope or sanitize output; do not remove a working capability. Where admin-only is too coarse, add an explicit privilege.
- **Land a regression test.** Each fix ships with the "Suggested test" (or a better one) so the behavior is locked in and cannot silently regress.
- **Follow the priority order.** Security boundary findings (AUDIT-001..005) before reliability/feature work, with maintainability/UX (AUDIT-007, 009, 012, 013) last unless paired with an exploit path.
