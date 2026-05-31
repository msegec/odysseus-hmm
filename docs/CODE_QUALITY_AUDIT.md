# Code Quality Audit Tracker

Audit date: 2026-06-01
Source reviewed: `pewdiepie-archdaemon/odysseus` at `051751a` (`main`)
Scope: security issues, user-experience breaking issues, maintainability risks, and obvious next hardening work.

Status legend: `Open`, `In progress`, `Fixed`, `Needs verification`, `Accepted risk`.

## Verification Notes

- `npm audit --audit-level=moderate`: passed, 0 vulnerabilities.
- `python -m pytest -q`: not run successfully in this shell because the active Python environment has no `pytest` installed.
- `python -m pip list --outdated`: active environment has many outdated packages, but this is the user's global/miniconda environment, not a project venv. Treat as weak signal only.
- Static size signal: `static/style.css` is about 34k lines and 1.1 MB; top frontend modules include `document.js` at about 9.2k lines and `slashCommands.js` at about 5.9k lines.

## P0 / High Severity

### AUDIT-001: Stored XSS Risk In Research Reports

- Status: Open
- Severity: High
- Area: Security
- Files: `src/visual_report.py`, `core/middleware.py`
- Evidence: Research report markdown is rendered into HTML while report responses are served with a report-specific CSP that allows `script-src 'unsafe-inline'`. Normal app pages use nonce-based script CSP; this finding is specific to generated research report pages.
- Impact: A malicious source page, prompt-injected report, or compromised generated report can become same-origin stored XSS. Same-origin script can target session-backed app APIs.
- Recommended fix: Sanitize generated report HTML with a strict allowlist such as `bleach`, disable raw HTML in markdown where possible, and remove `'unsafe-inline'` for report pages. Keep only nonce/hash-based trusted scripts if inline scripts are required.
- Suggested test: Persist a report containing `<script>window.__xss=1</script>` and an event-handler payload such as `<img src=x onerror=...>`, then assert rendered report HTML neutralizes them and CSP blocks execution.

### AUDIT-002: Research Spinoff Missing Ownership Check

- Status: Open
- Severity: High
- Area: Security / privacy
- File: `routes/research_routes.py`
- Evidence: `/api/research/spinoff/{session_id}` calls `_require_user(request)` but does not verify the caller owns the research task/result before reading in-memory or disk data.
- Impact: Any authenticated user who learns or guesses a research id can copy another user's research report into a new chat session.
- Recommended fix: Capture `user = _require_user(request)` and check `_owns_in_memory(session_id, user)` and/or persisted result ownership before reading result/sources. Return 404 on mismatch.
- Suggested test: Create two users, seed research result owned by user A, call spinoff as user B, assert 404 and no new session.

### AUDIT-003: Private Endpoint API Keys Can Be Reused By Id

- Status: Open
- Severity: High
- Area: Security / secret isolation
- Files: `routes/session_routes.py`, `routes/research_routes.py`
- Evidence: Session creation, session endpoint switching, and research startup load `ModelEndpoint` by direct `endpoint_id` without owner-scoping before reading `api_key`. Some default endpoint resolution paths already owner-filter; this finding is about explicit caller-supplied endpoint ids.
- Impact: A non-admin who obtains or guesses another user's endpoint id can cause Odysseus to use that endpoint's stored API key for chat or research.
- Recommended fix: Use `owner_filter(..., ModelEndpoint, current_user)` for non-admin callers before reading endpoint rows. Reject invisible/private endpoints with 404. Consider centralizing endpoint lookup in one helper.
- Suggested test: User A creates endpoint with API key; user B attempts chat/research with A's `endpoint_id`; assert 404 and no Authorization header is stored/used.

### AUDIT-004: Embedding Management Is Not Admin-Gated

- Status: Open
- Severity: High
- Area: Security / resource abuse / SSRF
- File: `routes/embedding_routes.py`
- Evidence: Embedding model download/delete and custom embedding endpoint set/clear routes do not require admin authorization.
- Impact: Any authenticated user can trigger large model downloads, delete cached embedding models, or set arbitrary embedding endpoints. Endpoint health check posts to caller-controlled URLs, which can become SSRF against internal services.
- Recommended fix: Add `Request` to write/delete handlers and call `require_admin(request)`. Validate custom endpoint URLs; block private/link-local metadata ranges unless explicitly allowed by admin config.
- Suggested test: Non-admin POST/DELETE to embedding routes returns 403; admin succeeds. Endpoint URL validation rejects `http://169.254.169.254/...` and loopback/private targets unless allowed.

### AUDIT-005: API Token Scopes Are Not Enforced Globally

- Status: Open
- Severity: High
- Area: Security / auth model
- File: `app.py`
- Evidence: Global auth middleware accepts bearer API tokens and sets `current_user = "api"`. `/api/v1/chat` enforces `chat` scope, but many normal app routes only see an authenticated-ish request and do not reject API-token callers.
- Impact: A leaked low-scope token may reach other authenticated surfaces that were intended for browser sessions only. Owner-filtered routes often see the synthetic owner `"api"`, so the main risk is unintended authenticated route reachability or global mutation, not always direct access to the token owner's records.
- Recommended fix: In middleware, allow bearer tokens only on token-aware routes by default, or add route-level scope metadata and enforce centrally. Avoid treating `current_user = "api"` as a normal user.
- Suggested test: Token with only `chat` scope can call `/api/v1/chat` but gets 403/404 on sessions, uploads, notes, memory, settings, gallery, etc. unless explicitly scoped.

### AUDIT-006: Blocking TTS/STT Work Inside Async Handlers

- Status: Open
- Severity: High
- Area: Reliability / UX
- Files: `routes/tts_routes.py`, `services/tts/tts_service.py`, `routes/stt_routes.py`, `services/stt/stt_service.py`
- Evidence: Async FastAPI handlers directly call sync service methods. The services use blocking `httpx.post(..., timeout=60)` and may also perform local model work.
- Impact: A slow TTS/STT request can block the event loop and make unrelated UI requests hang.
- Recommended fix: Run sync synthesis/transcription via `await asyncio.to_thread(...)`, or convert services to async with `httpx.AsyncClient` and offload local CPU/GPU model work.
- Suggested test: Start a delayed fake TTS/STT endpoint, issue synthesize/transcribe request, concurrently call `/api/health`, assert health responds immediately.

## P1 / Medium Severity

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
