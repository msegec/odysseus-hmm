# Odysseus Current Features And Goals

Audit date: 2026-06-01
Source reviewed: `pewdiepie-archdaemon/odysseus` at `051751a` (`main`)

## Executive Summary

Odysseus is a self-hosted AI workspace that aims to replace the day-to-day UI experience of ChatGPT/Claude while keeping data, model configuration, memory, automations, and privileged tools under the user's control. It is not just a chat frontend: it is a local-first operating surface for models, agents, research, documents, memory, email, calendar, tasks, images, and self-host integrations.

The project is feature-rich and already has a broad working surface. The next best work is not adding another major feature. The highest-leverage path is reliability, integration verification, security hardening, clearer first-run/degraded states, and frontend polish around mobile/modal/window behavior.

## Product Goals

1. Provide a local-first, privacy-first AI workspace that users can run on their own hardware.
2. Make local and remote model use practical through simple provider setup, endpoint probing, model selection, and hardware-aware serving recommendations.
3. Combine chat, agent execution, long-term memory, documents, research, and personal productivity tools in one workspace.
4. Let the assistant become more useful over time through persistent memory, skills, RAG, scheduled tasks, and user-specific context.
5. Support self-hosted power users while keeping high-risk operations behind admin controls.
6. Work well on desktop and mobile as an installable PWA.

## Current User-Facing Features

### Chat

- Streaming AI chat with session history, model selection, presets, search, markdown/code rendering, file attachments, vision/OCR paths, and export/copy/save flows.
- Supports local and API-backed OpenAI-compatible endpoints.
- Includes incognito/no-history style behavior for ephemeral sessions.
- Includes voice-adjacent surfaces through STT/TTS routes and browser/local/API provider settings.

Primary files: `routes/chat_routes.py`, `src/chat_handler.py`, `src/chat_processor.py`, `static/js/chat.js`, `static/js/chatStream.js`, `static/js/chatRenderer.js`.

### Agent And Tools

- Agent loop with tool execution, shell/Python/file/web/MCP paths, memory/skills integration, and background job continuation.
- Built-in MCP server registration and user-managed MCP route surface.
- Tool security exists in multiple modules, with admin-gated high-risk app routes.

Primary files: `src/agent_loop.py`, `src/agent_tools.py`, `src/tool_execution.py`, `src/tool_security.py`, `src/mcp_manager.py`, `routes/mcp_routes.py`, `routes/shell_routes.py`.

### Model Providers And Cookbook

- Model endpoint CRUD/probing, default model selection, cached models, provider setup, and endpoint resolution.
- Cookbook features for hardware scanning, model fit ranking, downloads, local/remote serving, optional package checks, SSH key setup, and background run state.
- Hardware fit service covers GPU/VRAM-aware recommendations.

Primary files: `routes/model_routes.py`, `src/model_discovery.py`, `src/endpoint_resolver.py`, `routes/cookbook_routes.py`, `routes/hwfit_routes.py`, `services/hwfit/*`, `static/js/cookbook*.js`.

### Deep Research

- Background research jobs with progress streaming, cancellation, persisted reports, report library/detail views, sources, raw findings, and spinoff chat creation.
- Visual reports are rendered as standalone HTML.

Primary files: `routes/research_routes.py`, `services/research/*`, `src/deep_research.py`, `src/visual_report.py`, `static/js/research/*`, `static/js/researchSynapse.js`.

### Compare

- Side-by-side model comparison with blind voting/history and synthesis-oriented flows.

Primary files: `routes/compare_routes.py`, `static/js/compare/*`, `tests/test_compare_js.py`.

### Documents And Library

- Document creation/editing, multi-format handling, versions/restore, rendering, AI document actions, annotations, export paths, and document library surfaces.
- Supports markdown, HTML, CSV, code/text, PDF import/text extraction, and office-document helpers.

Primary files: `routes/document_routes.py`, `routes/document_helpers.py`, `src/document_processor.py`, `src/document_actions.py`, `static/js/document.js`, `static/js/documentLibrary.js`.

### Memory And Skills

- Persistent memories, search/filter/sort/import/export, AI cleanup/extraction, vector-backed retrieval when available, and disk-backed skills.
- Skill extraction, audit, owner backfill, and formatting helpers exist.

Primary files: `routes/memory_routes.py`, `routes/skills_routes.py`, `services/memory/*`, `src/memory*.py`, `static/js/memory.js`, `static/js/skills.js`.

### RAG And Personal Docs

- Personal document upload/directory registration and guarded RAG integration paths.
- Current app startup explicitly disables the older vector document RAG manager because it was unused/broken, while other memory/vector services still exist.

Primary files: `routes/personal_routes.py`, `src/personal_docs.py`, `src/rag_*`, `app.py`.

### Email, Contacts, Calendar

- IMAP/SMTP inbox, compose/reply, folders, search, drafts/scheduled send, attachments-to-docs, AI reply/triage helpers, and email account management.
- Contacts/CardDAV import/export and local contact handling.
- Local calendar with CalDAV sync, `.ics` import/export, event CRUD, colors, reminders, and agent/task integration.

Primary files: `routes/email_routes.py`, `routes/email_helpers.py`, `mcp_servers/email_server.py`, `routes/contacts_routes.py`, `routes/calendar_routes.py`, `src/caldav_sync.py`, `static/js/email*.js`, `static/js/calendar*.js`.

### Notes, Tasks, Reminders

- Notes with pin/archive/checklists/reminders.
- Scheduled tasks with run history, notifications, webhooks, pause/resume/run-now/revert flows, and default housekeeping tasks.

Primary files: `routes/note_routes.py`, `routes/task_routes.py`, `src/task_scheduler.py`, `src/task_endpoint.py`, `static/js/notes.js`, `static/js/tasks.js`.

### Gallery And Image Editor

- Gallery upload/library/albums/tags/favorites, batch AI tagging, zip download, generated image serving, editor drafts, inpaint/harmonize/upscale/sharpen/denoise/background removal/face enhancement surfaces.

Primary files: `routes/gallery_routes.py`, `routes/gallery_helpers.py`, `routes/editor_draft_routes.py`, `static/js/gallery.js`, `static/js/galleryEditor.js`.

### Admin, Auth, Integrations, Backup

- Multi-user auth, session cookies, 2FA/TOTP flows, admin user management, privileges, app settings, API tokens, webhooks, integrations, backup/import/export, vault routes, and security headers.

Primary files: `core/auth.py`, `core/middleware.py`, `routes/auth_routes.py`, `routes/api_token_routes.py`, `routes/webhook_routes.py`, `routes/backup_routes.py`, `routes/vault_routes.py`.

### PWA And Mobile

- Manifest, service worker, route-specific app titles/icons, mobile-aware UI, touch/mobile feature claims, and large static frontend module set. PWA installability is currently degraded because the manifest/apple-touch PNG icons are referenced but missing.

Primary files: `static/index.html`, `static/manifest.json`, `static/sw.js`, `static/style.css`, `static/js/*`.

## Current Architecture

- `app.py`: FastAPI composition root. Loads auth, security middleware, static serving, route factories, managers, startup tasks, and shutdown cleanup.
- `core/`: auth, database, middleware, constants, exceptions, session manager primitives.
- `routes/`: HTTP API modules. Most features are wired by `setup_*_routes()` factories.
- `src/`: business logic, model/agent/tool internals, settings, schedulers, document/research/search helpers.
- `services/`: feature services for memory, research, search, hardware fit, TTS/STT, shell, docs, YouTube.
- `mcp_servers/`: bundled MCP-style servers for email, memory, RAG, image generation.
- `static/`: raw HTML/CSS/ES module frontend with no build step.
- `docs/`: public/demo assets and project documentation.
- `tests/`: pytest tests plus a Bombadil spec.

## Important Strengths

- Very broad feature surface for a self-hosted AI workspace.
- Security posture is not an afterthought: README/SECURITY call out risk, many routes are admin-gated, ownership checks are present in many areas, and regression tests cover several prior security issues.
- Local-first architecture is simple to inspect and deploy: FastAPI, SQLite/default data directory, static frontend, Docker Compose for ChromaDB/SearXNG/ntfy.
- Raw static ES modules avoid build complexity and make frontend debugging straightforward.
- Roadmap is honest about rough edges and already points to the right next work: bugs, integration audit, Cookbook reliability, frontend polish, accessibility, and degraded states.

## Obvious Next Features / Workstreams

### P0: Security Hardening

- Fix research report stored XSS risk.
- Add missing ownership checks on research spinoff and endpoint usage.
- Lock embedding model management and custom embedding endpoint changes behind admin.
- Centrally enforce API-token route scopes.

See `docs/CODE_QUALITY_AUDIT.md` for tracked issues.

### P0: Fresh Install And Integration Smoke Tests

- Add scripted Docker smoke test for first boot, login/setup, health, bundled services, model catalog load, and static asset 200s.
- Add manual/automated integration checklist for email, CalDAV, ntfy, SearXNG, ChromaDB, MCP, webhooks, and provider probes.
- Surface degraded services in the UI instead of leaving users to inspect logs.

### P1: Cookbook Reliability

- Exercise local and remote flows across OS/GPU/driver/shell combinations.
- Improve install/probe error messages and package detection.
- Document common fixes: venv activation, tmux, SSH key permissions, GPU driver mismatch, Hugging Face cache layout.

### P1: Frontend Reliability

- Normalize modal/window/dropdown coordinate handling.
- Make Esc behavior consistent across popups/modals.
- Reduce split module loading/caching risks.
- Add a small static asset smoke test that checks manifest icons, missing HTML routes, CDN dependencies, and duplicate module URLs.

### P1: Offline/Self-Hosted Assets

- Self-host KaTeX and Mermaid or ship graceful fallback UI.
- Add real PWA icons or switch manifest to existing generated SVG/data icon strategy.
- Document which assets are required for fully offline operation.

### P1: Accessibility And Mobile

- Keyboard navigation/focus states for modals, sidebars, menus, task lists, editor surfaces, and gallery.
- Reduced-motion support for tours/backgrounds.
- Contrast audit of custom themes and dense UI states.
- Mobile gallery/editor polish from the roadmap.

### P2: Dependency And Release Discipline

- Add Python constraints/lock workflow for runtime deps.
- Keep `package-lock.json`, but decide whether npm caret ranges are acceptable for app installs.
- Add a supported Python version and install verification command to README.
- Add release notes/changelog once formal releases start.

### P2: Backup/Restore UX

- Backup endpoints exist, but a clear restore guide/helper flow for `data/` is still needed.
- Include preflight checks: auth file, app DB, uploads, Chroma/memory, settings, secrets key, generated images.

## Goal-Specific Recommendation

For the next development round, do not expand the product surface. Fix the P0 security items, then add a small install/smoke harness that catches missing assets, failing app boot, broken auth setup, and broken bundled-service defaults. That will improve confidence across every existing feature more than another feature would.
