"""Read-only admin surface for the passive safety-telemetry ledger.

This is note 3 of the "Implementation Shape" in
`docs/security-telemetry-visual-concepts.html` (the Safety Recorder Dashboard /
Provenance views) and the observe-stage deliverable of G2 in
`docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`.

Scope is deliberately narrow and safe:

* **Read-only.** No route here mutates anything or enforces any policy. The
  layer only *exposes* what the recorder already captured locally. Enforcement
  (blocking, sanitization, scope deny) is a separate, later, explicitly-decided
  stage — this just makes behavior visible (the meta-gate's "observe first").
* **Admin-gated.** The ledger can contain routes, targets, and token state, so
  reading it is admin-only via the same ``require_admin`` used by shell / MCP /
  embeddings. Bearer API tokens (``current_user == "api"``) are rejected.
* **Local-only.** Data comes from ``src.security_telemetry``'s JSONL ledger
  under ``data/`` (gitignored); nothing egresses.
"""

import logging

from fastapi import APIRouter, Depends, Query

from core.middleware import require_admin
from src import security_telemetry as telemetry

logger = logging.getLogger(__name__)


def setup_security_telemetry_routes() -> APIRouter:
    router = APIRouter(prefix="/api/security/telemetry", tags=["security-telemetry"])

    @router.get("/summary")
    async def telemetry_summary(_admin: None = Depends(require_admin)):
        """Counts by classification bucket — the dashboard metrics row.

        (expected / needs_decision / dangerous / unknown / no_evidence / total)
        """
        return telemetry.summary()

    @router.get("/events")
    async def telemetry_events(
        _admin: None = Depends(require_admin),
        classification: str | None = Query(
            None,
            description="filter to one bucket: expected|needs_decision|dangerous|unknown|no_evidence",
        ),
        limit: int = Query(200, ge=1, le=2000),
    ):
        """Recent provenance-bearing events, newest first.

        Each event carries its replayable trace: raw signals, the classifier
        rule + rule_version, confidence, code refs, and an inputs hash — so a
        claim can be re-derived rather than taken on faith.
        """
        events = telemetry.read_events(limit=limit, classification=classification)
        return {"events": events, "count": len(events)}

    return router
