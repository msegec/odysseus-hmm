"""Passive safety-telemetry recorder — local-only provenance ledger.

This is note 1 + note 4 of the "Implementation Shape" in
`docs/security-telemetry-visual-concepts.html`: a central
``record_security_event(...)`` plus a ledger whose every row carries full
provenance (raw signals, classifier rule + rule version, confidence, code
refs, local timestamp) so any claim is replayable.

Storage choice (recorded decision): an **append-only JSONL file under
``data/security_telemetry/``**, not a DB table. Why:

* ``data/`` and ``*.db`` are gitignored, so the ledger is *guaranteed*
  local-only and never committed to git — G1 line 26 / the footer's "local dev
  telemetry" intent, by construction rather than by policy.
* No schema migration and no coupling to the heavy SQLAlchemy layer, so it
  can't affect app boot and stays stdlib-only / independently testable.
* Append-only matches "ledger" semantics: events are immutable evidence.

The recorder is **passive and best-effort**: it must never raise into the
caller's request path. A telemetry failure silently no-ops; observability is
never allowed to break a feature (the "no feature lost" invariant).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Default lives under data/ (gitignored). Overridable for tests via
# set_ledger_dir(); the env var lets an operator relocate it off a shared mount.
_DEFAULT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "security_telemetry",
)
_ledger_dir = os.environ.get("ODYSSEUS_TELEMETRY_DIR", _DEFAULT_DIR)
_lock = threading.Lock()
_seq = 0


def set_ledger_dir(path: str) -> None:
    """Point the ledger at ``path`` (used by tests and operators)."""
    global _ledger_dir
    _ledger_dir = path


def _ledger_path() -> str:
    # One file per UTC day keeps each file small and makes retention trivial.
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return os.path.join(_ledger_dir, f"events-{day}.jsonl")


def _next_trace_id() -> str:
    global _seq
    _seq += 1
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"evt_{stamp}_{_seq:04d}"


def record_security_event(
    *,
    event_type: str,
    source: str,
    classification: str,
    rule: str,
    rule_version: str,
    confidence: float,
    target: str = "",
    route: str = "",
    method: str = "",
    user: str = "",
    token_state=None,
    signals=None,
    code_refs=None,
    suggested_fix: str = "",
):
    """Append one provenance-bearing event to the local ledger.

    Returns the trace id on success, or ``None`` if recording failed (the
    caller never needs to care — telemetry is observe-only and best-effort).
    """
    try:
        signals = signals if signals is not None else {}
        code_refs = code_refs if code_refs is not None else []
        # Stable hash over the evidence so an event is tamper-evident and
        # de-dupable; this is the "inputs hash" shown in the provenance view.
        digest_src = json.dumps(
            {"t": event_type, "s": source, "tgt": target, "sig": signals,
             "rule": rule, "rv": rule_version},
            sort_keys=True, default=str,
        )
        inputs_hash = "sha256:" + hashlib.sha256(digest_src.encode()).hexdigest()[:32]

        with _lock:
            trace_id = _next_trace_id()
            event = {
                "trace_id": trace_id,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "source": source,
                "route": route,
                "method": method,
                "user": user,
                "token_state": token_state,
                "target": target,
                "signals": signals,
                "rule": rule,
                "rule_version": rule_version,
                "classification": classification,
                "confidence": confidence,
                "code_refs": code_refs,
                "suggested_fix": suggested_fix,
                "inputs_hash": inputs_hash,
            }
            os.makedirs(_ledger_dir, exist_ok=True)
            with open(_ledger_path(), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
        return trace_id
    except Exception as exc:  # noqa: BLE001 — passive layer must never raise
        logger.debug("security telemetry record failed (ignored): %s", exc)
        return None


def record_verdict(verdict, **ctx):
    """Convenience bridge from a ``security_classifiers.Verdict`` to a record.

    Lets instrumentation sites stay one-liners:
        record_verdict(classify_network_target(url), event_type="network_target",
                       source="research.web_fetch", target=url, route=..., user=...)
    """
    return record_security_event(
        classification=verdict.classification,
        rule=verdict.rule,
        rule_version=verdict.rule_version,
        confidence=verdict.confidence,
        signals=verdict.signals,
        code_refs=list(getattr(verdict, "code_refs", []) or []),
        suggested_fix=getattr(verdict, "suggested_fix", ""),
        **ctx,
    )


def read_events(limit=None, classification=None):
    """Read recorded events newest-first. Best-effort; never raises.

    Reads every daily file in the ledger dir. ``limit`` caps the result;
    ``classification`` filters to one bucket.
    """
    out = []
    try:
        if not os.path.isdir(_ledger_dir):
            return out
        files = sorted(
            (f for f in os.listdir(_ledger_dir)
             if f.startswith("events-") and f.endswith(".jsonl")),
            reverse=True,
        )
        for name in files:
            path = os.path.join(_ledger_dir, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if classification and ev.get("classification") != classification:
                    continue
                out.append(ev)
                if limit and len(out) >= limit:
                    return out
    except Exception as exc:  # noqa: BLE001
        logger.debug("security telemetry read failed (ignored): %s", exc)
    return out


def summary():
    """Count events by classification bucket (for the dashboard metrics row)."""
    counts = {"expected": 0, "needs_decision": 0, "dangerous": 0,
              "unknown": 0, "no_evidence": 0, "total": 0}
    for ev in read_events():
        cls = ev.get("classification", "unknown")
        counts[cls] = counts.get(cls, 0) + 1
        counts["total"] += 1
    return counts
