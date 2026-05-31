"""Pure, stdlib-only safety classifiers for the passive telemetry layer.

These are the *Observe*-stage rules from
`docs/security-telemetry-visual-concepts.html` (Concepts 1–3) and the
Continual Improvement Loop in `docs/PROJECT_CURRENT_FEATURES_AND_GOALS.md`.

Design constraints (deliberate):

* **Pure + decoupled.** No DB, no FastAPI, no network. A classifier turns raw
  signals into a `Verdict` and nothing else, so it can be unit-tested on its own
  (the "modular guardrail" invariant) — and so it runs in an env that has no
  sqlalchemy/pytest installed.
* **Observe-only.** Nothing here blocks. The most severe an *app-generated*
  artifact (a research report) gets is ``needs_decision``; only a genuinely
  hostile network target (cloud-metadata SSRF) is ``dangerous``. Enforcement is
  a later, separately-decided stage — this layer just makes behavior visible.
* **Replayable.** Every verdict carries the rule name, a **rule version**, a
  confidence, the raw signals it saw, and code references. When a rule changes,
  old recorded events stay interpretable because their own ``rule_version``
  travels with them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlparse

# Classification vocabulary (matches the dashboard buckets in the concept HTML).
EXPECTED = "expected"
NEEDS_DECISION = "needs_decision"
DANGEROUS = "dangerous"
UNKNOWN = "unknown"
NO_EVIDENCE = "no_evidence"

ALL_CLASSES = (EXPECTED, NEEDS_DECISION, DANGEROUS, UNKNOWN, NO_EVIDENCE)


@dataclass
class Verdict:
    """A replayable classification result.

    ``signals`` keeps the raw evidence the rule consumed so the claim can be
    re-derived later; ``rule`` + ``rule_version`` make old events interpretable
    after a rule changes; ``code_refs`` point at the relevant code / audit IDs.
    """
    classification: str
    rule: str
    rule_version: str
    confidence: float
    signals: object = field(default_factory=dict)   # dict (net) or list (html)
    code_refs: List[str] = field(default_factory=list)
    suggested_fix: str = ""


# ── network-target classifier ──────────────────────────────────

_NET_RULE = "net-target"
_NET_VERSION = "v1"

# Link-local / cloud-metadata ranges — the classic SSRF prize. Anything that
# resolves here is dangerous regardless of who set it (AUDIT-004).
_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"}


def classify_network_target(url: str) -> Verdict:
    """Classify an outbound target URL/host without resolving DNS.

    loopback / private LAN / bare docker service name -> EXPECTED (trusted local)
    link-local metadata                               -> DANGEROUS
    routable public host                              -> NEEDS_DECISION (observe)
    empty / unparseable                               -> UNKNOWN
    """
    raw = (url or "").strip()
    if not raw:
        return Verdict(UNKNOWN, _NET_RULE, _NET_VERSION, 0.0,
                       signals={"reason": "empty target"})

    host = _extract_host(raw)
    if not host or not _is_hostlike(host):
        return Verdict(UNKNOWN, _NET_RULE, _NET_VERSION, 0.2,
                       signals={"reason": "no parseable host", "raw": raw[:120]})

    signals: Dict[str, str] = {"host": host}

    # Metadata endpoints by name (before IP parsing — some are hostnames).
    if host.lower() in _METADATA_HOSTS:
        signals["kind"] = "link-local cloud-metadata"
        return Verdict(DANGEROUS, _NET_RULE, _NET_VERSION, 0.99, signals,
                       code_refs=["AUDIT-004"],
                       suggested_fix="admin-gate the setter; observe-first allowlist, no blunt URL filter")

    ip = _maybe_ip(host)
    if ip is not None:
        if ip.is_link_local:
            signals["kind"] = "link-local (metadata range)"
            return Verdict(DANGEROUS, _NET_RULE, _NET_VERSION, 0.95, signals,
                           code_refs=["AUDIT-004"],
                           suggested_fix="admin-gate the setter; observe-first allowlist")
        if ip.is_loopback:
            signals["kind"] = "loopback / trusted local"
            return Verdict(EXPECTED, _NET_RULE, _NET_VERSION, 0.95, signals)
        if ip.is_private:
            signals["kind"] = "private LAN / docker / VPN"
            return Verdict(EXPECTED, _NET_RULE, _NET_VERSION, 0.9, signals)
        # Public, routable IP literal.
        signals["kind"] = "public IP"
        return Verdict(NEEDS_DECISION, _NET_RULE, _NET_VERSION, 0.7, signals,
                       suggested_fix="confirm this egress is intended")

    # Hostname (not an IP literal).
    if host.lower() == "localhost":
        signals["kind"] = "loopback / trusted local"
        return Verdict(EXPECTED, _NET_RULE, _NET_VERSION, 0.95, signals)

    if "." not in host:
        # Bare single-label name => docker/compose service (searxng, chromadb…).
        signals["kind"] = "docker/internal service"
        return Verdict(EXPECTED, _NET_RULE, _NET_VERSION, 0.85, signals)

    # FQDN -> public egress worth a look (observe-only, never auto-blocked).
    signals["kind"] = "public host"
    return Verdict(NEEDS_DECISION, _NET_RULE, _NET_VERSION, 0.6, signals,
                   suggested_fix="confirm this external egress is intended")


def _extract_host(raw: str) -> str:
    """Best-effort host extraction; tolerant of scheme-less inputs."""
    candidate = raw if "://" in raw else "//" + raw
    try:
        parsed = urlparse(candidate)
        if parsed.hostname:
            return parsed.hostname
    except (ValueError, UnicodeError):
        pass
    # Fallback: strip creds/path/port off a bare authority.
    token = raw.split("/")[0].split("@")[-1]
    token = token.strip("[]")
    token = re.sub(r":\d+$", "", token)
    return token.strip()


# A real host is an IP literal or a DNS name: only letters, digits, dot,
# hyphen, colon (IPv6). Anything with spaces / junk isn't a host — it's noise,
# and must fall through to UNKNOWN rather than be mistaken for a docker service.
_HOSTLIKE = re.compile(r"^[A-Za-z0-9.\-:]+$")


def _is_hostlike(host: str) -> bool:
    return bool(_HOSTLIKE.match(host))


def _maybe_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


# ── report-HTML risk scanner (AUDIT-001, observe-first) ─────────

_HTML_RULE = "report-html"
_HTML_VERSION = "v1"

# Patterns that indicate *active* (script-capable) HTML inside a generated
# research report. Reports render in the app origin, so this is the AUDIT-001
# surface. We only record — sanitization/CSP enforcement is a later decision
# (the report template ships legitimate inline scripts we must preserve).
_HTML_PATTERNS = (
    ("script-tag",     re.compile(r"<\s*script\b", re.I)),
    ("event-handler",  re.compile(r"\son[a-z]+\s*=", re.I)),   # onerror=, onclick=…
    ("javascript:url", re.compile(r"javascript\s*:", re.I)),
    ("iframe",         re.compile(r"<\s*iframe\b", re.I)),
    ("form",           re.compile(r"<\s*form\b", re.I)),
    ("object-embed",   re.compile(r"<\s*(object|embed)\b", re.I)),
)


def scan_report_html(html: str) -> Verdict:
    """Scan generated report HTML for active-content signals.

    Pure detection. A clean report is ``EXPECTED``; any active-content hit is
    ``NEEDS_DECISION`` (observe-only — never auto-``DANGEROUS``, never blocked),
    because in the current single-user deployment reports are trusted, but the
    owner should still *see* that script-capable HTML rendered same-origin.
    """
    text = html or ""
    hits: List[str] = []
    for name, pat in _HTML_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = text[m.start():m.start() + 40].replace("\n", " ")
            hits.append(f"{name}: {snippet.strip()}")

    if not hits:
        return Verdict(EXPECTED, _HTML_RULE, _HTML_VERSION, 0.9, signals=[],
                       code_refs=["AUDIT-001"])

    # More distinct active-content features => higher confidence it's noteworthy.
    confidence = min(0.5 + 0.1 * len(hits), 0.95)
    return Verdict(
        NEEDS_DECISION, _HTML_RULE, _HTML_VERSION, confidence, signals=hits,
        code_refs=["AUDIT-001"],
        suggested_fix=("sanitize report body with an allowlist + move the "
                       "report template's own scripts to nonce/external, then "
                       "drop 'unsafe-inline' for report pages — preserves every "
                       "report feature"),
    )
