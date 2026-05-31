"""Passive safety telemetry: observe stage.

- pure network-target classifier (link-local metadata = dangerous, loopback /
  private / docker = expected, public = needs_decision, junk = unknown);
- pure report-HTML risk scanner (script / event-handler / javascript: / iframe
  / form signals, observe-only -> needs_decision, never blocks);
- a local-only append-only JSONL ledger whose events carry full provenance
  (raw signals, classifier rule + rule version, confidence, code refs) so each
  claim is replayable, and whose recorder is best-effort (never raises into the
  caller's path).

These are pure-stdlib tests by design: the active dev env has no pytest /
sqlalchemy, so the telemetry core stays decoupled from the heavy DB and is
runnable with plain `python tests/test_security_telemetry.py`. They also pass
unchanged under pytest once it is installed.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.security_classifiers import (  # noqa: E402
    EXPECTED,
    NEEDS_DECISION,
    DANGEROUS,
    UNKNOWN,
    classify_network_target,
    scan_report_html,
)


# Network-target classifier

def test_metadata_ip_is_dangerous():
    r = classify_network_target("http://169.254.169.254/latest/meta-data/")
    assert r.classification == DANGEROUS
    assert r.rule == "net-target"
    assert r.rule_version  # carries a version so old events stay interpretable
    assert r.confidence >= 0.9
    assert "link-local" in " ".join(r.signals.values()).lower() or \
        any("metadata" in s.lower() for s in r.signals.values())


def test_loopback_is_expected_trusted_local():
    for url in ("http://localhost:11434/v1", "http://127.0.0.1:8080", "http://[::1]:8000"):
        r = classify_network_target(url)
        assert r.classification == EXPECTED, url
        assert r.confidence >= 0.8


def test_private_lan_is_expected():
    for url in ("http://10.0.0.5:8000", "http://192.168.1.50", "http://172.16.3.4:9000"):
        r = classify_network_target(url)
        assert r.classification == EXPECTED, url


def test_docker_service_name_is_expected():
    # bare hostname, no dot -> internal docker/compose service (searxng, chromadb)
    for url in ("http://searxng:8080/search", "http://chromadb:8000"):
        r = classify_network_target(url)
        assert r.classification == EXPECTED, url
        assert "docker" in r.signals.get("kind", "").lower() or \
            "internal" in r.signals.get("kind", "").lower()


def test_public_host_needs_decision():
    r = classify_network_target("https://api.openai.com/v1/chat/completions")
    assert r.classification == NEEDS_DECISION
    # observe-only: a public egress is worth a human look, never auto-blocked
    assert r.confidence > 0


def test_unparseable_target_is_unknown_not_crash():
    r = classify_network_target("")
    assert r.classification == UNKNOWN
    r2 = classify_network_target("not a url at all ::: ///")
    assert r2.classification in (UNKNOWN, NEEDS_DECISION)


# Report-HTML risk scanner (AUDIT-001 observe-first)

def test_clean_report_has_no_active_signals():
    r = scan_report_html("<h1>Title</h1><p>Body with <a href='https://x'>link</a></p>")
    assert r.classification == EXPECTED
    assert r.signals == [] or r.signals == {} or not r.signals


def test_script_tag_flagged_but_not_blocked():
    r = scan_report_html("<p>ok</p><script>window.__x=1</script>")
    assert r.classification == NEEDS_DECISION  # observe-only, never DANGEROUS auto-block
    assert any("script" in s for s in r.signals)


def test_event_handler_and_js_url_and_iframe_flagged():
    html = '<img src=x onerror="steal()"><a href="javascript:evil()">x</a><iframe src="//e"></iframe>'
    r = scan_report_html(html)
    assert r.classification == NEEDS_DECISION
    joined = " ".join(r.signals)
    assert "onerror" in joined or "event-handler" in joined
    assert "javascript:" in joined
    assert "iframe" in joined


def test_scanner_carries_rule_version_and_codref():
    r = scan_report_html("<script>1</script>")
    assert r.rule == "report-html"
    assert r.rule_version
    assert "AUDIT-001" in r.code_refs


# Local-only provenance ledger

def _fresh_recorder(tmpdir):
    # import fresh so the ledger dir is the tmp one
    sys.modules.pop("src.security_telemetry", None)
    import src.security_telemetry as tel
    tel.set_ledger_dir(tmpdir)
    return tel


def test_record_writes_jsonl_with_provenance():
    with tempfile.TemporaryDirectory() as d:
        tel = _fresh_recorder(d)
        trace_id = tel.record_security_event(
            event_type="network_target",
            source="research.web_fetch",
            target="http://169.254.169.254/",
            route="/api/research/start",
            method="POST",
            user="alice",
            signals={"host": "169.254.169.254"},
            rule="net-target",
            rule_version="v1",
            classification="dangerous",
            confidence=0.95,
            code_refs=["routes/research_routes.py", "AUDIT-004"],
            suggested_fix="admin-gate + observe-first allowlist",
        )
        assert trace_id
        events = tel.read_events()
        assert len(events) == 1
        e = events[0]
        # provenance is replayable: signals + rule + version + confidence + refs
        assert e["trace_id"] == trace_id
        assert e["classification"] == "dangerous"
        assert e["rule_version"] == "v1"
        assert e["confidence"] == 0.95
        assert e["signals"]["host"] == "169.254.169.254"
        assert "AUDIT-004" in e["code_refs"]
        assert e["inputs_hash"].startswith("sha256:")
        assert "ts" in e


def test_recorder_is_best_effort_never_raises():
    with tempfile.TemporaryDirectory() as d:
        tel = _fresh_recorder(d)
        # point the ledger at an impossible path AFTER init; record must swallow
        tel.set_ledger_dir("/proc/nonexistent/cannot/write/here")
        # must not raise even though the write target is unwritable
        out = tel.record_security_event(
            event_type="x", source="y", classification="unknown",
            rule="r", rule_version="v1", confidence=0.0,
        )
        # returns a trace id (or None) but never explodes the caller's request
        assert out is None or isinstance(out, str)


def test_record_verdict_bridges_classifier_to_ledger():
    # This is the exact path the embedding set_endpoint instrumentation uses:
    # classify a target, then record the verdict with call context.
    from src.security_classifiers import classify_network_target
    with tempfile.TemporaryDirectory() as d:
        tel = _fresh_recorder(d)
        tid = tel.record_verdict(
            classify_network_target("http://169.254.169.254/"),
            event_type="network_target",
            source="embedding.set_endpoint",
            target="http://169.254.169.254/",
            route="/api/embeddings/endpoint",
            method="POST",
        )
        assert tid
        ev = tel.read_events()[0]
        assert ev["classification"] == "dangerous"
        assert ev["source"] == "embedding.set_endpoint"
        assert ev["route"] == "/api/embeddings/endpoint"
        assert "AUDIT-004" in ev["code_refs"]   # provenance carried through


def test_summary_counts_by_classification():
    with tempfile.TemporaryDirectory() as d:
        tel = _fresh_recorder(d)
        for cls in ("expected", "expected", "needs_decision", "dangerous", "unknown"):
            tel.record_security_event(
                event_type="t", source="s", classification=cls,
                rule="r", rule_version="v1", confidence=0.5,
            )
        s = tel.summary()
        assert s["expected"] == 2
        assert s["needs_decision"] == 1
        assert s["dangerous"] == 1
        assert s["unknown"] == 1
        assert s["total"] == 5


# Plain-stdlib runner (no pytest in this env)

def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"PASS {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            import traceback
            print(f"FAIL {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
