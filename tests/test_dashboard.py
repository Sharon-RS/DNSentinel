"""
Automated unit and integration tests for the DNSentinel SOC Dashboard.
Validates telemetry ingestion, profile loading, Phase 4 research data integrity,
HTTP endpoints, and cryptographic immutability of live data directories.
"""

import hashlib
import io
import json
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

# Ensure workspace root is in python path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from src.utils.config import Config
from dashboard.adapter import DashboardAdapter, validate_domain
from dashboard.app import DashboardHTTPRequestHandler


def compute_dir_hashes(directory: Path):
    """Computes SHA-256 hashes for all files in a directory."""
    hashes = {}
    if not directory.exists():
        return hashes
    for file_path in sorted(directory.glob("**/*")):
        if file_path.is_file():
            rel_name = str(file_path.relative_to(directory))
            with open(file_path, "rb") as f:
                hashes[rel_name] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def test_adapter_initialization_and_summary():
    """Verify clean initial state of DashboardAdapter."""
    adapter = DashboardAdapter()
    summary = adapter.get_summary()

    assert summary["total_queries"] == 0
    assert summary["normal_count"] == 0
    assert summary["low_risk_count"] == 0
    assert summary["suspicious_count"] == 0
    assert summary["high_risk_count"] == 0
    assert summary["is_demo_replay"] is False
    assert len(adapter.get_live_events()) == 0
    assert len(adapter.get_alerts()) == 0

    print("[PASS] test_adapter_initialization_and_summary passed.")


def test_adapter_ingestion_and_alerts():
    """Verify ingestion updates ring buffer and alerts triage queue appropriately."""
    adapter = DashboardAdapter()

    # Normal observation
    ev1 = {"source_ip": "10.0.0.1", "domain": "google.com", "query_type": 1, "timestamp": "2026-10-03T12:00:00"}
    feat1 = {"entropy": 2.5, "domain_length": 10, "query_rate": 0.5}
    res1 = {"behavior_score": 0.0, "risk_level": "NORMAL", "confidence": 0.90, "baseline_updated": True}
    adapter.ingest_processed_event(ev1, feat1, res1)

    # Suspicious observation
    ev2 = {"source_ip": "10.0.0.1", "domain": "weird12345.tunnel.org", "query_type": 1, "timestamp": "2026-10-03T12:00:01"}
    feat2 = {"entropy": 4.8, "domain_length": 32, "query_rate": 5.0}
    res2 = {"behavior_score": 58.5, "risk_level": "SUSPICIOUS", "confidence": 0.85, "baseline_updated": False}
    adapter.ingest_processed_event(ev2, feat2, res2)

    # High Risk observation
    ev3 = {"source_ip": "10.0.0.2", "domain": "evil99999.tunnel.biz", "query_type": 16, "timestamp": "2026-10-03T12:00:02"}
    feat3 = {"entropy": 5.2, "domain_length": 45, "query_rate": 15.0}
    res3 = {"behavior_score": 82.0, "risk_level": "HIGH_RISK", "confidence": 0.95, "baseline_updated": False}
    adapter.ingest_processed_event(ev3, feat3, res3)

    summary = adapter.get_summary()
    assert summary["total_queries"] == 3
    assert summary["normal_count"] == 1
    assert summary["suspicious_count"] == 1
    assert summary["high_risk_count"] == 1

    alerts = adapter.get_alerts()
    assert len(alerts) == 2, f"Expected 2 alerts, got {len(alerts)}"
    assert alerts[0]["risk_level"] == "HIGH_RISK"
    assert alerts[1]["risk_level"] == "SUSPICIOUS"

    print("[PASS] test_adapter_ingestion_and_alerts passed.")


def test_baseline_status_metadata_distinction():
    """
    Verify explicit baseline status metadata distinguishing:
    1. Learned: baseline was updated.
    2. Calibrating: observation is provisionally buffered and awaiting calibration.
    3. Quarantined: the host was explicitly quarantined by the pipeline.
    4. Not Updated: baseline was not updated (including NORMAL, SUSPICIOUS, HIGH_RISK).
    """
    adapter = DashboardAdapter()

    # 1. Learned: baseline was updated
    ev1 = {"source_ip": "10.0.0.1", "domain": "google.com", "query_type": 1}
    feat1 = {"entropy": 2.5, "domain_length": 10}
    res1 = {"behavior_score": 0.0, "risk_level": "NORMAL", "baseline_updated": True}
    rec1 = adapter.ingest_processed_event(ev1, feat1, res1)
    assert rec1["baseline_status"] == "Learned"
    assert rec1["baseline_updated"] is True
    assert rec1["provisional_held"] is False
    assert rec1["quarantined"] is False

    # 2. Calibrating: observation is provisionally buffered awaiting calibration
    ev2 = {"source_ip": "10.0.0.5", "domain": "newhost.org", "query_type": 1}
    feat2 = {"entropy": 2.8, "domain_length": 11}
    res2 = {
        "behavior_score": 5.0,
        "risk_level": "NORMAL",
        "baseline_updated": False,
        "provisional_held": True,
        "lifecycle_state": "COLD_START_CALIBRATION"
    }
    rec2 = adapter.ingest_processed_event(ev2, feat2, res2)
    assert rec2["baseline_status"] == "Calibrating"
    assert rec2["baseline_updated"] is False
    assert rec2["provisional_held"] is True
    assert rec2["quarantined"] is False

    # 3. Quarantined: host was explicitly quarantined
    ev3 = {"source_ip": "10.0.0.9", "domain": "victim.org", "query_type": 1}
    feat3 = {"entropy": 3.0, "domain_length": 10}
    res3 = {
        "behavior_score": 10.0,
        "risk_level": "NORMAL",
        "baseline_updated": False,
        "calibration_quarantined": True,
        "lifecycle_state": "STEADY_STATE"
    }
    rec3 = adapter.ingest_processed_event(ev3, feat3, res3)
    assert rec3["baseline_status"] == "Quarantined"
    assert rec3["baseline_updated"] is False
    assert rec3["quarantined"] is True
    assert rec3["calibration_quarantined"] is True

    # 4. Not Updated: baseline was not updated, but host is NOT quarantined
    # 4a. NORMAL query whose baseline was not updated
    ev4_norm = {"source_ip": "10.0.0.1", "domain": "normal-uncommitted.org", "query_type": 1}
    feat4_norm = {"entropy": 2.6, "domain_length": 22}
    res4_norm = {
        "behavior_score": 12.0,
        "risk_level": "NORMAL",
        "baseline_updated": False,
        "provisional_held": False,
        "calibration_quarantined": False
    }
    rec4_norm = adapter.ingest_processed_event(ev4_norm, feat4_norm, res4_norm)
    assert rec4_norm["baseline_status"] == "Not Updated"
    assert rec4_norm["risk_level"] == "NORMAL"
    assert rec4_norm["baseline_updated"] is False
    assert rec4_norm["provisional_held"] is False
    assert rec4_norm["quarantined"] is False

    # 4b. SUSPICIOUS query whose baseline was not updated
    ev4_susp = {"source_ip": "10.0.0.1", "domain": "suspicious-domain.org", "query_type": 1}
    feat4_susp = {"entropy": 4.5, "domain_length": 30}
    res4_susp = {
        "behavior_score": 55.0,
        "risk_level": "SUSPICIOUS",
        "baseline_updated": False
    }
    rec4_susp = adapter.ingest_processed_event(ev4_susp, feat4_susp, res4_susp)
    assert rec4_susp["baseline_status"] == "Not Updated"
    assert rec4_susp["baseline_updated"] is False

    # 4c. HIGH_RISK query whose baseline was not updated
    ev4_high = {"source_ip": "10.0.0.1", "domain": "exfiltration.evil.com", "query_type": 1}
    feat4_high = {"entropy": 5.1, "domain_length": 45}
    res4_high = {
        "behavior_score": 75.0,
        "risk_level": "HIGH_RISK",
        "baseline_updated": False
    }
    rec4_high = adapter.ingest_processed_event(ev4_high, feat4_high, res4_high)
    assert rec4_high["baseline_status"] == "Not Updated"
    assert rec4_high["baseline_updated"] is False

    # 5. Direct explicit override test
    res5 = {"baseline_updated": False, "baseline_status": "Calibrating"}
    rec5 = adapter.ingest_processed_event(ev2, feat2, res5)
    assert rec5["baseline_status"] == "Calibrating"

    # 6. Verify app.js distinguishes all 4 statuses
    app_js_path = Config.PROJECT_ROOT / "dashboard" / "static" / "app.js"
    assert app_js_path.exists()
    app_js_content = app_js_path.read_text(encoding="utf-8")
    assert "Learned" in app_js_content
    assert "Calibrating" in app_js_content
    assert "Quarantined" in app_js_content
    assert "Not Updated" in app_js_content

    print("[PASS] test_baseline_status_metadata_distinction passed.")


def test_detection_method_telemetry_and_ui_distinction():
    """
    Verify Detection Method column and cascade telemetry distinction:
    1. ML-escalated malicious records (cascade_path="ML_ESCALATED", cascade_decision="MALICIOUS", ml_probability finite).
    2. Fast-path records with no ML probability (cascade_path="FAST_PATH_BENIGN", cascade_decision="BENIGN", ml_probability=None).
    3. Records without cascade metadata (Heuristic only, ml_probability=None).
    4. Missing or invalid probabilities (string, nan, inf, None safely handled without errors).
    5. HTML table headers for Live Monitor and Alert View contain 'Detection Method' and distinction tooltips/footnotes.
    6. JavaScript app.js contains formatDetectionMethod, 'Heuristic only', 'N/A', and safe formatting.
    """
    adapter = DashboardAdapter()

    # 1. ML-escalated malicious record
    ev1 = {"source_ip": "10.0.0.1", "domain": "exfiltrate.tunnel.attacker.lab", "query_type": 1}
    feat1 = {"entropy": 4.8, "domain_length": 35, "query_rate": 1.2}
    res1 = {
        "behavior_score": 45.3,
        "risk_level": "HIGH_RISK",
        "confidence": 0.88,
        "baseline_updated": False,
        "ml_enabled": True,
        "cascade_path": "ML_ESCALATED",
        "cascade_decision": "MALICIOUS",
        "ml_probability": 0.3748
    }
    rec1 = adapter.ingest_processed_event(ev1, feat1, res1)
    assert rec1["cascade_path"] == "ML_ESCALATED"
    assert rec1["cascade_decision"] == "MALICIOUS"
    assert rec1["ml_probability"] == 0.3748
    assert rec1["ml_enabled"] is True
    assert rec1["behavior_score"] == 45.3
    assert rec1["risk_level"] == "HIGH_RISK"
    # Alerts buffer should also capture this HIGH_RISK record
    alerts = adapter.get_alerts()
    assert len(alerts) >= 1
    assert alerts[-1]["cascade_path"] == "ML_ESCALATED"
    assert alerts[-1]["cascade_decision"] == "MALICIOUS"
    assert alerts[-1]["ml_probability"] == 0.3748

    # 2. Fast-path record with no ML probability
    ev2 = {"source_ip": "10.0.0.2", "domain": "legit.example.org", "query_type": 1}
    feat2 = {"entropy": 2.2, "domain_length": 12, "query_rate": 0.5}
    res2 = {
        "behavior_score": 8.5,
        "risk_level": "NORMAL",
        "confidence": 0.95,
        "baseline_updated": True,
        "ml_enabled": True,
        "cascade_path": "FAST_PATH_BENIGN",
        "cascade_decision": "BENIGN",
        "ml_probability": None
    }
    rec2 = adapter.ingest_processed_event(ev2, feat2, res2)
    assert rec2["cascade_path"] == "FAST_PATH_BENIGN"
    assert rec2["cascade_decision"] == "BENIGN"
    assert rec2["ml_probability"] is None
    assert rec2["ml_enabled"] is True

    # 3. Record without cascade metadata (Heuristic only)
    ev3 = {"source_ip": "10.0.0.3", "domain": "local.internal.corp", "query_type": 1}
    feat3 = {"entropy": 2.5, "domain_length": 15, "query_rate": 0.1}
    res3 = {
        "behavior_score": 5.0,
        "risk_level": "NORMAL",
        "confidence": 0.90,
        "baseline_updated": True
    }
    rec3 = adapter.ingest_processed_event(ev3, feat3, res3)
    assert rec3["cascade_path"] is None
    assert rec3["cascade_decision"] is None
    assert rec3["ml_probability"] is None
    assert rec3["ml_enabled"] is False

    # 4. Missing or invalid probabilities
    # 4a. String non-numeric probability
    ev4a = {"source_ip": "10.0.0.4", "domain": "invalid-prob.tunnel.lab", "query_type": 1}
    feat4a = {"entropy": 4.1, "domain_length": 25, "query_rate": 1.0}
    res4a = {
        "behavior_score": 55.0,
        "risk_level": "SUSPICIOUS",
        "cascade_path": "ML_ESCALATED",
        "cascade_decision": "MALICIOUS",
        "ml_probability": "not-a-number"
    }
    rec4a = adapter.ingest_processed_event(ev4a, feat4a, res4a)
    assert rec4a["cascade_path"] == "ML_ESCALATED"
    assert rec4a["cascade_decision"] == "MALICIOUS"
    assert rec4a["ml_probability"] is None

    # 4b. NaN / Inf probability
    res4b = {
        "behavior_score": 60.0,
        "risk_level": "SUSPICIOUS",
        "cascade_path": "ML_ESCALATED",
        "cascade_decision": "MALICIOUS",
        "ml_probability": float("nan")
    }
    rec4b = adapter.ingest_processed_event(ev4a, feat4a, res4b)
    assert rec4b["ml_probability"] is None

    res4c = {
        "behavior_score": 60.0,
        "risk_level": "SUSPICIOUS",
        "cascade_path": "ML_ESCALATED",
        "cascade_decision": "MALICIOUS",
        "ml_probability": float("inf")
    }
    rec4c = adapter.ingest_processed_event(ev4a, feat4a, res4c)
    assert rec4c["ml_probability"] is None

    # 5. Verify index.html contains Detection Method column headers and distinction tooltips/footnotes
    html_path = Config.PROJECT_ROOT / "dashboard" / "static" / "index.html"
    assert html_path.exists()
    html_content = html_path.read_text(encoding="utf-8")
    assert "Detection Method" in html_content
    # Check both table headers
    assert "table-live-events" in html_content
    assert "table-alerts" in html_content
    # Check explanatory note on behavioral score and cascade risk level being different signals
    assert "Behavioral score and final cascade risk level are different signals" in html_content

    # 6. Verify app.js contains formatDetectionMethod, 'Heuristic only', 'N/A', and safe formatters
    app_js_path = Config.PROJECT_ROOT / "dashboard" / "static" / "app.js"
    assert app_js_path.exists()
    app_js = app_js_path.read_text(encoding="utf-8")
    assert "formatDetectionMethod" in app_js
    assert "Heuristic only" in app_js
    assert "N/A" in app_js
    assert "formatNumber" in app_js
    assert "formatPercent" in app_js
    assert "escapeHtml" in app_js
    assert "detection-method-cell" in app_js

    # 7. Verify CSS contains detection-method-cell class
    css_path = Config.PROJECT_ROOT / "dashboard" / "static" / "style.css"
    assert css_path.exists()
    css_content = css_path.read_text(encoding="utf-8")
    assert ".detection-method-cell" in css_content

    print("[PASS] test_detection_method_telemetry_and_ui_distinction passed.")


def test_host_and_organization_baselines_loading():
    """Verify reading host profiles and enterprise organization profile from disk."""
    adapter = DashboardAdapter()
    hosts = adapter.get_monitored_hosts_list()
    assert len(hosts) > 0, "Expected at least one monitored host in data/profiles/"

    for host_ip in hosts:
        details = adapter.get_host_profile_details(host_ip)
        assert details is not None
        assert "average_entropy" in details
        assert "average_domain_length" in details
        assert "total_queries" in details

    org = adapter.get_organization_profile_details()
    assert "status" in org
    assert "total_queries" in org

    print("[PASS] test_host_and_organization_baselines_loading passed.")


def test_phase4_research_data_integrity():
    """Verify research results match exact verified TunnelEye reproduction metrics."""
    adapter = DashboardAdapter()
    res = adapter.get_research_results()

    te = res["tunneleye_baseline"]
    assert te["latency"] == "Latency unavailable under identical streaming hardware conditions"
    assert "External verified reproduction baseline" in te["system"]

    # Verify all 4 dataset splits are present with exact metrics
    expected_splits = {
        "CIC-FWD": 0.9987240888,
        "CIC-BWD": 0.9971739576,
        "DoH-Extended-FWD": 0.9996498212,
        "DoH-Extended-BWD": 0.9994861631
    }

    found_splits = {}
    for ds in te["datasets"]:
        found_splits[ds["split_id"]] = ds["accuracy"]

    for split_id, expected_acc in expected_splits.items():
        assert split_id in found_splits, f"Missing split {split_id}"
        assert abs(found_splits[split_id] - expected_acc) < 1e-9, f"Mismatch in {split_id}: {found_splits[split_id]} vs {expected_acc}"

    # Verify Macro Average
    macro = te["macro_average"]
    assert abs(macro["accuracy"] - 0.9987585077) < 1e-9

    # Verify Cold-Start and Ablation data present
    assert len(res["cold_start_ab"]) > 0
    assert len(res["ablation_study"]) > 0

    print("[PASS] test_phase4_research_data_integrity passed.")


def test_demo_replay_and_live_data_immutability():
    """Verify that Demo Replay operates in isolation and leaves live profiles 100% untouched."""
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"
    experiments_results_dir = Config.PROJECT_ROOT / "experiments" / "results"

    # Capture pre-replay cryptographic hashes
    pre_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    pre_org_hashes = compute_dir_hashes(live_org_dir)
    pre_results_hashes = compute_dir_hashes(experiments_results_dir)

    adapter = DashboardAdapter()

    # 1. Research Replay (Unmitigated Cold Start): Must reproduce documented Phase 2 result
    rep1 = adapter.replay_dataset("benign", max_records=200)
    assert rep1["status"] == "success"
    assert rep1["mode"] == "RESEARCH REPLAY — UNMITIGATED COLD START"
    assert adapter.is_demo_replay is True

    summary1 = adapter.get_summary()
    assert summary1["total_queries"] == 119
    assert summary1["suspicious_count"] == 19
    assert summary1["high_risk_count"] == 2
    assert summary1["normal_count"] == 92
    assert summary1["low_risk_count"] == 6
    assert summary1["replay_mode"] == "RESEARCH REPLAY — UNMITIGATED COLD START"

    # 2. Mature Organization Replay: Pre-seeded isolated sandbox with enterprise_org_baseline.json
    adapter.clear_session()
    assert adapter.is_demo_replay is False

    rep_mature = adapter.replay_dataset("benign_mature", max_records=200)
    assert rep_mature["status"] == "success"
    assert rep_mature["mode"] == "ADAPTIVE BASELINE DEMO — MATURE ORGANIZATION"
    assert adapter.is_demo_replay is True

    summary_mature = adapter.get_summary()
    assert summary_mature["total_queries"] == 119
    assert summary_mature["normal_count"] == 96
    assert summary_mature["replay_mode"] == "ADAPTIVE BASELINE DEMO — MATURE ORGANIZATION"

    # 3. Tunnel burst attack replay
    adapter.clear_session()
    rep2 = adapter.replay_dataset("tunnel", max_records=20)
    assert rep2["status"] == "success"
    assert rep2["mode"] == "DEMO REPLAY — NOT LIVE TRAFFIC"

    # 4. Custom query submission
    rep3 = adapter.process_test_query("10.0.0.1", "sample73829.tunnel.attacker.lab", 1)
    assert rep3["status"] == "success"

    # Capture post-replay cryptographic hashes
    post_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    post_org_hashes = compute_dir_hashes(live_org_dir)
    post_results_hashes = compute_dir_hashes(experiments_results_dir)

    # Assert 100% bitwise identity across all live baselines and results
    assert pre_profiles_hashes == post_profiles_hashes, "Live data/profiles/ was modified during demo replay!"
    assert pre_org_hashes == post_org_hashes, "Live data/organization/ was modified during demo replay!"
    assert pre_results_hashes == post_results_hashes, "experiments/results/ was modified during demo replay!"

    print("[PASS] test_demo_replay_and_live_data_immutability passed (both modes verified, 100% bitwise immutable).")


def test_process_test_query_enterprise_baseline_loading_and_isolation():
    """
    Verify that process_test_query loads the enterprise organization baseline into
    the isolated sandbox, evaluates cold hosts against enterprise priors, and leaves
    production baselines (data/organization, data/profiles) 100% bitwise immutable.
    """
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"
    experiments_results_dir = Config.PROJECT_ROOT / "experiments" / "results"

    pre_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    pre_org_hashes = compute_dir_hashes(live_org_dir)
    pre_results_hashes = compute_dir_hashes(experiments_results_dir)

    adapter = DashboardAdapter()

    # 1. Heuristic mode (Pipeline B) with novel tunneling domain on a cold-start host
    adapter.set_pipeline_mode("heuristic")
    rep_novel = adapter.process_test_query("10.88.88.88", "exfiltrate.tunnel.attacker.lab", 1)
    assert rep_novel["status"] == "success"
    assert rep_novel["mode"] == "LIVE HEURISTIC — PIPELINE B"
    rec_novel = rep_novel["record"]

    # Verify enterprise organization baseline was loaded:
    # Novel domain on cold-start host falls back to enterprise mature prior
    assert rec_novel["organization_rarity_score"] == 1.0, f"Expected rarity 1.0, got {rec_novel['organization_rarity_score']}"
    assert rec_novel["domain_length_deviation"] > 0.0, f"Expected domain length deviation > 0, got {rec_novel['domain_length_deviation']}"
    assert rec_novel["entropy_deviation"] > 0.0, f"Expected entropy deviation > 0, got {rec_novel['entropy_deviation']}"
    assert rec_novel["behavior_score"] > 30.0, f"Expected behavior score > 30, got {rec_novel['behavior_score']}"
    assert rec_novel["provisional_held"] is True
    assert rec_novel["baseline_status"] == "Calibrating"

    # 2. Heuristic mode with enterprise-known benign domain (google.com) on a cold-start host
    rep_benign = adapter.process_test_query("10.88.88.88", "google.com", 1)
    rec_benign = rep_benign["record"]
    assert rec_benign["organization_rarity_score"] == 0.0, f"Expected rarity 0.0, got {rec_benign['organization_rarity_score']}"
    assert rec_benign["behavior_score"] < 15.0, f"Expected benign behavior score < 15, got {rec_benign['behavior_score']}"

    # 3. Cascade mode (Pipeline ML30) with novel tunneling domain on a cold-start host
    adapter.set_pipeline_mode("cascade")
    rep_cascade = adapter.process_test_query("10.88.88.88", "exfiltrate.tunnel.attacker.lab", 1)
    assert rep_cascade["status"] == "success"
    assert rep_cascade["mode"] == "LIVE TIERED CASCADE — ML30"
    rec_cascade = rep_cascade["record"]
    assert rec_cascade["ml_enabled"] is True
    assert rec_cascade["organization_rarity_score"] == 1.0
    assert rec_cascade["cascade_path"] == "ML_ESCALATED"
    assert rec_cascade["risk_level"] in ("HIGH_RISK", "SUSPICIOUS")

    # Restore default pipeline mode
    adapter.set_pipeline_mode("heuristic")

    # 4. Assert 100% cryptographic immutability of live data directories
    post_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    post_org_hashes = compute_dir_hashes(live_org_dir)
    post_results_hashes = compute_dir_hashes(experiments_results_dir)

    assert pre_profiles_hashes == post_profiles_hashes, "Live data/profiles/ was modified by process_test_query!"
    assert pre_org_hashes == post_org_hashes, "Live data/organization/ was modified by process_test_query!"
    assert pre_results_hashes == post_results_hashes, "experiments/results/ was modified by process_test_query!"

    print("[PASS] test_process_test_query_enterprise_baseline_loading_and_isolation passed.")


def test_custom_domain_input_validation():
    """
    Verify input validation for custom domain tests:
    - Rejects terminal text, whitespace, URLs, invalid characters, malformed labels, excessive lengths.
    - Accepts valid ordinary and lab domains: stackoverflow.com, google.com, attacker.lab, evil7382.tunnel.attacker.lab.
    - Ensures malformed input never executes feature extraction or detection pipeline, nor creates alerts.
    - Preserves bitwise immutability of live data directories.
    """
    # 1. Direct validation helper tests - Valid domains
    valid_domains = [
        "stackoverflow.com",
        "google.com",
        "evil7382.tunnel.attacker.lab",
        "attacker.lab",
        "google.com.",
        "SUB-domain.example.co.uk",
        "a.b.c.d.com",
        "x" * 63 + ".com",
        "a." * 120 + "example.com",
    ]
    for d in valid_domains:
        is_val, err = validate_domain(d)
        assert is_val is True, f"Expected '{d}' to be valid, got error: {err}"
        assert err is None

    # Exact 253 characters domain (63 + 1 + 63 + 1 + 63 + 1 + 58 + 1 + 2 = 253)
    dom_253 = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 58 + ".co"
    assert len(dom_253) == 253
    is_val, err = validate_domain(dom_253)
    assert is_val is True, f"Expected 253-char domain to be valid, got: {err}"

    # Invalid domains
    invalid_domains = [
        ("", "Empty domain"),
        ("   ", "Whitespace only"),
        (None, "None value"),
        ("google .com", "Whitespace inside domain"),
        ("google\t.com", "Tab inside domain"),
        ("evil tunnel.attacker.lab", "Space inside domain"),
        ("attacker.lab\n", "Newline inside domain"),
        ("cat /etc/passwd", "Terminal text"),
        ("sharon@kali:~$ ./run.sh", "Terminal text"),
        ("rm -rf /", "Terminal text"),
        ("ls -la; id", "Terminal text"),
        ("curl http://evil.com", "Terminal text"),
        ("whoami", "Single label terminal command"),
        ("http://google.com", "URL scheme"),
        ("https://evil.com/path", "URL scheme and path"),
        ("google.com/search?q=test", "URL path and query"),
        ("attacker.lab#fragment", "URL fragment"),
        ("ftp://foo.bar", "FTP scheme"),
        ("google.com:8080", "Port separator"),
        ("attacker.lab\\test", "Backslash"),
        ("google..com", "Empty label"),
        (".google.com", "Leading dot / empty label"),
        ("google...com", "Multiple dots"),
        ("-google.com", "Label starting with hyphen"),
        ("google-.com", "Label ending with hyphen"),
        ("bad.-label.com", "Inner label starting with hyphen"),
        ("bad.label-.com", "Inner label ending with hyphen"),
        ("google_site.com", "Underscore in label"),
        ("foo@bar.com", "At sign"),
        ("test$domain.com", "Dollar sign"),
        ("a" * 64 + ".com", "Label exceeds 63 chars"),
        ("sub." + "b" * 64 + ".com", "Subdomain label exceeds 63 chars"),
        ("a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 59 + ".co", "Domain exceeds 253 chars"),
        ("localhost", "Single label"),
        ("attacker", "Single label"),
        ("192.168.1.1", "Numeric TLD / IPv4"),
        ("example.123", "Numeric TLD"),
        ("göögle.com", "Non-ASCII characters"),
    ]

    for d, desc in invalid_domains:
        is_val, err = validate_domain(d)
        assert is_val is False, f"Expected '{d}' ({desc}) to be rejected, but it passed!"
        assert err is not None, f"Expected error message for '{d}' ({desc})"

    # 2. Pipeline isolation and alert protection
    adapter = DashboardAdapter()
    init_total_queries = adapter.get_summary()["total_queries"]
    init_alerts_count = len(adapter.get_alerts())
    init_events_count = len(adapter.get_live_events())

    malformed_tests = [
        "cat /etc/passwd",
        "http://attacker.lab/payload",
        "-malformed.lab",
        "bad label.attacker.lab",
        "a" * 64 + ".lab",
    ]
    for bad_dom in malformed_tests:
        res = adapter.process_test_query("10.0.0.1", bad_dom)
        assert "error" in res, f"Expected error for '{bad_dom}', got: {res}"
        assert res.get("status") != "success"

    # Verify that detector NEVER ran and no events or alerts were created
    post_total_queries = adapter.get_summary()["total_queries"]
    post_alerts_count = len(adapter.get_alerts())
    post_events_count = len(adapter.get_live_events())

    assert post_total_queries == init_total_queries, "Invalid domains must not increment query count!"
    assert post_alerts_count == init_alerts_count, "Invalid domains must not generate alerts!"
    assert post_events_count == init_events_count, "Invalid domains must not append to live events!"

    # 3. Valid domains process successfully
    res_valid = adapter.process_test_query("10.0.0.1", "evil7382.tunnel.attacker.lab")
    assert res_valid["status"] == "success"
    assert "record" in res_valid

    # 4. Frontend logic verification (ensure input preservation and alert on failure)
    app_js_path = Config.PROJECT_ROOT / "dashboard" / "static" / "app.js"
    assert app_js_path.exists()
    with open(app_js_path, "r", encoding="utf-8") as f:
        app_js_content = f.read()

    assert "submitCustomTest" in app_js_content
    assert "data.error" in app_js_content
    assert "alert(errMsg)" in app_js_content

    print("[PASS] test_custom_domain_input_validation passed.")


def test_alert_view_consistency_and_queue_isolation():
    """
    Regression test verifying:
    1. Alert View displays actual dynamic baseline status rather than hardcoded quarantine status.
    2. NORMAL and LOW_RISK events are excluded from the alert queue but remain available in the live event stream.
    3. The same event has identical behavior_score, risk_level, domain, and host in both API responses when present in both.
    4. Button for replaying tunnel burst attack is clearly labeled as Pipeline A1 / Unmitigated Cold Start.
    """
    # 1. Frontend source verification: app.js must not contain hardcoded 'Quarantined (0 Drift)'
    app_js_path = Config.PROJECT_ROOT / "dashboard" / "static" / "app.js"
    assert app_js_path.exists()
    app_js = app_js_path.read_text(encoding="utf-8")
    assert "Quarantined (0 Drift)" not in app_js, "Alert View must not contain hardcoded 'Quarantined (0 Drift)' badge!"
    assert "formatBaselineStatus(al)" in app_js, "Alert View must use formatBaselineStatus(al) for dynamic baseline status!"

    # 2. Verify index.html clearly labels Replay Tunnel Burst as Pipeline A1 / unmitigated cold start
    html_path = Config.PROJECT_ROOT / "dashboard" / "static" / "index.html"
    assert html_path.exists()
    html_content = html_path.read_text(encoding="utf-8")
    assert "Pipeline A1" in html_content, "Replay Tunnel Burst action must be clearly labeled as Pipeline A1"
    assert "Unmitigated Cold Start" in html_content, "Replay Tunnel Burst action must be clearly labeled as Unmitigated Cold Start"

    # 3. Adapter isolation and queue filtering test
    adapter = DashboardAdapter()

    ev_norm = {"source_ip": "10.0.0.1", "domain": "benign.normal.org", "query_type": 1}
    feat_norm = {"entropy": 2.1, "domain_length": 14, "query_rate": 0.5}
    res_norm = {
        "behavior_score": 10.5,
        "risk_level": "NORMAL",
        "confidence": 0.90,
        "baseline_updated": True,
        "baseline_status": "Learned"
    }

    ev_low = {"source_ip": "10.0.0.2", "domain": "monitor.lowrisk.org", "query_type": 1}
    feat_low = {"entropy": 3.2, "domain_length": 20, "query_rate": 1.2}
    res_low = {
        "behavior_score": 38.0,
        "risk_level": "LOW_RISK",
        "confidence": 0.70,
        "baseline_updated": True,
        "baseline_status": "Learned"
    }

    ev_susp = {"source_ip": "10.0.0.3", "domain": "novel.tunnel.suspicious.lab", "query_type": 1}
    feat_susp = {"entropy": 4.5, "domain_length": 32, "query_rate": 2.5}
    res_susp = {
        "behavior_score": 54.5,
        "risk_level": "SUSPICIOUS",
        "confidence": 0.85,
        "baseline_updated": False,
        "baseline_status": "Calibrating",
        "provisional_held": True
    }

    ev_high = {"source_ip": "10.0.0.4", "domain": "exfil.burst.highrisk.lab", "query_type": 1}
    feat_high = {"entropy": 4.9, "domain_length": 45, "query_rate": 8.0}
    res_high = {
        "behavior_score": 88.0,
        "risk_level": "HIGH_RISK",
        "confidence": 0.95,
        "baseline_updated": False,
        "baseline_status": "Quarantined",
        "quarantined": True
    }

    rec_norm = adapter.ingest_processed_event(ev_norm, feat_norm, res_norm)
    rec_low = adapter.ingest_processed_event(ev_low, feat_low, res_low)
    rec_susp = adapter.ingest_processed_event(ev_susp, feat_susp, res_susp)
    rec_high = adapter.ingest_processed_event(ev_high, feat_high, res_high)

    live_events = adapter.get_live_events(limit=10)
    alerts = adapter.get_alerts(limit=10)

    # Live events contains all 4 events
    live_ids = [e["id"] for e in live_events]
    assert rec_norm["id"] in live_ids, "NORMAL event must be in live event stream"
    assert rec_low["id"] in live_ids, "LOW_RISK event must be in live event stream"
    assert rec_susp["id"] in live_ids, "SUSPICIOUS event must be in live event stream"
    assert rec_high["id"] in live_ids, "HIGH_RISK event must be in live event stream"

    # Alerts queue contains ONLY SUSPICIOUS and HIGH_RISK events
    alert_ids = [a["id"] for a in alerts]
    assert rec_norm["id"] not in alert_ids, "NORMAL event must NOT be in alert queue"
    assert rec_low["id"] not in alert_ids, "LOW_RISK event must NOT be in alert queue"
    assert rec_susp["id"] in alert_ids, "SUSPICIOUS event must be in alert queue"
    assert rec_high["id"] in alert_ids, "HIGH_RISK event must be in alert queue"
    assert len(alerts) == 2, f"Expected exactly 2 alerts, got {len(alerts)}"

    # 4. Consistency: Verify the same event has the exact same behavior_score and risk_level in both
    for alert in alerts:
        matching_live = next((e for e in live_events if e["id"] == alert["id"]), None)
        assert matching_live is not None, f"Alert ID {alert['id']} missing from live stream"
        assert alert["behavior_score"] == matching_live["behavior_score"], "behavior_score mismatch between alert and live views!"
        assert alert["risk_level"] == matching_live["risk_level"], "risk_level mismatch between alert and live views!"
        assert alert["domain"] == matching_live["domain"], "domain mismatch between alert and live views!"
        assert alert["host"] == matching_live["host"], "host mismatch between alert and live views!"
        assert alert["baseline_status"] == matching_live["baseline_status"], "baseline_status mismatch between alert and live views!"

    # Verify dynamic baseline status on alert records (not hardcoded to Quarantined)
    alert_susp = next(a for a in alerts if a["id"] == rec_susp["id"])
    assert alert_susp["baseline_status"] == "Calibrating", f"Expected 'Calibrating', got {alert_susp['baseline_status']}"
    alert_high = next(a for a in alerts if a["id"] == rec_high["id"])
    assert alert_high["baseline_status"] == "Quarantined", f"Expected 'Quarantined', got {alert_high['baseline_status']}"

    print("[PASS] test_alert_view_consistency_and_queue_isolation passed.")


def test_tunnel_replay_toolbar_buttons_and_modes():
    """
    Regression test for the replay toolbar:
    1. index.html contains distinct, accessible buttons for Pipeline A1, Pipeline B, and ML30 Cascade.
    2. Tooltips and labels clearly distinguish each pipeline without hardcoding recall claims.
    3. app.js binds event listeners that invoke triggerReplay with 'tunnel', 'tunnel_b', and 'tunnel_cascade'.
    4. triggerReplay updates the respective button state during replay execution.
    5. Adapter replay produces the corresponding replay_mode banner and detection telemetry for all 3 modes.
    6. Verifies that running all three replay modes leaves live profiles, baselines, and results 100% untouched.
    """
    html_path = Config.PROJECT_ROOT / "dashboard" / "static" / "index.html"
    assert html_path.exists()
    html_content = html_path.read_text(encoding="utf-8")

    # Verify Pipeline A1 button is preserved
    assert 'id="btn-replay-tunnel"' in html_content
    assert "Pipeline A1" in html_content
    assert "Unmitigated Cold Start" in html_content

    # Verify Pipeline B button exists
    assert 'id="btn-replay-tunnel-b"' in html_content
    assert "Pipeline B" in html_content
    assert "Heuristic" in html_content

    # Verify ML30 Cascade button exists
    assert 'id="btn-replay-tunnel-cascade"' in html_content
    assert "ML30 Cascade" in html_content

    # Verify distinct labels and tooltips
    assert 'title="DEMO REPLAY — PIPELINE A1 / UNMITIGATED COLD START (lab_trace_tunnel_burst.jsonl, 115 Queries)"' in html_content
    assert 'title="RESEARCH REPLAY — PIPELINE B (ENTERPRISE PRIOR: lab_trace_tunnel_burst.jsonl, 115 Queries)"' in html_content
    assert 'title="LIVE TIERED CASCADE — ML30 (RANDOM FOREST: lab_trace_tunnel_burst.jsonl, 115 Queries)"' in html_content

    # Verify app.js element bindings and event listeners
    app_js_path = Config.PROJECT_ROOT / "dashboard" / "static" / "app.js"
    assert app_js_path.exists()
    app_js = app_js_path.read_text(encoding="utf-8")

    assert "btnReplayTunnel: document.getElementById('btn-replay-tunnel')" in app_js
    assert "btnReplayTunnelB: document.getElementById('btn-replay-tunnel-b')" in app_js
    assert "btnReplayTunnelCascade: document.getElementById('btn-replay-tunnel-cascade')" in app_js

    assert "triggerReplay('tunnel')" in app_js
    assert "triggerReplay('tunnel_b')" in app_js
    assert "triggerReplay('tunnel_cascade')" in app_js

    # Verify button state management in triggerReplay
    assert "traceType === 'tunnel_b'" in app_js
    assert "traceType === 'tunnel_cascade'" in app_js

    # Verify backend replay modes and immutability
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"
    experiments_results_dir = Config.PROJECT_ROOT / "experiments" / "results"

    pre_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    pre_org_hashes = compute_dir_hashes(live_org_dir)
    pre_results_hashes = compute_dir_hashes(experiments_results_dir)

    adapter = DashboardAdapter()

    # Mode 1: Pipeline A1 (tunnel)
    res_a1 = adapter.replay_dataset("tunnel", max_records=20)
    assert res_a1["status"] == "success"
    assert res_a1["mode"] == "DEMO REPLAY — NOT LIVE TRAFFIC"
    summary_a1 = adapter.get_summary()
    assert summary_a1["is_demo_replay"] is True
    assert summary_a1["replay_mode"] == "DEMO REPLAY — NOT LIVE TRAFFIC"
    events_a1 = adapter.get_live_events(limit=5)
    assert len(events_a1) > 0
    # A1 is heuristic-only
    assert events_a1[0]["cascade_path"] is None

    # Mode 2: Pipeline B (tunnel_b)
    adapter.clear_session()
    res_b = adapter.replay_dataset("tunnel_b", max_records=20)
    assert res_b["status"] == "success"
    assert res_b["mode"] == "RESEARCH REPLAY — PIPELINE B (ENTERPRISE PRIOR)"
    summary_b = adapter.get_summary()
    assert summary_b["is_demo_replay"] is True
    assert summary_b["replay_mode"] == "RESEARCH REPLAY — PIPELINE B (ENTERPRISE PRIOR)"
    events_b = adapter.get_live_events(limit=5)
    assert len(events_b) > 0
    # Pipeline B is heuristic-only
    assert events_b[0]["cascade_path"] is None

    # Mode 3: ML30 Cascade (tunnel_cascade)
    adapter.clear_session()
    res_cascade = adapter.replay_dataset("tunnel_cascade", max_records=20)
    assert res_cascade["status"] == "success"
    assert res_cascade["mode"] == "LIVE TIERED CASCADE — ML30"
    summary_cascade = adapter.get_summary()
    assert summary_cascade["is_demo_replay"] is True
    assert summary_cascade["replay_mode"] == "LIVE TIERED CASCADE — ML30"
    events_cascade = adapter.get_live_events(limit=5)
    assert len(events_cascade) > 0
    # Cascade events contain cascade metadata
    cascade_paths = [e["cascade_path"] for e in events_cascade if e.get("cascade_path")]
    assert len(cascade_paths) > 0, "ML30 Cascade must emit cascade_path telemetry"

    # Verify bitwise immutability
    post_profiles_hashes = compute_dir_hashes(live_profiles_dir)
    post_org_hashes = compute_dir_hashes(live_org_dir)
    post_results_hashes = compute_dir_hashes(experiments_results_dir)

    assert pre_profiles_hashes == post_profiles_hashes, "Live data/profiles/ modified during toolbar replay!"
    assert pre_org_hashes == post_org_hashes, "Live data/organization/ modified during toolbar replay!"
    assert pre_results_hashes == post_results_hashes, "experiments/results/ modified during toolbar replay!"

    print("[PASS] test_tunnel_replay_toolbar_buttons_and_modes passed.")



def test_http_api_endpoints():
    """Verify HTTP server responds with correct status codes and JSON payloads."""
    # Find a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHTTPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"

    try:
        # GET / (HTML)
        with urllib.request.urlopen(f"{base_url}/") as res:
            assert res.status == 200
            html = res.read().decode("utf-8")
            assert "DNSentinel" in html
            assert "DEMO REPLAY" in html

        # GET /style.css
        with urllib.request.urlopen(f"{base_url}/style.css") as res:
            assert res.status == 200
            css = res.read().decode("utf-8")
            assert "app-container" in css

        # GET /app.js
        with urllib.request.urlopen(f"{base_url}/app.js") as res:
            assert res.status == 200
            js = res.read().decode("utf-8")
            assert "pollCycle" in js

        # GET /api/status
        with urllib.request.urlopen(f"{base_url}/api/status") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert "capture_interface" in data

        # GET /api/summary
        with urllib.request.urlopen(f"{base_url}/api/summary") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert "total_queries" in data

        # GET /api/research
        with urllib.request.urlopen(f"{base_url}/api/research") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert "tunneleye_baseline" in data

        # POST /api/test_query (Valid domain)
        req = urllib.request.Request(
            f"{base_url}/api/test_query",
            data=json.dumps({"host": "10.0.0.1", "domain": "test.google.com"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["status"] == "success"

        # POST /api/test_query with invalid domain (should return HTTP 400 Bad Request)
        req_bad = urllib.request.Request(
            f"{base_url}/api/test_query",
            data=json.dumps({"host": "10.0.0.1", "domain": "cat /etc/passwd"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req_bad) as res:
                assert False, "Expected 400 HTTPError for invalid domain"
        except urllib.error.HTTPError as e:
            assert e.code == 400
            err_data = json.loads(e.read().decode("utf-8"))
            assert "error" in err_data
            e.close()

        # POST /api/replay (Mature organization mode)
        req_mature = urllib.request.Request(
            f"{base_url}/api/replay",
            data=json.dumps({"trace": "benign_mature", "max_records": 10}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_mature) as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["status"] == "success"
            assert data["mode"] == "ADAPTIVE BASELINE DEMO — MATURE ORGANIZATION"

        # POST /api/replay (Pipeline A1 mode)
        req_tunnel_a1 = urllib.request.Request(
            f"{base_url}/api/replay",
            data=json.dumps({"trace": "tunnel", "max_records": 10}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_tunnel_a1) as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["status"] == "success"
            assert data["mode"] == "DEMO REPLAY — NOT LIVE TRAFFIC"

        # POST /api/replay (Pipeline B mode)
        req_tunnel_b = urllib.request.Request(
            f"{base_url}/api/replay",
            data=json.dumps({"trace": "tunnel_b", "max_records": 10}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_tunnel_b) as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["status"] == "success"
            assert data["mode"] == "RESEARCH REPLAY — PIPELINE B (ENTERPRISE PRIOR)"

        # POST /api/replay (ML30 Cascade mode)
        req_tunnel_cascade = urllib.request.Request(
            f"{base_url}/api/replay",
            data=json.dumps({"trace": "tunnel_cascade", "max_records": 10}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_tunnel_cascade) as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["status"] == "success"
            assert data["mode"] == "LIVE TIERED CASCADE — ML30"

        # GET /nonexistent-path (404 Error handling & logging regression test)
        try:
            with urllib.request.urlopen(f"{base_url}/nonexistent-page-404") as res:
                assert False, "Expected 404 HTTPError"
        except urllib.error.HTTPError as e:
            assert e.code == 404
            e.close()

    finally:
        server.shutdown()
        server.server_close()

    print("[PASS] test_http_api_endpoints passed.")


def test_log_message_safe_handling():
    """Verify log_message handles HTTPStatus, int, empty args, and suppressed endpoints without error."""
    handler = DashboardHTTPRequestHandler.__new__(DashboardHTTPRequestHandler)
    handler.log_date_time_string = lambda: "04/Oct/2026 00:00:00"

    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        # Case 1: BaseHTTPRequestHandler.send_error passes (HTTPStatus.NOT_FOUND, 'Resource not found')
        handler.log_message("code %d, message %s", HTTPStatus.NOT_FOUND, "Resource not found")
        output = sys.stderr.getvalue()
        assert "code 404, message Resource not found" in output

        # Case 2: Integer status code
        sys.stderr.truncate(0)
        sys.stderr.seek(0)
        handler.log_message("code %d, message %s", 404, "Not Found")
        assert "code 404, message Not Found" in sys.stderr.getvalue()

        # Case 3: Empty args
        sys.stderr.truncate(0)
        sys.stderr.seek(0)
        handler.log_message("Simple message")
        assert "Simple message" in sys.stderr.getvalue()

        # Case 4: High-frequency polling endpoints must be suppressed
        sys.stderr.truncate(0)
        sys.stderr.seek(0)
        handler.log_message('"%s" %s %s', "GET /api/live HTTP/1.1", "200", "-")
        handler.log_message('"%s" %s %s', "GET /api/summary HTTP/1.1", "200", "-")
        handler.log_message('"%s" %s %s', "GET /api/status HTTP/1.1", "200", "-")
        assert sys.stderr.getvalue() == "", "High-frequency polling endpoints should be suppressed"

        # Case 5: Normal endpoint must be logged
        handler.log_message('"%s" %s %s', "GET /api/hosts HTTP/1.1", "200", "-")
        assert "GET /api/hosts HTTP/1.1" in sys.stderr.getvalue()
    finally:
        sys.stderr = old_stderr

    print("[PASS] test_log_message_safe_handling passed.")


def test_figure_static_endpoint_and_traversal_protection():
    """Verify /figures/ serves valid PNG with HTTP 200 and blocks traversal with HTTP 404."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHTTPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. Valid figure request
        with urllib.request.urlopen(f"{base_url}/figures/01_cold_start_baseline_drift.png") as res:
            assert res.status == 200
            assert res.headers.get("Content-Type") == "image/png"
            content = res.read()
            assert len(content) > 1000
            assert content[:8] == b"\x89PNG\r\n\x1a\n"

        # 2. All 5 Phase 7B figures respond 200
        for fig in [
            "01_cold_start_baseline_drift.png",
            "02_roc_curve.png",
            "03_precision_recall_curve.png",
            "04_cascade_latency.png",
            "05_abdg_pareto_frontier.png"
        ]:
            with urllib.request.urlopen(f"{base_url}/figures/{fig}") as res:
                assert res.status == 200
                assert res.headers.get("Content-Type") == "image/png"

        # 3. Path traversal attack: /figures/../../app.py must be rejected with 404
        try:
            with urllib.request.urlopen(f"{base_url}/figures/../../app.py") as res:
                assert False, "Expected 404 for traversal"
        except urllib.error.HTTPError as e:
            assert e.code == 404
            e.close()

        # 4. Non-existent figure
        try:
            with urllib.request.urlopen(f"{base_url}/figures/nonexistent_figure.png") as res:
                assert False, "Expected 404 for non-existent figure"
        except urllib.error.HTTPError as e:
            assert e.code == 404
            e.close()

        # 5. Non-png extension in figures directory
        try:
            with urllib.request.urlopen(f"{base_url}/figures/fake.txt") as res:
                assert False, "Expected 404 for non-png"
        except urllib.error.HTTPError as e:
            assert e.code == 404
            e.close()

    finally:
        server.shutdown()
        server.server_close()

    print("[PASS] test_figure_static_endpoint_and_traversal_protection passed.")


def test_extended_phase7b_research_results():
    """Verify get_research_results returns Phase 7B metrics while preserving TunnelEye baseline."""
    adapter = DashboardAdapter()
    res = adapter.get_research_results()

    # Verify preserved Phase 4 keys
    assert "tunneleye_baseline" in res
    assert "cold_start_ab" in res
    assert "ablation_study" in res
    assert "static_rule_baseline" in res

    # Verify exact TunnelEye macro accuracy remains untouched
    te = res["tunneleye_baseline"]
    assert abs(te["macro_average"]["accuracy"] - 0.9987585077) < 1e-9

    # Verify Phase 7B extensions
    assert "phase7b_figures" in res
    assert len(res["phase7b_figures"]) == 5
    assert "phase7b_tables" in res
    assert len(res["phase7b_tables"]) == 4

    # Verify Key Benchmark Metrics
    assert "key_benchmark_metrics" in res
    km = res["key_benchmark_metrics"]
    assert km["behavioral"]["recall"] == 100.0
    assert km["behavioral"]["fpr"] == 1.75
    assert km["ml30"]["recall"] == 100.0
    assert km["ml30"]["fpr"] == 0.0
    assert km["ml31"]["recall"] == 100.0
    assert km["ml31"]["fpr"] == 0.13
    assert km["hybrid"]["recall"] == 100.0
    assert km["hybrid"]["fpr"] == 0.0
    assert km["cascade"]["recall"] == 100.0
    assert km["cascade"]["fpr"] == 0.0

    # Verify Disclaimers
    assert "methodological_disclaimer" in res
    assert "universal production guarantees" in res["methodological_disclaimer"]
    assert "tunneleye_boundary" in res
    assert "not methodologically valid" in res["tunneleye_boundary"]

    print("[PASS] test_extended_phase7b_research_results passed.")


def test_all_seven_tab_sections_rendered():
    """Verify all 7 independent dashboard sections exist in static/index.html."""
    html_path = Config.PROJECT_ROOT / "dashboard" / "static" / "index.html"
    assert html_path.exists(), "index.html does not exist"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    expected_tab_buttons = [
        'id="tab-btn-live"',
        'id="tab-btn-risk"',
        'id="tab-btn-behavior"',
        'id="tab-btn-hosts"',
        'id="tab-btn-alerts"',
        'id="tab-btn-research"',
        'id="tab-btn-system"'
    ]

    expected_sections = [
        'id="tab-live"',
        'id="tab-risk"',
        'id="tab-behavior"',
        'id="tab-hosts"',
        'id="tab-alerts"',
        'id="tab-research"',
        'id="tab-system"'
    ]

    for btn in expected_tab_buttons:
        assert btn in html, f"Missing tab button: {btn}"

    for sec in expected_sections:
        assert sec in html, f"Missing tab section: {sec}"

    # Verify modal element
    assert 'id="image-modal"' in html

    print("[PASS] test_all_seven_tab_sections_rendered passed.")


def test_system_status_integrity_hashes_and_models():
    """Verify system status reports dataset SHA-256 hashes and ML model readiness."""
    adapter = DashboardAdapter()
    status = adapter.get_system_status()

    assert "models_available" in status
    assert status["models_available"] is True
    assert status["ml30_model_ready"] is True
    assert status["ml31_model_ready"] is True
    assert status["calibration_ready"] is True

    assert "dataset_hashes" in status
    dh = status["dataset_hashes"]
    assert dh["dnsentinel_ml_benchmark.jsonl"] == "cbb1147ab3a241c3222c6f11529465c2e4725ec6a00aea5dc4c8df4c8286e32a"
    assert dh["dnsentinel_ml_features.jsonl"] == "7de0bb5a5a6b5eb7dbf335e2fcc04ab9de5db802227457c6228e7b259952e394"

    assert "model_hashes" in status
    mh = status["model_hashes"]
    assert mh["ml30_random_forest.joblib"] == "0cb956069f463ef66f5de3b7f249417d67df879c91d0936eaff720628935c6e2"
    assert mh["ml31_random_forest.joblib"] == "208146aa46630ee026a0b8ef301aacd5a5758f3904bd151b988e8e1a41398257"
    assert mh["calibration_config.json"] == "69f7cbbcc66de3d3a4582ecb7a4fee7c82599216eb72244a54719e13bc034737"

    print("[PASS] test_system_status_integrity_hashes_and_models passed.")


class TestDashboardSuite(unittest.TestCase):
    """Unittest test runner discovery wrapper."""

    def test_adapter_initialization_and_summary(self):
        test_adapter_initialization_and_summary()

    def test_adapter_ingestion_and_alerts(self):
        test_adapter_ingestion_and_alerts()

    def test_baseline_status_metadata_distinction(self):
        test_baseline_status_metadata_distinction()

    def test_detection_method_telemetry_and_ui_distinction(self):
        test_detection_method_telemetry_and_ui_distinction()

    def test_host_and_organization_baselines_loading(self):
        test_host_and_organization_baselines_loading()

    def test_phase4_research_data_integrity(self):
        test_phase4_research_data_integrity()

    def test_demo_replay_and_live_data_immutability(self):
        test_demo_replay_and_live_data_immutability()

    def test_process_test_query_enterprise_baseline_loading_and_isolation(self):
        test_process_test_query_enterprise_baseline_loading_and_isolation()

    def test_custom_domain_input_validation(self):
        test_custom_domain_input_validation()

    def test_alert_view_consistency_and_queue_isolation(self):
        test_alert_view_consistency_and_queue_isolation()

    def test_tunnel_replay_toolbar_buttons_and_modes(self):
        test_tunnel_replay_toolbar_buttons_and_modes()

    def test_http_api_endpoints(self):
        test_http_api_endpoints()

    def test_log_message_safe_handling(self):
        test_log_message_safe_handling()

    def test_figure_static_endpoint_and_traversal_protection(self):
        test_figure_static_endpoint_and_traversal_protection()

    def test_extended_phase7b_research_results(self):
        test_extended_phase7b_research_results()

    def test_all_seven_tab_sections_rendered(self):
        test_all_seven_tab_sections_rendered()

    def test_system_status_integrity_hashes_and_models(self):
        test_system_status_integrity_hashes_and_models()


if __name__ == "__main__":
    test_adapter_initialization_and_summary()
    test_adapter_ingestion_and_alerts()
    test_baseline_status_metadata_distinction()
    test_detection_method_telemetry_and_ui_distinction()
    test_host_and_organization_baselines_loading()
    test_phase4_research_data_integrity()
    test_demo_replay_and_live_data_immutability()
    test_process_test_query_enterprise_baseline_loading_and_isolation()
    test_custom_domain_input_validation()
    test_alert_view_consistency_and_queue_isolation()
    test_tunnel_replay_toolbar_buttons_and_modes()
    test_http_api_endpoints()
    test_log_message_safe_handling()
    test_figure_static_endpoint_and_traversal_protection()
    test_extended_phase7b_research_results()
    test_all_seven_tab_sections_rendered()
    test_system_status_integrity_hashes_and_models()
    print("\nALL DASHBOARD UNIT & INTEGRATION TESTS PASSED SUCCESSFULLY.")
