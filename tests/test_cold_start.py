"""
Unit tests for Phase 3 Cold-Start Detection Mitigation.
Validates:
1. Organization fallback calculation when org baseline is mature.
2. Deterministic zero-fallback on fresh install (immature org baseline).
3. Provisional calibration holding: zero persistent updates during queries 1..10.
4. Batch gating failure on malicious queries: entire batch quarantined (0 committed).
5. Batch gating success on benign queries: exactly 10 queries committed.
6. Bitwise immutability of live data directories.
"""

import hashlib
from pathlib import Path

from src.utils.config import Config
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_calculator import DeviationCalculator
from src.behavior.deviation_engine import ColdStartDeviationEngine
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cold_start_pipeline import ColdStartMitigatedPipeline
from experiments.context import IsolatedEvaluationContext


def get_dir_hashes(directory: Path):
    hashes = {}
    if not directory.exists():
        return hashes
    for file_path in sorted(directory.glob("*.json")):
        with open(file_path, "rb") as f:
            hashes[file_path.name] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def test_org_fallback_when_mature():
    """Verify that cold host (total_queries < 2) falls back to mature org baseline."""
    snapshot = BehaviorSnapshot(
        host="10.50.50.1",
        domain="exfiltrate.data.tunnel.com",
        packet_features={"entropy": 4.8, "domain_length": 60, "query_type": 1},
        host_profile={"total_queries": 0, "average_entropy": 0.0, "average_domain_length": 0.0},
        organization_profile={
            "total_queries": 50,
            "average_entropy": 3.0,
            "average_domain_length": 12.0,
            "total_hosts": ["10.0.0.1", "10.0.0.2"]
        },
        window_statistics={"query_rate": 0.0, "window_size": 1}
    )

    # Mature org baseline: threshold 20 met (50 >= 20)
    dev_entropy = DeviationCalculator.entropy_with_fallback(snapshot, min_org_observations=20)
    dev_len = DeviationCalculator.domain_length_with_fallback(snapshot, min_org_observations=20)

    # Entropy deviation: |4.8 - 3.0| / 3.0 = 1.8 / 3.0 = 0.6000
    assert dev_entropy == 0.6000, f"Expected 0.6000, got {dev_entropy}"
    # Length deviation: |60 - 12| / 12 = 4.0 -> clamped to 1.0000
    assert dev_len == 1.0000, f"Expected 1.0000, got {dev_len}"

    engine = ColdStartDeviationEngine(min_org_observations=20)
    res = engine.calculate(snapshot)
    assert res["entropy_deviation"] == 0.6000
    assert res["domain_length_deviation"] == 1.0000
    # Natural score: 0.60 * 25 + 1.0 * 20 = 15 + 20 = 35 + org_rarity (1.0 * 20 = 20) = 55.0
    assert res["behavior_score"] >= 50.0, f"Expected >= 50.0, got {res['behavior_score']}"
    print("[PASS] test_org_fallback_when_mature passed.")


def test_org_fallback_fresh_install():
    """Verify that when org baseline is immature or fresh install, deviation returns 0.0 safely."""
    snapshot = BehaviorSnapshot(
        host="10.50.50.2",
        domain="exfiltrate.data.tunnel.com",
        packet_features={"entropy": 4.8, "domain_length": 60, "query_type": 1},
        host_profile={"total_queries": 0, "average_entropy": 0.0, "average_domain_length": 0.0},
        organization_profile={
            "total_queries": 5,  # Insufficient observations (< 20)
            "average_entropy": 0.0,
            "average_domain_length": 0.0,
            "total_hosts": []
        },
        window_statistics={"query_rate": 0.0, "window_size": 1}
    )

    dev_entropy = DeviationCalculator.entropy_with_fallback(snapshot, min_org_observations=20)
    dev_len = DeviationCalculator.domain_length_with_fallback(snapshot, min_org_observations=20)

    assert dev_entropy == 0.0, f"Expected 0.0 on immature org, got {dev_entropy}"
    assert dev_len == 0.0, f"Expected 0.0 on immature org, got {dev_len}"
    print("[PASS] test_org_fallback_fresh_install passed.")


def test_calibration_provisional_holding_and_quarantine():
    """Verify that queries 1..10 do not update persistent baseline, and batch fails on attack."""
    with IsolatedEvaluationContext() as ctx:
        pipeline = ColdStartMitigatedPipeline(data_dir=ctx.sandbox_path, calibration_queries=10)

        # 9 benign queries followed by 1 attack query
        for i in range(9):
            res = pipeline.process(
                "10.99.1.1",
                f"legit{i}.com",
                {"entropy": 3.0, "domain_length": 12, "query_type": 1, "timestamp": 1000.0 + i * 1.5}
            )
            assert res["lifecycle_state"] == "COLD_START_CALIBRATION"
            assert res["baseline_updated"] is False, "Persistent baseline updated during calibration!"
            profile = pipeline.host_profile.load("10.99.1.1").to_dict()
            assert profile["total_queries"] == 0, "Persistent host profile modified during calibration!"

        # Query 10: Tunnel packet (high entropy, long domain, burst interval)
        res10 = pipeline.process(
            "10.99.1.1",
            "525443.000.longtunnelingexfiltrationdomainpayload.attacker.lab",
            {"entropy": 4.9, "domain_length": 62, "query_type": 1, "timestamp": 1013.55}
        )
        assert res10["lifecycle_state"] == "COLD_START_CALIBRATION"
        assert res10["baseline_updated"] is False

        # Batch evaluated at Query 10: attack packet triggered gating failure!
        # Entire batch must be quarantined; 0 observations committed.
        profile = pipeline.host_profile.load("10.99.1.1").to_dict()
        assert profile["total_queries"] == 0, f"Expected 0 queries committed after quarantine, got {profile['total_queries']}"
        assert "10.99.1.1" in pipeline.quarantined_hosts, "Host not marked quarantined!"

        # Query 11: Steady state on quarantined host
        res11 = pipeline.process(
            "10.99.1.1",
            "google.com",
            {"entropy": 2.5, "domain_length": 10, "query_type": 1, "timestamp": 1015.0}
        )
        assert res11["lifecycle_state"] == "STEADY_STATE"
        assert res11["baseline_updated"] is False, "Quarantined host updated baseline in steady state!"
        print("[PASS] test_calibration_provisional_holding_and_quarantine passed.")


def test_calibration_benign_graduation():
    """Verify that when all 10 calibration queries are benign, exactly 10 are committed in batch."""
    with IsolatedEvaluationContext() as ctx:
        pipeline = ColdStartMitigatedPipeline(data_dir=ctx.sandbox_path, calibration_queries=10)

        for i in range(10):
            res = pipeline.process(
                "10.99.2.2",
                f"benign{i}.org",
                {"entropy": 3.0, "domain_length": 14, "query_type": 1, "timestamp": 1000.0 + i * 1.5}
            )
            if i < 9:
                profile = pipeline.host_profile.load("10.99.2.2").to_dict()
                assert profile["total_queries"] == 0, f"Premature commit at query {i + 1}"

        # At Query 10, all 10 queries passed -> batch committed!
        profile = pipeline.host_profile.load("10.99.2.2").to_dict()
        assert profile["total_queries"] == 10, f"Expected exactly 10 committed queries, got {profile['total_queries']}"
        assert "10.99.2.2" not in pipeline.quarantined_hosts

        # Query 11: Normal query in STEADY_STATE updates baseline normally
        res11 = pipeline.process(
            "10.99.2.2",
            "github.com",
            {"entropy": 3.0, "domain_length": 10, "query_type": 1, "timestamp": 1016.5}
        )
        assert res11["lifecycle_state"] == "STEADY_STATE"
        assert res11["baseline_updated"] is True
        profile = pipeline.host_profile.load("10.99.2.2").to_dict()
        assert profile["total_queries"] == 11
        print("[PASS] test_calibration_benign_graduation passed.")


def test_live_data_immutability():
    """Assert live data files remain bitwise unchanged."""
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"
    pre_profiles = get_dir_hashes(live_profiles_dir)
    pre_org = get_dir_hashes(live_org_dir)

    with IsolatedEvaluationContext() as ctx:
        p = ColdStartMitigatedPipeline(data_dir=ctx.sandbox_path)
        for i in range(12):
            p.process("10.88.88.88", f"test{i}.com", {"entropy": 3.0, "domain_length": 11, "query_type": 1, "timestamp": 1000.0 + i})

    post_profiles = get_dir_hashes(live_profiles_dir)
    post_org = get_dir_hashes(live_org_dir)
    assert pre_profiles == post_profiles, "Live profiles modified!"
    assert pre_org == post_org, "Live org modified!"
    print("[PASS] test_live_data_immutability passed.")


if __name__ == "__main__":
    test_org_fallback_when_mature()
    test_org_fallback_fresh_install()
    test_calibration_provisional_holding_and_quarantine()
    test_calibration_benign_graduation()
    test_live_data_immutability()
    print("\nALL COLD-START UNIT TESTS PASSED SUCCESSFULLY.")
