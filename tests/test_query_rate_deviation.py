"""
Unit tests for temporal query-rate calculation and deviation scoring.
"""

from src.behavior.sliding_window import SlidingWindowManager
from src.behavior.deviation_calculator import DeviationCalculator
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_engine import BehaviorDeviationEngine
from src.utils.config import Config


def test_cold_start():
    window = SlidingWindowManager(window_size=20)
    features = {
        "entropy": 3.0,
        "domain_length": 12,
        "query_type": 1,
        "timestamp": 1000.0
    }
    window.update("10.0.0.1", "google.com", features)
    stats = window.get_statistics("10.0.0.1")

    assert stats["window_size"] == 1
    assert stats["query_rate"] == 0.0
    assert stats["window_duration"] == 0.0

    snapshot = BehaviorSnapshot(
        host="10.0.0.1",
        domain="google.com",
        packet_features=features,
        host_profile={"average_entropy": 3.0, "average_domain_length": 12, "total_queries": 1},
        organization_profile={"total_hosts": ["10.0.0.1"], "host_domain_map": {"google.com": ["10.0.0.1"]}},
        window_statistics=stats
    )

    deviation = DeviationCalculator.query_rate(snapshot)
    assert deviation == 0.0, f"Expected 0.0 on cold start, got {deviation}"
    print("[PASS] test_cold_start passed.")


def test_steady_traffic():
    window = SlidingWindowManager(window_size=20)
    # 5 queries spaced 1.0 second apart -> 4 intervals / 4.0s = 1.0 QPS <= BASELINE_QUERY_RATE (2.0)
    timestamps = [1000.0, 1001.0, 1002.0, 1003.0, 1004.0]
    for ts in timestamps:
        features = {
            "entropy": 3.0,
            "domain_length": 12,
            "query_type": 1,
            "timestamp": ts
        }
        window.update("10.0.0.1", "google.com", features)

    stats = window.get_statistics("10.0.0.1")
    assert stats["window_size"] == 5
    assert stats["window_duration"] == 4.0
    assert stats["query_rate"] == 1.0, f"Expected 1.0 QPS, got {stats['query_rate']}"

    snapshot = BehaviorSnapshot(
        host="10.0.0.1",
        domain="google.com",
        packet_features=features,
        host_profile={"average_entropy": 3.0, "average_domain_length": 12, "total_queries": 5},
        organization_profile={"total_hosts": ["10.0.0.1"], "host_domain_map": {"google.com": ["10.0.0.1"]}},
        window_statistics=stats
    )

    deviation = DeviationCalculator.query_rate(snapshot)
    assert deviation == 0.0, f"Expected 0.0 for steady traffic (1.0 QPS <= 2.0), got {deviation}"
    print("[PASS] test_steady_traffic passed.")


def test_burst_traffic_and_scoring_contribution():
    window = SlidingWindowManager(window_size=20)
    # 10 queries within 0.45 seconds -> 9 intervals / 0.45s = 20.0 QPS > BASELINE_QUERY_RATE (2.0)
    for i in range(10):
        features = {
            "entropy": 3.0,
            "domain_length": 12,
            "query_type": 1,
            "timestamp": 1000.0 + (i * 0.05)
        }
        window.update("10.0.0.1", "google.com", features)

    stats = window.get_statistics("10.0.0.1")
    assert stats["window_size"] == 10
    assert stats["query_rate"] == 20.0, f"Expected 20.0 QPS, got {stats['query_rate']}"

    snapshot = BehaviorSnapshot(
        host="10.0.0.1",
        domain="google.com",
        packet_features={
            "entropy": 3.0,
            "domain_length": 12,
            "query_type": 1
        },
        host_profile={
            "average_entropy": 3.0,
            "average_domain_length": 12,
            "total_queries": 10,
            "unique_domains": ["google.com"]
        },
        organization_profile={
            "total_hosts": ["10.0.0.1"],
            "host_domain_map": {"google.com": ["10.0.0.1"]}
        },
        window_statistics=stats
    )

    # Deviation calculation
    deviation = DeviationCalculator.query_rate(snapshot)
    assert deviation == 1.0, f"Expected 1.0 (capped) for 20.0 QPS burst, got {deviation}"

    # Verify BehaviorDeviationEngine scoring math:
    # All other deviations are 0.0 (entropy match, length match, known domain, common in org).
    # score = 1.0 * Config.QUERY_RATE_WEIGHT (0.15) = 0.15 -> behavior_score = 0.15 * 100 = 15.0
    engine = BehaviorDeviationEngine()
    result = engine.calculate(snapshot)

    assert result["entropy_deviation"] == 0.0
    assert result["domain_length_deviation"] == 0.0
    assert result["query_rate_deviation"] == 1.0
    assert result["novel_domain_score"] == 0.0
    assert result["organization_rarity_score"] == 0.0

    expected_score = round(1.0 * Config.QUERY_RATE_WEIGHT * 100, 2)
    assert result["behavior_score"] == expected_score, (
        f"Expected behavior_score {expected_score}, got {result['behavior_score']}"
    )
    print(f"[PASS] test_burst_traffic_and_scoring_contribution passed (behavior_score = {result['behavior_score']}).")


def test_intermediate_burst_rate():
    # 4 queries over 1.0s -> 3 intervals / 1.0s = 3.0 QPS
    # baseline = 2.0 QPS -> deviation = (3.0 - 2.0) / 2.0 = 0.50
    # Expected behavior score contribution = 0.50 * 0.15 * 100 = 7.50
    window = SlidingWindowManager(window_size=20)
    timestamps = [1000.0, 1000.33, 1000.66, 1001.0]
    for ts in timestamps:
        features = {
            "entropy": 3.0,
            "domain_length": 12,
            "query_type": 1,
            "timestamp": ts
        }
        window.update("10.0.0.1", "google.com", features)

    stats = window.get_statistics("10.0.0.1")
    snapshot = BehaviorSnapshot(
        host="10.0.0.1",
        domain="google.com",
        packet_features={"entropy": 3.0, "domain_length": 12, "query_type": 1},
        host_profile={"average_entropy": 3.0, "average_domain_length": 12, "total_queries": 10, "unique_domains": ["google.com"]},
        organization_profile={"total_hosts": ["10.0.0.1"], "host_domain_map": {"google.com": ["10.0.0.1"]}},
        window_statistics=stats
    )

    deviation = DeviationCalculator.query_rate(snapshot)
    assert deviation == 0.5, f"Expected 0.5 for 3.0 QPS relative to 2.0, got {deviation}"

    engine = BehaviorDeviationEngine()
    result = engine.calculate(snapshot)
    assert result["query_rate_deviation"] == 0.5
    assert result["behavior_score"] == 7.5, f"Expected 7.5, got {result['behavior_score']}"
    print("[PASS] test_intermediate_burst_rate passed.")


if __name__ == "__main__":
    test_cold_start()
    test_steady_traffic()
    test_burst_traffic_and_scoring_contribution()
    test_intermediate_burst_rate()
    print("\nALL QUERY-RATE DEVIATION TESTS PASSED SUCCESSFULLY.")
