"""
Unit tests proving complete filesystem isolation for tests and evaluation.
Asserts that live data/profiles and data/organization remain 100% bitwise immutable.
"""

import hashlib
from pathlib import Path

from src.utils.config import Config
from experiments.context import IsolatedEvaluationContext
from experiments.evaluator import DNSentinelEvaluator


def get_dir_hashes(directory: Path):
    hashes = {}
    if not directory.exists():
        return hashes
    for file_path in sorted(directory.glob("*.json")):
        with open(file_path, "rb") as f:
            hashes[file_path.name] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def test_isolated_evaluation_context():
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"

    pre_profile_hashes = get_dir_hashes(live_profiles_dir)
    pre_org_hashes = get_dir_hashes(live_org_dir)

    # Run workload inside isolated context
    with IsolatedEvaluationContext() as ctx:
        pipeline = ctx.create_pipeline()

        # Establish baseline with 4 normal queries
        normal_samples = [
            ("google.com", 2.6, 10, 1000.0),
            ("github.com", 3.0, 10, 1001.0),
            ("youtube.com", 3.2, 11, 1002.0),
            ("stackoverflow.com", 3.4, 17, 1003.0),
        ]
        for d, ent, l, ts in normal_samples:
            res = pipeline.process(
                "10.99.99.1",
                d,
                {"entropy": ent, "domain_length": l, "query_type": 1, "timestamp": ts}
            )
            assert res["baseline_updated"] is True

        # Send malicious burst query
        malicious_features = {
            "entropy": 5.2,
            "domain_length": 35,
            "query_type": 1,
            "timestamp": 1003.05
        }
        r2 = pipeline.process("10.99.99.1", "exfil987654321.tunnel.xyz", malicious_features)
        assert r2["risk_level"] in ("SUSPICIOUS", "HIGH_RISK")
        assert r2["baseline_updated"] is False

        # Verify files WERE created in the sandbox directory
        sandbox_profiles = list((ctx.sandbox_path / "profiles").glob("*.json"))
        assert len(sandbox_profiles) >= 1
        sandbox_org = ctx.sandbox_path / "organization" / "organization.json"
        assert sandbox_org.exists()

    # After exit, verify live directory hashes
    post_profile_hashes = get_dir_hashes(live_profiles_dir)
    post_org_hashes = get_dir_hashes(live_org_dir)

    assert pre_profile_hashes == post_profile_hashes, (
        f"Live profiles altered! Pre: {pre_profile_hashes} vs Post: {post_profile_hashes}"
    )
    assert pre_org_hashes == post_org_hashes, (
        f"Live organization profiles altered! Pre: {pre_org_hashes} vs Post: {post_org_hashes}"
    )

    print("[PASS] test_isolated_evaluation_context passed: Live profiles 100% untouched.")


def test_evaluator_stream_isolated():
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"

    pre_profile_hashes = get_dir_hashes(live_profiles_dir)
    pre_org_hashes = get_dir_hashes(live_org_dir)

    events = [
        # Normal warmup
        {"host": "10.50.0.1", "domain": "google.com", "features": {"entropy": 2.5, "domain_length": 10, "query_type": 1, "timestamp": 100.0}, "label": 0},
        {"host": "10.50.0.1", "domain": "github.com", "features": {"entropy": 2.9, "domain_length": 10, "query_type": 1, "timestamp": 101.0}, "label": 0},
        {"host": "10.50.0.1", "domain": "youtube.com", "features": {"entropy": 3.1, "domain_length": 11, "query_type": 1, "timestamp": 102.0}, "label": 0},
        {"host": "10.50.0.1", "domain": "stackoverflow.com", "features": {"entropy": 3.2, "domain_length": 17, "query_type": 1, "timestamp": 103.0}, "label": 0},
        # High-speed tunnel burst
        {"host": "10.50.0.1", "domain": "a1b2c3d4e5f6.tunnel.xyz", "features": {"entropy": 5.1, "domain_length": 25, "query_type": 1, "timestamp": 104.01}, "label": 1},
        {"host": "10.50.0.1", "domain": "g7h8i9j0k1l2.tunnel.xyz", "features": {"entropy": 5.3, "domain_length": 26, "query_type": 1, "timestamp": 104.05}, "label": 1},
    ]

    metrics = DNSentinelEvaluator.evaluate_isolated(events)

    assert metrics.total_samples == 6
    assert metrics.true_positives == 2
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 4
    assert metrics.false_negatives == 0
    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.baseline_contamination_count == 0, "Contamination occurred during evaluation!"

    # Verify live directory hashes after evaluation
    post_profile_hashes = get_dir_hashes(live_profiles_dir)
    post_org_hashes = get_dir_hashes(live_org_dir)

    assert pre_profile_hashes == post_profile_hashes
    assert pre_org_hashes == post_org_hashes

    print(f"[PASS] test_evaluator_stream_isolated passed: Accuracy={metrics.accuracy}, ContaminationCount={metrics.baseline_contamination_count}.")


if __name__ == "__main__":
    test_isolated_evaluation_context()
    test_evaluator_stream_isolated()
    print("\nALL ISOLATION TESTS PASSED: Zero live data modification verified.")
