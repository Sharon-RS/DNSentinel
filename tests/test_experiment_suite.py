"""
Automated unit tests for the Phase 2 research experiment suite.
Validates dataset schemas, evaluation metrics calculation, ablation weight
renormalization, baseline drift measurement, and isolation integrity.
"""

import json
import hashlib
from pathlib import Path

from src.utils.config import Config
from experiments.context import IsolatedEvaluationContext
from experiments.evaluator import DNSentinelEvaluator, EvaluationMetrics
from experiments.runners.run_ablation import ABLATION_TIERS
from experiments.runners.run_poisoning_test import UnprotectedDetectionPipeline


def get_dir_hashes(directory: Path):
    hashes = {}
    if not directory.exists():
        return hashes
    for file_path in sorted(directory.glob("*.json")):
        with open(file_path, "rb") as f:
            hashes[file_path.name] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def test_dataset_provenance_and_schema():
    datasets_dir = Config.PROJECT_ROOT / "experiments" / "datasets"
    expected_files = [
        "lab_trace_benign.jsonl",
        "lab_trace_tunnel_burst.jsonl",
        "synthetic_mixed_stream.jsonl",
        "synthetic_poisoning_attack.jsonl"
    ]

    for fname in expected_files:
        fpath = datasets_dir / fname
        assert fpath.exists(), f"Dataset file missing: {fname}"
        assert fpath.stat().st_size > 0, f"Dataset file is empty: {fname}"

        with open(fpath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0, f"No entries in {fname}"
        for i, line in enumerate(lines):
            record = json.loads(line)
            assert "host" in record, f"Missing 'host' in {fname} line {i}"
            assert "domain" in record, f"Missing 'domain' in {fname} line {i}"
            assert "features" in record, f"Missing 'features' in {fname} line {i}"
            assert "label" in record, f"Missing 'label' in {fname} line {i}"
            assert record["label"] in (0, 1), f"Invalid label {record['label']} in {fname} line {i}"
            assert isinstance(record["features"], dict), f"Features not dict in {fname} line {i}"
            assert "entropy" in record["features"]
            assert "domain_length" in record["features"]
            assert "timestamp" in record["features"]

    print("[PASS] test_dataset_provenance_and_schema passed.")


def test_ablation_weights_renormalization():
    """Verify all 4 tiers sum their weights to 1.0 (or 100% of the active scale)."""
    assert len(ABLATION_TIERS) == 4, f"Expected 4 tiers, got {len(ABLATION_TIERS)}"

    for tier_id, tier_info in ABLATION_TIERS.items():
        weights = tier_info["weights"]
        weight_sum = sum(weights.values())
        assert abs(weight_sum - 1.0) < 1e-6, f"Tier {tier_id} weights do not sum to 1.0: {weight_sum}"

    print("[PASS] test_ablation_weights_renormalization passed.")


def test_evaluator_metrics_calculation():
    """Verify that EvaluationMetrics computes precision, recall, F1, FPR, FNR, and latency."""
    events = [
        # 4 benign
        {"host": "10.0.0.1", "domain": "google.com", "features": {"entropy": 2.5, "domain_length": 10, "query_type": 1, "timestamp": 1000.0}, "label": 0},
        {"host": "10.0.0.1", "domain": "github.com", "features": {"entropy": 3.0, "domain_length": 10, "query_type": 1, "timestamp": 1001.0}, "label": 0},
        {"host": "10.0.0.1", "domain": "youtube.com", "features": {"entropy": 3.2, "domain_length": 11, "query_type": 1, "timestamp": 1002.0}, "label": 0},
        {"host": "10.0.0.1", "domain": "stackoverflow.com", "features": {"entropy": 3.4, "domain_length": 17, "query_type": 1, "timestamp": 1003.0}, "label": 0},
        # 2 malicious
        {"host": "10.0.0.1", "domain": "a1b2c3d4e5f6g7h8i9j0.tunnel.net", "features": {"entropy": 5.2, "domain_length": 32, "query_type": 1, "timestamp": 1003.05}, "label": 1},
        {"host": "10.0.0.1", "domain": "x1y2z3a4b5c6d7e8f9g0.tunnel.net", "features": {"entropy": 5.3, "domain_length": 32, "query_type": 1, "timestamp": 1003.10}, "label": 1},
    ]

    with IsolatedEvaluationContext() as ctx:
        pipeline = ctx.create_pipeline()
        evaluator = DNSentinelEvaluator(pipeline)
        metrics = evaluator.evaluate_stream(events)

        assert metrics.total_samples == 6
        assert metrics.true_positives == 2
        assert metrics.true_negatives == 4
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.accuracy == 1.0
        assert metrics.binary_precision == 1.0
        assert metrics.binary_recall == 1.0
        assert metrics.binary_f1 == 1.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.false_negative_rate == 0.0
        assert metrics.mean_latency_ms >= 0.0
        assert metrics.median_latency_ms >= 0.0
        assert metrics.p99_latency_ms >= 0.0

    print("[PASS] test_evaluator_metrics_calculation passed.")


def test_unprotected_control_behavior():
    """Verify that UnprotectedDetectionPipeline permits baseline drift while protected prevents it."""
    benign_warmup = [
        {"host": "10.0.0.1", "domain": f"site{i}.org", "features": {"entropy": 3.0, "domain_length": 12, "query_type": 1, "timestamp": 1000.0 + i}, "label": 0}
        for i in range(10)
    ]
    attack = [
        {"host": "10.0.0.1", "domain": f"tunnel{i}.exfiltration.biz", "features": {"entropy": 5.5, "domain_length": 45, "query_type": 1, "timestamp": 1010.0 + i}, "label": 1}
        for i in range(10)
    ]

    with IsolatedEvaluationContext() as ctx:
        # Protected pipeline
        protected_pipe = ctx.create_pipeline()
        for ev in benign_warmup:
            protected_pipe.process(ev["host"], ev["domain"], ev["features"])
        pre_entropy = protected_pipe.host_profile.load("10.0.0.1").average_entropy
        for ev in attack:
            protected_pipe.process(ev["host"], ev["domain"], ev["features"])
        post_entropy_protected = protected_pipe.host_profile.load("10.0.0.1").average_entropy
        protected_drift = abs(post_entropy_protected - pre_entropy)
        assert protected_drift == 0.0, f"Protected pipeline drifted by {protected_drift}"

    with IsolatedEvaluationContext() as ctx:
        # Unprotected control
        unprotected_pipe = UnprotectedDetectionPipeline(data_dir=ctx.sandbox_path)
        for ev in benign_warmup:
            unprotected_pipe.process(ev["host"], ev["domain"], ev["features"])
        pre_entropy_unprotected = unprotected_pipe.host_profile.load("10.0.0.1").average_entropy
        for ev in attack:
            unprotected_pipe.process(ev["host"], ev["domain"], ev["features"])
        post_entropy_unprotected = unprotected_pipe.host_profile.load("10.0.0.1").average_entropy
        unprotected_drift = abs(post_entropy_unprotected - pre_entropy_unprotected)
        assert unprotected_drift > 0.0, "Unprotected pipeline failed to exhibit baseline drift under attack"

    print("[PASS] test_unprotected_control_behavior passed.")


def test_live_data_immutability():
    """Verify live data remains 100% bitwise immutable before and after test execution."""
    live_profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    live_org_dir = Config.PROJECT_ROOT / "data" / "organization"

    pre_profiles = get_dir_hashes(live_profiles_dir)
    pre_org = get_dir_hashes(live_org_dir)

    with IsolatedEvaluationContext() as ctx:
        pipe = ctx.create_pipeline()
        pipe.process("10.0.0.1", "random.xyz", {"entropy": 4.5, "domain_length": 25, "query_type": 1})

    post_profiles = get_dir_hashes(live_profiles_dir)
    post_org = get_dir_hashes(live_org_dir)

    assert pre_profiles == post_profiles, "Live profiles modified!"
    assert pre_org == post_org, "Live org modified!"
    print("[PASS] test_live_data_immutability passed.")


if __name__ == "__main__":
    test_dataset_provenance_and_schema()
    test_ablation_weights_renormalization()
    test_evaluator_metrics_calculation()
    test_unprotected_control_behavior()
    test_live_data_immutability()
    print("\nALL EXPERIMENT SUITE UNIT TESTS PASSED SUCCESSFULLY.")
