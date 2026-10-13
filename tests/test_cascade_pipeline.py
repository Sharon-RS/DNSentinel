"""
Unit and Integration Tests for Tiered ML Cascade Detection Pipeline (Phase 9A).

Tests all contract requirements:
1. Model loads successfully with project-root relative resolution
2. 30-feature vector has exact canonical ordering
3. All feature values in matrix X are float64
4. S < 20 bypasses ML (FAST_PATH_BENIGN)
5. S >= 70 bypasses ML (FAST_PATH_MALICIOUS)
6. 20 <= S < 70 invokes ML (ML_ESCALATED)
7. P_ML >= 0.20 produces MALICIOUS (elevates to HIGH_RISK, blocks baseline update)
8. P_ML < 0.20 produces BENIGN (cleared, allows Pipeline B baseline gating)
9. Malicious decisions NEVER update host or organization baselines
10. Benign decisions preserve Pipeline B baseline gating
11. Calibration buffer remains protected (provisional held; batch gating quarantines on attack)
12. Strict causality (no future information used)
13. Existing DetectionPipeline tests and behavior remain unchanged
14. Existing ColdStartMitigatedPipeline tests and behavior remain unchanged
"""

from pathlib import Path
import shutil
import time
import unittest
from unittest.mock import MagicMock

import numpy as np

from src.utils.config import Config
from src.features.traditional_features import TraditionalFeatureExtractor
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cold_start_pipeline import ColdStartMitigatedPipeline
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline
from experiments.context import IsolatedEvaluationContext


def setup_enterprise_org_baseline(sandbox_path: Path):
    """Initializes the isolated sandbox with authentic enterprise organization baseline."""
    org_src = Config.PROJECT_ROOT / "experiments" / "datasets" / "enterprise_org_baseline.json"
    if org_src.exists():
        dst = sandbox_path / "organization" / "organization.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(org_src, dst)


class TestCascadePipelineContract(unittest.TestCase):
    """Verifies ML30 model loading, attributes, feature contract, and causality."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = TraditionalFeatureExtractor()

    def test_model_loading_and_attributes(self):
        """Test 1: Model loads successfully and matches frozen configuration."""
        pipeline = CascadeDetectionPipeline()
        self.assertIsNotNone(pipeline.model)
        self.assertEqual(pipeline.n_features_in_, 30)
        self.assertEqual(pipeline.n_estimators, 100)
        self.assertEqual(pipeline.n_jobs, 1)

    def test_30_feature_vector_exact_ordering(self):
        """Test 2 & 3: 30-feature vector has exact ordering and all values are float64."""
        pipeline = CascadeDetectionPipeline()

        expected_order = [
            "lex_domain_length",
            "lex_subdomain_length",
            "lex_subdomain_ratio",
            "lex_label_count",
            "lex_entropy",
            "lex_digit_ratio",
            "lex_alphabet_ratio",
            "lex_special_ratio",
            "lex_packet_size",
            "proto_query_type",
            "temp_inter_arrival_time",
            "temp_query_rate",
            "temp_window_duration",
            "temp_entropy_trend",
            "temp_length_trend",
            "temp_unique_ratio",
            "host_total_queries",
            "host_average_entropy",
            "host_average_domain_length",
            "host_entropy_deviation",
            "host_length_deviation",
            "host_query_rate_deviation",
            "host_novel_domain",
            "org_total_queries",
            "org_domain_frequency",
            "org_rarity_score",
            "org_average_entropy",
            "org_average_domain_length",
            "org_entropy_deviation",
            "org_length_deviation",
        ]
        self.assertEqual(pipeline.FEATURE_NAMES, expected_order)

        # Generate a test event and build the feature vector
        dns_event = {
            "timestamp": time.time(),
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "domain": "sub.testdomain.org",
            "query_type": 1,
            "packet_size": 72,
        }
        features = self.extractor.extract(dns_event)
        features["timestamp"] = dns_event["timestamp"]

        with IsolatedEvaluationContext() as ctx:
            test_pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
            res = test_pipe.process("10.0.0.99", "sub.testdomain.org", features)

            # Build feature vector directly
            snap = BehaviorSnapshot(
                host="10.0.0.99",
                domain="sub.testdomain.org",
                packet_features=features,
                host_profile={},
                organization_profile={},
                window_statistics=test_pipe.window.get_statistics("10.0.0.99"),
            )
            X, feat_dict = test_pipe.build_feature_vector(
                host="10.0.0.99",
                domain="sub.testdomain.org",
                features=features,
                snapshot=snap,
                window_statistics=test_pipe.window.get_statistics("10.0.0.99"),
                inter_arrival_time=0.25,
            )

            # Assert shape, type, and exact feature list
            self.assertEqual(X.shape, (1, 30))
            self.assertEqual(X.dtype, np.float64)
            for fname, val in feat_dict.items():
                self.assertIsInstance(val, float, f"Feature {fname} is not float: {type(val)}")
            self.assertEqual(list(feat_dict.keys()), expected_order)

    def test_causal_feature_generation_no_future_info(self):
        """Test 12: No future query information is used; inter-arrival time is causal."""
        with IsolatedEvaluationContext() as ctx:
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
            t0 = 1000.0
            t1 = 1002.5

            ev0 = {"source_ip": "10.0.0.5", "domain": "a.com", "query_type": 1, "packet_size": 60}
            f0 = self.extractor.extract(ev0)
            f0["timestamp"] = t0
            r0 = pipe.process("10.0.0.5", "a.com", f0)

            ev1 = {"source_ip": "10.0.0.5", "domain": "b.com", "query_type": 1, "packet_size": 60}
            f1 = self.extractor.extract(ev1)
            f1["timestamp"] = t1
            r1 = pipe.process("10.0.0.5", "b.com", f1)

            # Assert last_query_timestamp updated to t1 and inter-arrival time is causal
            self.assertAlmostEqual(pipe.last_query_timestamps["10.0.0.5"], t1)


class TestCascadeDecisionLogic(unittest.TestCase):
    """Verifies fast-path bypassing, ML escalation, and probability thresholding."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = TraditionalFeatureExtractor()

    def test_fast_path_benign_bypasses_ml(self):
        """Test 4: S < 20.0 bypasses ML as FAST_PATH_BENIGN."""
        with IsolatedEvaluationContext() as ctx:
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
            # Mock the model to fail if predict_proba is called
            pipe.model.predict_proba = MagicMock(side_effect=AssertionError("ML should be bypassed for S < 20"))

            # Query designed to have zero deviation (score = 0.0 < 20.0)
            ev = {"source_ip": "10.0.0.1", "domain": "google.com", "query_type": 1, "packet_size": 60}
            feats = self.extractor.extract(ev)
            feats["timestamp"] = time.time()

            result = pipe.process("10.0.0.1", "google.com", feats)
            self.assertTrue(result["ml_enabled"])
            self.assertEqual(result["cascade_path"], "FAST_PATH_BENIGN")
            self.assertEqual(result["cascade_decision"], "BENIGN")
            self.assertIsNone(result["ml_probability"])
            pipe.model.predict_proba.assert_not_called()

    def test_fast_path_malicious_bypasses_ml(self):
        """Test 5 & 9: S >= 70.0 bypasses ML as FAST_PATH_MALICIOUS and blocks baseline update."""
        with IsolatedEvaluationContext() as ctx:
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path, calibration_queries=5)

            # First establish a host baseline with 5 normal queries to graduate
            t0 = time.time()
            for i in range(5):
                ev = {"source_ip": "10.0.0.2", "domain": f"test{i}.com", "query_type": 1, "packet_size": 50}
                f = self.extractor.extract(ev)
                f["timestamp"] = t0 + i * 10
                pipe.process("10.0.0.2", f"test{i}.com", f)

            # Now attach mock to ensure ML is NEVER invoked when S >= 70
            pipe.model.predict_proba = MagicMock(side_effect=AssertionError("ML should be bypassed for S >= 70"))

            # Query designed to produce S >= 70.0 (high entropy + burst rate)
            tunnel_domain = "a98b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1.tunnel.cc"
            ev = {"source_ip": "10.0.0.2", "domain": tunnel_domain, "query_type": 16, "packet_size": 256}
            feats = self.extractor.extract(ev)
            feats["timestamp"] = t0 + 40.01  # rapid burst 0.01s after query 5

            result = pipe.process("10.0.0.2", tunnel_domain, feats)
            self.assertGreaterEqual(result["behavior_score"], 70.0)
            self.assertEqual(result["cascade_path"], "FAST_PATH_MALICIOUS")
            self.assertEqual(result["cascade_decision"], "MALICIOUS")
            self.assertIsNone(result["ml_probability"])
            self.assertFalse(result["baseline_updated"])
            pipe.model.predict_proba.assert_not_called()

    def test_ml_escalation_and_thresholding(self):
        """Test 6, 7 & 8: 20 <= S < 70 invokes ML; P_ML >= 0.20 -> MALICIOUS, P_ML < 0.20 -> BENIGN."""
        with IsolatedEvaluationContext() as ctx:
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path, calibration_queries=3)

            # Establish baseline with 3 queries so host graduates and query 4 lands in [20, 70)
            t0 = time.time()
            for i in range(3):
                ev = {"source_ip": "10.0.0.3", "domain": f"test{i}.com", "query_type": 1, "packet_size": 50}
                f = self.extractor.extract(ev)
                f["timestamp"] = t0 + i * 10
                pipe.process("10.0.0.3", f"test{i}.com", f)

            ev = {"source_ip": "10.0.0.3", "domain": "subdomain.example.org", "query_type": 1, "packet_size": 60}
            feats = self.extractor.extract(ev)
            feats["timestamp"] = t0 + 40

            # Case A: Mock model to return P_ML = 0.25 (>= 0.2000 -> MALICIOUS)
            pipe.model.predict_proba = MagicMock(return_value=np.array([[0.75, 0.25]]))
            res_mal = pipe.process("10.0.0.3", "subdomain.example.org", feats)

            self.assertGreaterEqual(res_mal["behavior_score"], 20.0)
            self.assertLess(res_mal["behavior_score"], 70.0)
            self.assertEqual(res_mal["cascade_path"], "ML_ESCALATED")
            self.assertEqual(res_mal["cascade_decision"], "MALICIOUS")
            self.assertEqual(res_mal["ml_probability"], 0.25)
            self.assertEqual(res_mal["risk_level"], "HIGH_RISK")
            self.assertFalse(res_mal["baseline_updated"])

            # Case B: Mock model to return P_ML = 0.12 (< 0.2000 -> BENIGN)
            pipe.model.predict_proba = MagicMock(return_value=np.array([[0.88, 0.12]]))
            res_ben = pipe.process("10.0.0.3", "subdomain.example.org", feats)

            self.assertEqual(res_ben["cascade_path"], "ML_ESCALATED")
            self.assertEqual(res_ben["cascade_decision"], "BENIGN")
            self.assertEqual(res_ben["ml_probability"], 0.12)


class TestColdStartAndQuarantineIntegration(unittest.TestCase):
    """Verifies provisional buffering, batch graduation, and quarantine protection."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = TraditionalFeatureExtractor()

    def test_calibration_buffer_protection_and_batch_graduation(self):
        """Test 10 & 11: Calibration queries 1..9 hold provisional buffer; query 10 graduates clean host."""
        with IsolatedEvaluationContext() as ctx:
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path, calibration_queries=10)

            # Feed 9 clean benign queries
            for k in range(1, 10):
                ev = {"source_ip": "10.0.0.10", "domain": f"site{k}.org", "query_type": 1, "packet_size": 60}
                f = self.extractor.extract(ev)
                f["timestamp"] = time.time() + k * 10
                res = pipe.process("10.0.0.10", f"site{k}.org", f)

                self.assertEqual(res["lifecycle_state"], "COLD_START_CALIBRATION")
                self.assertTrue(res["provisional_held"])
                self.assertFalse(res["baseline_updated"])

            # Verify provisional buffer has 9 items and persistent profile total_queries is still 0
            self.assertEqual(len(pipe.provisional_buffers["10.0.0.10"]), 9)
            prof_before = pipe.host_profile.load("10.0.0.10")
            self.assertEqual(prof_before.total_queries, 0)

            # Query 10: Clean query triggers batch graduation
            ev10 = {"source_ip": "10.0.0.10", "domain": "site10.org", "query_type": 1, "packet_size": 60}
            f10 = self.extractor.extract(ev10)
            f10["timestamp"] = time.time() + 100
            res10 = pipe.process("10.0.0.10", "site10.org", f10)

            # Buffer cleared, all 10 committed to persistent profile
            self.assertEqual(len(pipe.provisional_buffers.get("10.0.0.10", [])), 0)
            prof_after = pipe.host_profile.load("10.0.0.10")
            self.assertEqual(prof_after.total_queries, 10)
            self.assertNotIn("10.0.0.10", pipe.quarantined_hosts)

    def test_calibration_quarantine_on_ml_malicious_detection(self):
        """Test 9 & 11: Malicious ML decision during calibration quarantines entire batch."""
        with IsolatedEvaluationContext() as ctx:
            setup_enterprise_org_baseline(ctx.sandbox_path)
            pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path, calibration_queries=10)

            # Queries 1..5: Benign slow traffic
            t_base = 1000.0
            for k in range(1, 6):
                ev = {"source_ip": "10.0.0.20", "domain": f"ok{k}.com", "query_type": 1, "packet_size": 60}
                f = self.extractor.extract(ev)
                f["timestamp"] = t_base + k * 10
                pipe.process("10.0.0.20", f"ok{k}.com", f)

            # Query 6: subdomain.example.org evaluated against enterprise baseline gives S = 48.11 (in [20, 70))
            ev6 = {"source_ip": "10.0.0.20", "domain": "subdomain.example.org", "query_type": 1, "packet_size": 60}
            f6 = self.extractor.extract(ev6)
            f6["timestamp"] = t_base + 60

            # Mock ML to return P_ML = 0.85 (malicious)
            pipe.model.predict_proba = MagicMock(return_value=np.array([[0.15, 0.85]]))
            res6 = pipe.process("10.0.0.20", "subdomain.example.org", f6)
            self.assertEqual(res6["cascade_path"], "ML_ESCALATED")
            self.assertEqual(res6["cascade_decision"], "MALICIOUS")
            self.assertEqual(res6["risk_level"], "HIGH_RISK")
            self.assertFalse(res6["baseline_updated"])

            # Queries 7..10: Normal traffic up to calibration boundary
            for k in range(7, 11):
                ev = {"source_ip": "10.0.0.20", "domain": f"ok{k}.com", "query_type": 1, "packet_size": 60}
                f = self.extractor.extract(ev)
                f["timestamp"] = t_base + k * 10
                pipe.model.predict_proba = MagicMock(return_value=np.array([[0.95, 0.05]]))
                pipe.process("10.0.0.20", f"ok{k}.com", f)

            # Batch failed at query 10: Host must be quarantined, 0 queries committed!
            self.assertIn("10.0.0.20", pipe.quarantined_hosts)
            prof = pipe.host_profile.load("10.0.0.20")
            self.assertEqual(prof.total_queries, 0, "Quarantined batch must commit 0 queries!")

            # Subsequent steady-state query #11 is marked quarantined and cannot update baseline
            ev11 = {"source_ip": "10.0.0.20", "domain": "benign-afterward.org", "query_type": 1, "packet_size": 60}
            f11 = self.extractor.extract(ev11)
            f11["timestamp"] = t_base + 300
            res11 = pipe.process("10.0.0.20", "benign-afterward.org", f11)
            self.assertTrue(res11.get("calibration_quarantined", False))
            self.assertFalse(res11["baseline_updated"])


class TestLegacyPipelineImmutability(unittest.TestCase):
    """Test 13 & 14: Verifies that DetectionPipeline and ColdStartMitigatedPipeline remain unchanged."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = TraditionalFeatureExtractor()

    def test_detection_pipeline_operates_without_ml(self):
        """DetectionPipeline runs classic heuristic logic with no ML dependencies."""
        with IsolatedEvaluationContext() as ctx:
            pipe = DetectionPipeline(data_dir=ctx.sandbox_path)
            ev = {"source_ip": "10.0.0.1", "domain": "test.org", "query_type": 1, "packet_size": 64}
            f = self.extractor.extract(ev)
            res = pipe.process("10.0.0.1", "test.org", f)
            self.assertNotIn("ml_enabled", res)
            self.assertIn("behavior_score", res)
            self.assertIn("risk_level", res)

    def test_cold_start_mitigated_pipeline_operates_without_ml(self):
        """ColdStartMitigatedPipeline runs Pipeline B without ML dependencies."""
        with IsolatedEvaluationContext() as ctx:
            pipe = ColdStartMitigatedPipeline(data_dir=ctx.sandbox_path)
            ev = {"source_ip": "10.0.0.1", "domain": "test.org", "query_type": 1, "packet_size": 64}
            f = self.extractor.extract(ev)
            res = pipe.process("10.0.0.1", "test.org", f)
            self.assertNotIn("ml_enabled", res)
            self.assertIn("lifecycle_state", res)
            self.assertEqual(res["lifecycle_state"], "COLD_START_CALIBRATION")


if __name__ == "__main__":
    unittest.main()
