"""
Tests for Phase 5 Adaptive Benign-Domain Graduation (ABDG) Experimental Harness.
Verifies candidate state lifecycle, gating filters, multi-host quorum,
lexical invariance modes, damped baseline updates, and sandbox isolation immutability.
"""

import hashlib
import unittest
from pathlib import Path

from src.utils.config import Config
from experiments.context import IsolatedEvaluationContext
from experiments.runners.run_domain_graduation_experiment import (
    GraduationConfig,
    GraduationExperimentalPipeline,
)


def get_dir_hashes(directory: Path) -> dict:
    hashes = {}
    if not directory.exists():
        return hashes
    for f in sorted(directory.glob("*")):
        if f.is_file():
            with open(f, "rb") as fp:
                hashes[f.name] = hashlib.sha256(fp.read()).hexdigest()
    return hashes


class TestDomainGraduationHarness(unittest.TestCase):

    def setUp(self):
        self.ref_config = GraduationConfig(
            config_id="TEST_REF",
            stage="test",
            score_ceiling=65.0,
            entropy_ceiling=4.0,
            length_ceiling=32,
            min_spacing_s=30.0,
            quorum_n=5,
            multi_host_quorum_h=2,
            lexical_invariance="exact_fqdn",
            damping_alpha=0.05,
            enabled=True,
            notes="Unit test reference config",
        )

    def _warmup_hosts(self, pipeline, hosts, start_ts=100.0):
        """Warms up test hosts so they exit cold-start and establish a baseline."""
        for h in hosts:
            for i in range(10):
                pipeline.process(h, "google.com", {
                    "entropy": 2.6,
                    "domain_length": 10,
                    "query_type": 1,
                    "timestamp": start_ts + i * 2.0
                })

    def test_baseline_control_preserves_quarantine_lock(self):
        """Baseline control (enabled=False) must never graduate candidate domains."""
        control_config = GraduationConfig(
            config_id="TEST_CTRL",
            stage="test",
            score_ceiling=65.0,
            entropy_ceiling=4.0,
            length_ceiling=32,
            min_spacing_s=30.0,
            quorum_n=5,
            multi_host_quorum_h=2,
            lexical_invariance="exact_fqdn",
            damping_alpha=0.05,
            enabled=False,
            notes="Baseline control",
        )
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(control_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1", "10.0.0.2"])

            features = {
                "entropy": 3.69,
                "domain_length": 17,
                "query_type": 1,
                "timestamp": 1000.0,
            }
            for i in range(10):
                host = "10.0.0.1" if i % 2 == 0 else "10.0.0.2"
                features["timestamp"] = 1000.0 + (i * 60.0)
                res = pipeline.process(host, "quarantined-domain.com", features)
                self.assertFalse(res.get("candidate_graduated", False))
                if res.get("risk_level") in ("SUSPICIOUS", "HIGH_RISK"):
                    self.assertFalse(res.get("baseline_updated", False))

            self.assertEqual(len(pipeline.graduated_domains), 0)

    def test_candidate_graduation_lifecycle(self):
        """Candidate domain meeting all criteria across multiple hosts graduates."""
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(self.ref_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1", "10.0.0.2"])

            features = {
                "entropy": 3.69,
                "domain_length": 17,
                "query_type": 1,
                "timestamp": 1000.0,
            }
            # Host 1 sends 3 observations spaced by 45s
            for i in range(3):
                features["timestamp"] = 1000.0 + (i * 45.0)
                res = pipeline.process("10.0.0.1", "stackoverflow.com", features)
                self.assertFalse(res.get("candidate_graduated", False))

            cand = pipeline.candidates.get("stackoverflow.com")
            self.assertIsNotNone(cand)
            self.assertEqual(cand["count"], 3)
            self.assertEqual(len(cand["hosts"]), 1)
            self.assertFalse(cand["graduated"])

            # Host 2 sends 4th observation
            features["timestamp"] = 1000.0 + (3 * 45.0)
            res = pipeline.process("10.0.0.2", "stackoverflow.com", features)
            self.assertFalse(res.get("candidate_graduated", False))
            self.assertEqual(cand["count"], 4)
            self.assertEqual(len(cand["hosts"]), 2)

            # Host 2 sends 5th observation (quorum_n=5, multi_host_quorum_h=2 satisfied!)
            features["timestamp"] = 1000.0 + (4 * 45.0)
            res = pipeline.process("10.0.0.2", "stackoverflow.com", features)
            self.assertTrue(res.get("candidate_graduated", False))
            self.assertTrue(res.get("baseline_updated", False))
            self.assertIn("stackoverflow.com", pipeline.graduated_domains)

            # Observation 6: Subsequent query should now benefit from learned baseline
            features["timestamp"] = 1000.0 + (5 * 45.0)
            res_subsequent = pipeline.process("10.0.0.1", "stackoverflow.com", features)
            # With domain now in host and org profiles, score should drop substantially
            self.assertLess(res_subsequent["behavior_score"], 50.0)

    def test_spacing_gate_rejection(self):
        """Queries arriving faster than min_spacing_s do not advance quorum."""
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(self.ref_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1"])

            features = {
                "entropy": 3.3,
                "domain_length": 14,
                "query_type": 1,
                "timestamp": 1000.0,
            }
            # Observation 1 at t=1000
            pipeline.process("10.0.0.1", "api.github.com", features)
            cand = pipeline.candidates.get("api.github.com")
            self.assertIsNotNone(cand)
            self.assertEqual(cand["count"], 1)

            # Rapid observations at t=1005, 1010, 1015 (spacing < 30s)
            for t in [1005.0, 1010.0, 1015.0]:
                features["timestamp"] = t
                pipeline.process("10.0.0.1", "api.github.com", features)
                # Count should remain 1 because delta_t < min_spacing_s
                self.assertEqual(cand["count"], 1)

            # Spaced observation at t=1035 (delta_t = 35s >= 30s)
            features["timestamp"] = 1035.0
            pipeline.process("10.0.0.1", "api.github.com", features)
            self.assertEqual(cand["count"], 2)

    def test_entropy_ceiling_disqualification(self):
        """Candidate exceeding entropy ceiling is disqualified and revoked."""
        config_ent_test = GraduationConfig(
            config_id="TEST_ENT",
            stage="test",
            score_ceiling=70.0,
            entropy_ceiling=4.0,
            length_ceiling=32,
            min_spacing_s=30.0,
            quorum_n=5,
            multi_host_quorum_h=2,
            lexical_invariance="exact_fqdn",
            damping_alpha=0.05,
            enabled=True,
        )
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(config_ent_test, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1"])

            # Observation 1: normal entropy
            f1 = {"entropy": 3.3, "domain_length": 14, "query_type": 1, "timestamp": 1000.0}
            pipeline.process("10.0.0.1", "api.github.com", f1)
            cand = pipeline.candidates.get("api.github.com")
            self.assertIsNotNone(cand)
            self.assertFalse(cand["revoked"])

            # Observation 2: high entropy burst exceeding 4.0 ceiling
            f2 = {"entropy": 4.1, "domain_length": 14, "query_type": 1, "timestamp": 1060.0}
            pipeline.process("10.0.0.1", "api.github.com", f2)
            self.assertTrue(cand["revoked"])
            self.assertIn("entropy_ceiling_exceeded", cand["rejection_reason"])

    def test_length_ceiling_disqualification(self):
        """Candidate exceeding domain length ceiling is disqualified and revoked."""
        config_len_test = GraduationConfig(
            config_id="TEST_LEN",
            stage="test",
            score_ceiling=70.0,
            entropy_ceiling=4.0,
            length_ceiling=20,
            min_spacing_s=30.0,
            quorum_n=5,
            multi_host_quorum_h=2,
            lexical_invariance="exact_fqdn",
            damping_alpha=0.05,
            enabled=True,
        )
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(config_len_test, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1"])

            # Observation 1: normal length
            f1 = {"entropy": 3.3, "domain_length": 14, "query_type": 1, "timestamp": 1000.0}
            pipeline.process("10.0.0.1", "api.github.com", f1)
            cand = pipeline.candidates.get("api.github.com")
            self.assertIsNotNone(cand)
            self.assertFalse(cand["revoked"])

            # Observation 2: length 25 exceeding 20 ceiling
            f2 = {"entropy": 3.3, "domain_length": 25, "query_type": 1, "timestamp": 1060.0}
            pipeline.process("10.0.0.1", "api.github.com", f2)
            self.assertTrue(cand["revoked"])
            self.assertIn("length_ceiling_exceeded", cand["rejection_reason"])

    def test_multi_host_quorum_blocks_single_host(self):
        """Single host cannot graduate a domain when multi_host_quorum_h = 2."""
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(self.ref_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1"])

            features = {"entropy": 3.3, "domain_length": 14, "query_type": 1}
            # Single host sends 15 spaced queries (far exceeding quorum_n=5)
            for i in range(15):
                features["timestamp"] = 1000.0 + (i * 45.0)
                res = pipeline.process("10.0.0.1", "api.github.com", features)
                self.assertFalse(res.get("candidate_graduated", False))

            cand = pipeline.candidates.get("api.github.com")
            self.assertIsNotNone(cand)
            self.assertEqual(cand["count"], 15)
            self.assertEqual(len(cand["hosts"]), 1)
            self.assertFalse(cand["graduated"])
            self.assertNotIn("api.github.com", pipeline.graduated_domains)

    def test_lexical_invariance_subdomain_violation(self):
        """Under sld_static_subdomain, changing subdomains revokes graduation candidate."""
        static_sub_config = GraduationConfig(
            config_id="TEST_STATIC",
            stage="test",
            score_ceiling=65.0,
            entropy_ceiling=4.0,
            length_ceiling=32,
            min_spacing_s=10.0,
            quorum_n=3,
            multi_host_quorum_h=1,
            lexical_invariance="sld_static_subdomain",
            damping_alpha=0.05,
            enabled=True,
        )
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(static_sub_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1"])

            f1 = {"entropy": 3.3, "domain_length": 14, "query_type": 1, "timestamp": 1000.0}
            pipeline.process("10.0.0.1", "api.github.com", f1)
            cand = pipeline.candidates.get("github.com")
            self.assertIsNotNone(cand)
            self.assertFalse(cand["revoked"])

            # Query 2: Different subdomain on the same SLD
            f2 = {"entropy": 3.3, "domain_length": 14, "query_type": 1, "timestamp": 1020.0}
            pipeline.process("10.0.0.1", "web.github.com", f2)
            self.assertTrue(cand["revoked"])
            self.assertEqual(cand["rejection_reason"], "varying_subdomain_violation")

    def test_filesystem_isolation_immutability(self):
        """Verify that live data and results directories remain untouched."""
        live_profiles = Config.PROJECT_ROOT / "data" / "profiles"
        live_org = Config.PROJECT_ROOT / "data" / "organization"
        live_results = Config.PROJECT_ROOT / "experiments" / "results"

        pre_profiles = get_dir_hashes(live_profiles)
        pre_org = get_dir_hashes(live_org)
        pre_results = get_dir_hashes(live_results)

        # Run pipeline in isolated context and trigger graduation
        with IsolatedEvaluationContext() as ctx:
            pipeline = GraduationExperimentalPipeline(self.ref_config, data_dir=ctx.sandbox_path)
            self._warmup_hosts(pipeline, ["10.0.0.1", "10.0.0.2"])
            f = {"entropy": 3.69, "domain_length": 17, "query_type": 1}
            for i in range(5):
                h = "10.0.0.1" if i % 2 == 0 else "10.0.0.2"
                f["timestamp"] = 1000.0 + (i * 50.0)
                pipeline.process(h, "stackoverflow.com", f)

            self.assertIn("stackoverflow.com", pipeline.graduated_domains)

        post_profiles = get_dir_hashes(live_profiles)
        post_org = get_dir_hashes(live_org)
        post_results = get_dir_hashes(live_results)

        self.assertEqual(pre_profiles, post_profiles)
        self.assertEqual(pre_org, post_org)
        self.assertEqual(pre_results, post_results)


if __name__ == "__main__":
    unittest.main()
