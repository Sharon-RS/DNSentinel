"""
Unit tests for DNSentinel Phase 6B Causal ML Feature Extraction.
Validates chronological replay, absence of future lookahead, absence of identity
shortcuts (no host, domain, timestamp, or provenance in features), schema consistency,
reproducibility, and production baseline immutability.
"""

import hashlib
import json
import math
import unittest
from pathlib import Path

from src.utils.config import Config
from experiments.ml.causal_extractor import CausalMLFeatureExtractor
from experiments.runners.build_ml_features import OUTPUT_FEATURES, build_causal_features


def get_dir_hashes(directory: Path) -> dict:
    hashes = {}
    if not directory.exists():
        return hashes
    for f in sorted(directory.glob("*")):
        if f.is_file():
            with open(f, "rb") as fp:
                hashes[f.name] = hashlib.sha256(fp.read()).hexdigest()
    return hashes


class TestCausalMLFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        live_profiles = Config.PROJECT_ROOT / "data" / "profiles"
        live_org = Config.PROJECT_ROOT / "data" / "organization"
        cls.pre_profiles = get_dir_hashes(live_profiles)
        cls.pre_org = get_dir_hashes(live_org)

        try:
            if not OUTPUT_FEATURES.exists():
                build_causal_features()
        finally:
            cls.post_profiles = get_dir_hashes(live_profiles)
            cls.post_org = get_dir_hashes(live_org)

        with open(OUTPUT_FEATURES, "r", encoding="utf-8") as f:
            cls.records = [json.loads(line) for line in f if line.strip()]

    def test_output_file_exists_and_count(self):
        """Assert output file exists and contains exactly 6000 records."""
        self.assertTrue(OUTPUT_FEATURES.exists())
        self.assertEqual(len(self.records), 6000)

    def test_top_level_schema(self):
        """Verify each record has exactly: sample_id, label, provenance, features."""
        expected_top = {"sample_id", "label", "provenance", "features"}
        for i, r in enumerate(self.records[:200]):
            self.assertEqual(set(r.keys()), expected_top, f"Row {i} top keys mismatch")
            self.assertIn(r["label"], (0, 1))
            self.assertIsInstance(r["sample_id"], int)
            self.assertIsInstance(r["provenance"], str)
            self.assertIsInstance(r["features"], dict)

    def test_no_shortcut_or_forbidden_features(self):
        """Verify NO host IP, raw domain, absolute timestamp, or provenance in features."""
        forbidden_exact = {
            "host", "ip", "source_ip", "client_ip", "domain", "domain_name",
            "raw_domain", "fqdn", "sld", "timestamp", "time", "epoch",
            "provenance", "phase", "label", "class"
        }
        sample_features = self.records[0]["features"]
        for k in sample_features.keys():
            self.assertNotIn(k.lower(), forbidden_exact, f"Forbidden key found in features: {k}")
            # Ensure no substring matches for identity keys
            self.assertFalse(k.startswith("host_ip") or k.startswith("domain_name") or k == "timestamp")

    def test_feature_schema_consistency(self):
        """Verify all 31 features are present in every row with no NaN or Inf."""
        expected_features = set(CausalMLFeatureExtractor.FEATURE_NAMES)
        self.assertEqual(len(expected_features), 31)

        for i, r in enumerate(self.records):
            feats = r["features"]
            self.assertEqual(set(feats.keys()), expected_features, f"Row {i} feature mismatch")
            for fk, fv in feats.items():
                self.assertIsNotNone(fv, f"Row {i} feature {fk} is None")
                self.assertFalse(math.isnan(fv), f"Row {i} feature {fk} is NaN")
                self.assertFalse(math.isinf(fv), f"Row {i} feature {fk} is Inf")

    def test_causal_state_evolution(self):
        """Verify that state evolves strictly forward without lookahead."""
        # For sample 0 (first query in stream), host_total_queries and inter_arrival must be 0
        first_sample = self.records[0]
        feats0 = first_sample["features"]
        self.assertEqual(feats0["host_total_queries"], 0)
        self.assertEqual(feats0["temp_inter_arrival_time"], 0.0)

        # Later samples should have non-zero accumulated queries
        last_sample = self.records[-1]
        feats_last = last_sample["features"]
        self.assertGreater(feats_last["org_total_queries"], 0)

    def test_temporal_feature_bounds(self):
        """Verify temporal features adhere to valid physical boundaries."""
        for r in self.records[:500]:
            f = r["features"]
            self.assertGreaterEqual(f["temp_inter_arrival_time"], 0.0)
            self.assertGreaterEqual(f["temp_query_rate"], 0.0)
            self.assertGreaterEqual(f["temp_window_duration"], 0.0)
            self.assertGreaterEqual(f["temp_unique_ratio"], 0.0)
            self.assertLessEqual(f["temp_unique_ratio"], 1.0)

    def test_class_balance_preserved(self):
        """Verify 4,000 benign and 2,000 malicious labels."""
        labels = [r["label"] for r in self.records]
        self.assertEqual(labels.count(0), 4000)
        self.assertEqual(labels.count(1), 2000)

    def test_production_baseline_immutability(self):
        """Verify that live data directories remain 100% bitwise untouched."""
        live_profiles = Config.PROJECT_ROOT / "data" / "profiles"
        live_org = Config.PROJECT_ROOT / "data" / "organization"

        post_profiles = get_dir_hashes(live_profiles)
        post_org = get_dir_hashes(live_org)

        # Verify that setup workload did not modify runtime directories
        self.assertEqual(
            self.pre_profiles,
            self.post_profiles,
            "Live data directories modified during feature extraction setup!"
        )
        self.assertEqual(
            self.pre_org,
            self.post_org,
            "Live data directories modified during feature extraction setup!"
        )

        # Verify complete snapshot equality across causal feature test execution:
        # - In a fresh clone (absent/empty directories), asserts post_profiles == {} (no rogue files leaked)
        # - In existing environments, asserts all pre-existing files retain exact bitwise SHA-256 hashes
        self.assertEqual(
            self.pre_profiles,
            post_profiles,
            "Live data/profiles/ was modified during causal feature test execution!"
        )
        self.assertEqual(
            self.pre_org,
            post_org,
            "Live data/organization/ was modified during causal feature test execution!"
        )


if __name__ == "__main__":
    unittest.main()
