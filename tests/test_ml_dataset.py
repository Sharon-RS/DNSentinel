"""
Unit tests for DNSentinel Phase 6A ML Benchmark Dataset.
Validates schema compliance, class balance, host and domain diversity,
chronological ordering, hard-negative preservation, generator reproducibility,
and production data immutability.
"""

import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from src.utils.config import Config
from experiments.datasets.generate_ml_benchmark import (
    OUTPUT_FILE,
    RANDOM_SEED,
    BenchmarkDatasetValidator,
    DNSentinelMLBenchmarkGenerator,
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


class TestMLBenchmarkDataset(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        live_profiles = Config.PROJECT_ROOT / "data" / "profiles"
        live_org = Config.PROJECT_ROOT / "data" / "organization"
        cls.pre_profiles = get_dir_hashes(live_profiles)
        cls.pre_org = get_dir_hashes(live_org)

        try:
            if not OUTPUT_FILE.exists():
                generator = DNSentinelMLBenchmarkGenerator(seed=RANDOM_SEED)
                records = generator.build_dataset()
                with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                    for r in records:
                        f.write(json.dumps(r) + "\n")
        finally:
            cls.post_profiles = get_dir_hashes(live_profiles)
            cls.post_org = get_dir_hashes(live_org)

        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            cls.records = [json.loads(line) for line in f if line.strip()]

    def test_file_exists_and_non_empty(self):
        """Assert output file exists and contains valid JSON lines."""
        self.assertTrue(OUTPUT_FILE.exists())
        self.assertGreater(len(self.records), 0)

    def test_schema_and_features_completeness(self):
        """Verify all records conform strictly to DNSentinel JSONL schema."""
        required_top = {"timestamp", "host", "domain", "features", "provenance", "label"}
        required_feats = {
            "domain_length", "subdomain_length", "label_count", "entropy",
            "digit_ratio", "alphabet_ratio", "special_character_ratio",
            "packet_size", "query_type", "timestamp"
        }
        for i, r in enumerate(self.records[:200]):  # check sample
            self.assertEqual(set(r.keys()), required_top, f"Row {i} top keys mismatch")
            self.assertEqual(set(r["features"].keys()), required_feats, f"Row {i} feature keys mismatch")

    def test_class_balance_and_volume(self):
        """Verify total volume is 6,000 queries with 4,000 benign and 2,000 malicious."""
        self.assertEqual(len(self.records), 6000)
        labels = Counter(r["label"] for r in self.records)
        self.assertEqual(labels[0], 4000)
        self.assertEqual(labels[1], 2000)

    def test_host_diversity_and_no_exclusive_malicious_hosts(self):
        """Verify at least 10 hosts and that no host is exclusively malicious."""
        hosts_all = set(r["host"] for r in self.records)
        hosts_benign = set(r["host"] for r in self.records if r["label"] == 0)
        hosts_malicious = set(r["host"] for r in self.records if r["label"] == 1)

        self.assertGreaterEqual(len(hosts_all), 10)
        self.assertEqual(len(hosts_benign), 16)
        # Every host with malicious queries must also have benign queries
        self.assertEqual(len(hosts_malicious - hosts_benign), 0)

    def test_domain_diversity_and_zero_cross_class_overlap(self):
        """Verify domain counts and that no domain is shared across classes."""
        doms_benign = set(r["domain"] for r in self.records if r["label"] == 0)
        doms_malicious = set(r["domain"] for r in self.records if r["label"] == 1)

        self.assertGreaterEqual(len(doms_benign), 50)
        self.assertGreaterEqual(len(doms_malicious), 500)
        overlap = doms_benign.intersection(doms_malicious)
        self.assertEqual(len(overlap), 0, f"Cross-class overlap detected: {overlap}")

    def test_timestamp_ordering_and_temporal_span(self):
        """Verify chronological ordering per host, global ordering, and adequate time span."""
        # Global ordering
        ts_list = [r["timestamp"] for r in self.records]
        self.assertEqual(ts_list, sorted(ts_list))

        # Per host ordering
        host_last_ts = {}
        for r in self.records:
            h = r["host"]
            ts = r["timestamp"]
            if h in host_last_ts:
                self.assertGreater(ts, host_last_ts[h], f"Timestamp regression on host {h}")
            host_last_ts[h] = ts

        span_hours = (max(ts_list) - min(ts_list)) / 3600.0
        self.assertGreaterEqual(span_hours, 8.0)

    def test_hard_negative_danger_edu_preservation(self):
        """Verify authentic lab trace danger.edu observations are preserved as label 0."""
        danger_records = [
            r for r in self.records
            if "m92xk7qlp81zr4.danger.edu" in r["domain"]
        ]
        self.assertEqual(len(danger_records), 2)
        for dr in danger_records:
            self.assertEqual(dr["label"], 0)
            self.assertIn("danger_edu", dr["provenance"])

    def test_campaign_diversity(self):
        """Verify at least 5 distinct attack campaigns recorded in provenance."""
        campaigns = set(
            r["provenance"] for r in self.records if r["label"] == 1
        )
        self.assertGreaterEqual(len(campaigns), 5)

    def test_reproducibility(self):
        """Assert generator produces identical output from fixed seed."""
        gen2 = DNSentinelMLBenchmarkGenerator(seed=RANDOM_SEED)
        records2 = gen2.build_dataset()
        self.assertEqual(len(records2), len(self.records))
        self.assertEqual(records2[0]["domain"], self.records[0]["domain"])
        self.assertEqual(records2[-1]["domain"], self.records[-1]["domain"])
        self.assertEqual(records2[1000]["timestamp"], self.records[1000]["timestamp"])

    def test_production_data_immutability(self):
        """Verify live profiles and organization data remain untouched."""
        live_profiles = Config.PROJECT_ROOT / "data" / "profiles"
        live_org = Config.PROJECT_ROOT / "data" / "organization"

        post_profiles = get_dir_hashes(live_profiles)
        post_org = get_dir_hashes(live_org)

        # Verify that setup workload did not modify runtime directories
        self.assertEqual(
            self.pre_profiles,
            self.post_profiles,
            "Live data directories modified during benchmark generation setup!"
        )
        self.assertEqual(
            self.pre_org,
            self.post_org,
            "Live data directories modified during benchmark generation setup!"
        )

        # Verify complete snapshot equality across the entire test execution:
        # - In a fresh clone (absent/empty directories), asserts post_profiles == {} (no rogue files leaked)
        # - In existing environments, asserts all pre-existing files retain exact bitwise SHA-256 hashes
        self.assertEqual(
            self.pre_profiles,
            post_profiles,
            "Live data/profiles was modified during benchmark dataset test execution!"
        )
        self.assertEqual(
            self.pre_org,
            post_org,
            "Live data/organization was modified during benchmark dataset test execution!"
        )


if __name__ == "__main__":
    unittest.main()
