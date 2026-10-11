"""
Comprehensive unit and regression tests for Parent-Domain Burst-Taint Propagation.

Validates:
1. Strict registrable domain extraction without naive suffix substring matching.
2. Confirmed attacks establish active host-isolated taint.
3. Later control queries inherit taint and record detection_source='TAINT_PROPAGATED'.
4. Unrelated domains from the same host NEVER inherit taint.
5. Different hosts are strictly isolated and NEVER share taint state.
6. Taint expires correctly by time elapsed (taint_ttl_seconds).
7. Taint expires correctly by query index gap (taint_max_query_gap).
8. reset_taint() completely purges taint state.
9. Benign-only traffic produces zero taint and zero propagated alerts.
10. CascadeDetectionPipeline baseline preserves unchanged behavior when enable_burst_taint=False.
"""

import shutil
import unittest
from pathlib import Path

from src.utils.config import Config
from src.utils.domain import extract_registrable_domain, is_same_registrable_domain
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline, BurstTaintCascadePipeline
from experiments.context import IsolatedEvaluationContext


def setup_sandbox_org(sandbox_path: Path):
    org_src = Config.PROJECT_ROOT / "experiments" / "datasets" / "enterprise_org_baseline.json"
    if org_src.exists():
        dst = sandbox_path / "organization" / "organization.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(org_src, dst)


class TestBurstTaintPropagation(unittest.TestCase):

    def test_registrable_domain_parsing_strictness(self):
        """Test 1: Exact registrable parent domain extraction without naive suffix matching."""
        # Standard lab & enterprise domains
        self.assertEqual(extract_registrable_domain("hello.attacker.lab"), "attacker.lab")
        self.assertEqual(extract_registrable_domain("525443.end.attacker.lab"), "attacker.lab")
        self.assertEqual(extract_registrable_domain("chunk.001.data.attacker.lab"), "attacker.lab")
        self.assertEqual(extract_registrable_domain("attacker.lab"), "attacker.lab")
        self.assertEqual(extract_registrable_domain("docs.python.org"), "python.org")
        self.assertEqual(extract_registrable_domain("connectivity-check.ubuntu.com"), "ubuntu.com")
        self.assertEqual(extract_registrable_domain("sub.c2.co.uk"), "c2.co.uk")

        # Crucial: Rejection of naive string suffix substrings
        self.assertEqual(extract_registrable_domain("notattacker.lab"), "notattacker.lab")
        self.assertFalse(is_same_registrable_domain("notattacker.lab", "attacker.lab"))

        self.assertEqual(extract_registrable_domain("evilattacker.lab"), "evilattacker.lab")
        self.assertFalse(is_same_registrable_domain("evilattacker.lab", "attacker.lab"))

        self.assertEqual(extract_registrable_domain("attacker.lab.attacker.com"), "attacker.com")
        self.assertFalse(is_same_registrable_domain("attacker.lab.attacker.com", "attacker.lab"))

    def test_confirmed_attack_establishes_taint_and_control_inherits(self):
        """Test 2 & 3: Confirmed attack establishes taint; later control query inherits taint."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path, taint_ttl_seconds=60.0)

            host = "192.168.145.128"
            t0 = 1000.0

            # Query 1: Heavy payload attack chunk -> Confirmed MALICIOUS
            feat_attack = {
                "entropy": 4.8,
                "domain_length": 55,
                "subdomain_length": 42,
                "query_rate": 10.0,
                "packet_size": 120,
                "query_type": 1,
                "timestamp": t0
            }
            res_attack = pipeline.process(host, "chunk001.hex.attacker.lab", feat_attack)
            self.assertEqual(res_attack["cascade_decision"], "MALICIOUS")
            self.assertEqual(res_attack["risk_level"], "HIGH_RISK")
            self.assertFalse(res_attack["taint_propagated"])
            self.assertIn("DIRECT", res_attack["detection_source"])

            # Verify taint record was registered
            is_tainted, rec = pipeline._check_taint(host, "attacker.lab", t0 + 0.2, 2)
            self.assertTrue(is_tainted)
            self.assertIsNotNone(rec)
            self.assertEqual(rec.registrable_domain, "attacker.lab")

            # Query 2: Control framing query (.end.attacker.lab) arriving 0.2s later
            # Features are individually benign/low-risk
            feat_control = {
                "entropy": 3.4,
                "domain_length": 23,
                "subdomain_length": 10,
                "query_rate": 1.0,
                "packet_size": 55,
                "query_type": 1,
                "timestamp": t0 + 0.2
            }
            res_control = pipeline.process(host, "525443.end.attacker.lab", feat_control)

            # Assert taint propagation behavior
            self.assertEqual(res_control["cascade_decision"], "MALICIOUS")
            self.assertEqual(res_control["risk_level"], "HIGH_RISK")
            self.assertEqual(res_control["cascade_path"], "TAINT_PROPAGATED")
            self.assertEqual(res_control["detection_source"], "TAINT_PROPAGATED")
            self.assertTrue(res_control["taint_propagated"])
            self.assertEqual(res_control["taint_parent_domain"], "attacker.lab")
            self.assertEqual(res_control["taint_source_domain"], "chunk001.hex.attacker.lab")
            self.assertFalse(res_control["baseline_updated"])

    def test_unrelated_domains_do_not_inherit_taint(self):
        """Test 4: Unrelated domains from the same host NEVER inherit active taint."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path, taint_ttl_seconds=60.0)

            host = "192.168.145.128"
            t0 = 2000.0

            # Attack establishes taint on attacker.lab
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host, "chunk.attacker.lab", feat_attack)

            # Query to legitimate google.com 0.5s later from the same host
            feat_benign = {"entropy": 2.6, "domain_length": 10, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 0.5}
            res_google = pipeline.process(host, "google.com", feat_benign)

            self.assertEqual(res_google["cascade_decision"], "BENIGN")
            self.assertFalse(res_google["taint_propagated"])
            self.assertNotEqual(res_google["detection_source"], "TAINT_PROPAGATED")

            # Query to notattacker.lab (substring lookalike) must NOT inherit taint
            feat_lookalike = {"entropy": 2.8, "domain_length": 15, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 0.8}
            res_lookalike = pipeline.process(host, "notattacker.lab", feat_lookalike)
            self.assertEqual(res_lookalike["cascade_decision"], "BENIGN")
            self.assertFalse(res_lookalike["taint_propagated"])

    def test_host_isolation(self):
        """Test 5: Different hosts are strictly isolated and NEVER share taint state."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path, taint_ttl_seconds=60.0)

            host_a = "10.0.0.1"
            host_b = "10.0.0.2"
            t0 = 3000.0

            # Host A has confirmed attack on attacker.lab
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host_a, "chunk.attacker.lab", feat_attack)

            # Host B queries the same domain with benign characteristics
            feat_b = {"entropy": 3.4, "domain_length": 23, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 0.2}
            res_b = pipeline.process(host_b, "525443.end.attacker.lab", feat_b)

            # Host B must NOT inherit Host A's taint
            self.assertEqual(res_b["cascade_decision"], "BENIGN")
            self.assertFalse(res_b["taint_propagated"])
            self.assertNotEqual(res_b["detection_source"], "TAINT_PROPAGATED")

    def test_expiry_by_time(self):
        """Test 6: Taint expires after taint_ttl_seconds."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            ttl = 30.0
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path, taint_ttl_seconds=ttl)

            host = "192.168.145.128"
            t0 = 4000.0

            # Attack at t0
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host, "chunk.attacker.lab", feat_attack)

            # Control query arrives at t0 + ttl + 1.0 (after expiration)
            feat_control = {"entropy": 3.4, "domain_length": 23, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + ttl + 1.0}
            res_expired = pipeline.process(host, "525443.end.attacker.lab", feat_control)

            self.assertEqual(res_expired["cascade_decision"], "BENIGN")
            self.assertFalse(res_expired["taint_propagated"])

    def test_expiry_by_query_gap(self):
        """Test 7: Taint expires if too many unrelated queries intervene (taint_max_query_gap)."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            gap = 5
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path, taint_ttl_seconds=300.0, taint_max_query_gap=gap)

            host = "192.168.145.128"
            t0 = 5000.0

            # Attack at query k=1
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host, "chunk.attacker.lab", feat_attack)

            # Send 6 intervening benign queries (k=2..7)
            for i in range(gap + 1):
                f = {"entropy": 2.5, "domain_length": 10, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + i + 1}
                pipeline.process(host, f"benign{i}.other.org", f)

            # Next query to attacker.lab at k=8 exceeds query gap
            feat_control = {"entropy": 3.4, "domain_length": 23, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 10.0}
            res_gap_expired = pipeline.process(host, "525443.end.attacker.lab", feat_control)

            self.assertEqual(res_gap_expired["cascade_decision"], "BENIGN")
            self.assertFalse(res_gap_expired["taint_propagated"])

    def test_reset_taint(self):
        """Test 8: Explicit reset_taint() completely purges taint state."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path)

            host = "192.168.145.128"
            t0 = 6000.0

            # Attack establishes taint
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host, "chunk.attacker.lab", feat_attack)

            self.assertIn(host, pipeline.taint_state)
            pipeline.reset_taint(host)
            self.assertNotIn(host, pipeline.taint_state)

            # Subsequent control query has no taint
            feat_control = {"entropy": 3.4, "domain_length": 23, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 0.2}
            res = pipeline.process(host, "525443.end.attacker.lab", feat_control)
            self.assertFalse(res["taint_propagated"])

    def test_benign_only_traffic_unaffected(self):
        """Test 9: Purely benign traffic never establishes taint and produces 0 propagated alerts."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            pipeline = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path)

            host = "10.0.0.1"
            benign_domains = ["google.com", "github.com", "youtube.com", "ubuntu.com", "microsoft.com"]
            for i, d in enumerate(benign_domains):
                f = {"entropy": 2.6, "domain_length": len(d), "query_rate": 0.5, "query_type": 1, "timestamp": 7000.0 + i}
                res = pipeline.process(host, d, f)
                self.assertFalse(res["taint_propagated"])
                self.assertNotEqual(res["detection_source"], "TAINT_PROPAGATED")

            self.assertEqual(len(pipeline.taint_state), 0)

    def test_baseline_cascade_preservation_when_flag_disabled(self):
        """Test 10: CascadeDetectionPipeline with enable_burst_taint=False is 100% identical to baseline."""
        with IsolatedEvaluationContext() as ctx:
            setup_sandbox_org(ctx.sandbox_path)
            # Default initialization has enable_burst_taint=False
            pipeline = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
            self.assertFalse(pipeline.enable_burst_taint)

            host = "192.168.145.128"
            t0 = 8000.0

            # Attack query
            feat_attack = {"entropy": 4.9, "domain_length": 50, "query_rate": 10.0, "query_type": 1, "timestamp": t0}
            pipeline.process(host, "chunk.attacker.lab", feat_attack)

            # Control query does NOT get tainted because feature flag is False
            feat_control = {"entropy": 3.4, "domain_length": 23, "query_rate": 0.5, "query_type": 1, "timestamp": t0 + 0.2}
            res_control = pipeline.process(host, "525443.end.attacker.lab", feat_control)

            self.assertFalse(res_control["taint_propagated"])
            self.assertEqual(res_control["cascade_decision"], "BENIGN")
            self.assertNotEqual(res_control["cascade_path"], "TAINT_PROPAGATED")


if __name__ == "__main__":
    unittest.main()
