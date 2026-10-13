"""
Automated regression tests for DNSentinel Four-Pipeline Publication Figures and Summary Tables.

Validates:
1. Existence and valid binary format (PNG magic header, file size > 30KB) of all 5 research figures.
2. Existence and consistency of Markdown summary tables and README.
3. Strict provenance separation across evaluation workloads (no cross-workload metric merging).
4. Correct representation of undefined metrics as None / N/A (never substituted with zero).
5. Dataset sample size invariants:
   - Tunnel Burst Trace: N = 115 (Pos = 115, Neg = 0)
   - Benign Lab Trace: N = 119 (Pos = 0, Neg = 119)
   - Synthetic Cold Host: N = 100 (Pos = 0, Neg = 100)
   - Combined Lab Stream: N = 234 (Pos = 115, Neg = 119)
   - Held-Out Zero-Day Benchmark: N = 1,714 (Pos = 916, Neg = 798)
6. Exact audited key metric values across all 4 detection pipelines.
"""

import json
import unittest
from pathlib import Path

from src.utils.config import Config


class TestEvaluationFiguresAndArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.figures_dir = Config.PROJECT_ROOT / "experiments" / "results" / "figures" / "evaluation"
        cls.tables_dir = Config.PROJECT_ROOT / "experiments" / "results" / "tables"
        cls.source_json = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation.json"
        cls.source_report = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation_report.md"

        cls.expected_figures = [
            "fig01_combined_stream_recall_fpr.png",
            "fig02_latency_comparison.png",
            "fig03_confusion_matrices.png",
            "fig04_direct_vs_taint_detections.png",
            "fig05_cross_workload_provenance.png"
        ]

        if not cls.source_json.exists():
            raise FileNotFoundError(f"Missing source evaluation JSON: {cls.source_json}")

        with open(cls.source_json, "r", encoding="utf-8") as f:
            cls.data = json.load(f)

    def test_figures_exist_and_valid_png_headers(self):
        """Verifies each expected figure exists, has valid PNG magic bytes, and reasonable file size."""
        png_magic = b"\x89PNG\r\n\x1a\n"
        for fig_name in self.expected_figures:
            fig_path = self.figures_dir / fig_name
            self.assertTrue(fig_path.exists(), f"Figure missing: {fig_path}")

            file_size = fig_path.stat().st_size
            self.assertGreater(file_size, 30000, f"Figure file size too small ({file_size} bytes): {fig_path}")

            with open(fig_path, "rb") as f:
                header = f.read(8)
                self.assertEqual(header, png_magic, f"File is not a valid PNG image: {fig_path}")

    def test_summary_tables_and_readme_exist(self):
        """Verifies that canonical Table 5 and the figure README exist and are non-empty."""
        t5_path = self.tables_dir / "table5_four_pipeline_evaluation.md"
        readme_path = self.figures_dir / "README.md"

        self.assertTrue(t5_path.exists(), f"Summary table missing: {t5_path}")
        self.assertTrue(readme_path.exists(), f"Figure README missing: {readme_path}")

        self.assertGreater(t5_path.stat().st_size, 500, "Table 5 unexpectedly empty")
        self.assertGreater(readme_path.stat().st_size, 1000, "Figure README unexpectedly empty")

        with open(t5_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Table 5: Comprehensive DNSentinel Four-Pipeline Performance Profile", content)
            self.assertIn("N/A", content, "Table 5 must explicitly represent undefined metrics as N/A")

    def test_workload_sample_sizes_and_class_distributions(self):
        """Verifies exact sample sizes and positive/negative ground-truth counts across all 5 workloads."""
        workload_specs = {
            "Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)": (115, 115, 0),
            "Historical Lab Benign Trace (lab_trace_benign.jsonl)": (119, 0, 119),
            "Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)": (100, 0, 100),
            "Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)": (234, 115, 119),
            "Phase 6D Held-Out Zero-Day Benchmark Partition": (1714, 916, 798),
        }

        for w_key, (exp_n, exp_pos, exp_neg) in workload_specs.items():
            self.assertIn(w_key, self.data, f"Workload key missing: {w_key}")
            w_data = self.data[w_key]
            self.assertEqual(w_data["sample_size"], exp_n, f"Sample size mismatch for {w_key}")

            for p_name, m in w_data["pipelines"].items():
                self.assertEqual(m["n"], exp_n, f"[{w_key}][{p_name}] n != {exp_n}")
                self.assertEqual(m["pos_count"], exp_pos, f"[{w_key}][{p_name}] pos_count != {exp_pos}")
                self.assertEqual(m["neg_count"], exp_neg, f"[{w_key}][{p_name}] neg_count != {exp_neg}")

    def test_combined_stream_key_metrics(self):
        """Verifies exact recall, FPR, and confusion counts on the Combined Historical Lab Stream (N=234)."""
        comb = self.data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]

        # Pipeline A1: Unmitigated baseline suffers severe self-poisoning
        self.assertEqual(comb["Pipeline A1"]["tp"], 36)
        self.assertEqual(comb["Pipeline A1"]["fp"], 116)
        self.assertEqual(comb["Pipeline A1"]["tn"], 3)
        self.assertEqual(comb["Pipeline A1"]["fn"], 79)
        self.assertAlmostEqual(comb["Pipeline A1"]["recall"], 0.313, places=3)
        self.assertAlmostEqual(comb["Pipeline A1"]["fpr"], 0.9748, places=4)

        # Pipeline B: Dual-baseline mitigation prevents self-poisoning
        self.assertEqual(comb["Pipeline B"]["tp"], 65)
        self.assertEqual(comb["Pipeline B"]["fp"], 5)
        self.assertEqual(comb["Pipeline B"]["tn"], 114)
        self.assertEqual(comb["Pipeline B"]["fn"], 50)
        self.assertAlmostEqual(comb["Pipeline B"]["recall"], 0.5652, places=4)
        self.assertAlmostEqual(comb["Pipeline B"]["fpr"], 0.042, places=3)

        # ML30 Cascade: Fast-path + RF
        self.assertEqual(comb["ML30 Cascade"]["tp"], 110)
        self.assertEqual(comb["ML30 Cascade"]["fp"], 2)
        self.assertEqual(comb["ML30 Cascade"]["tn"], 117)
        self.assertEqual(comb["ML30 Cascade"]["fn"], 5)
        self.assertAlmostEqual(comb["ML30 Cascade"]["recall"], 0.9565, places=4)
        self.assertAlmostEqual(comb["ML30 Cascade"]["fpr"], 0.0168, places=4)

        # ML30 + Burst-Taint: Delimiter recovery brings recall to 99.13%
        self.assertEqual(comb["ML30 + Burst-Taint"]["tp"], 114)
        self.assertEqual(comb["ML30 + Burst-Taint"]["fp"], 2)
        self.assertEqual(comb["ML30 + Burst-Taint"]["tn"], 117)
        self.assertEqual(comb["ML30 + Burst-Taint"]["fn"], 1)
        self.assertEqual(comb["ML30 + Burst-Taint"]["direct_detections"], 112)
        self.assertEqual(comb["ML30 + Burst-Taint"]["taint_detections"], 4)
        self.assertAlmostEqual(comb["ML30 + Burst-Taint"]["recall"], 0.9913, places=4)
        self.assertAlmostEqual(comb["ML30 + Burst-Taint"]["fpr"], 0.0168, places=4)

    def test_held_out_benchmark_metrics(self):
        """Verifies exact recall, FPR, and confusion counts on the Held-Out Benchmark (N=1,714)."""
        ho = self.data["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]

        # Behavioral heuristics struggle on cold hosts
        self.assertEqual(ho["Pipeline A1"]["tp"], 338)
        self.assertEqual(ho["Pipeline A1"]["fp"], 300)
        self.assertAlmostEqual(ho["Pipeline A1"]["recall"], 0.3690, places=4)

        self.assertEqual(ho["Pipeline B"]["tp"], 427)
        self.assertEqual(ho["Pipeline B"]["fp"], 124)
        self.assertAlmostEqual(ho["Pipeline B"]["recall"], 0.4662, places=4)

        # ML cascades achieve 100% recall and 0% FPR
        self.assertEqual(ho["ML30 Cascade"]["tp"], 916)
        self.assertEqual(ho["ML30 Cascade"]["fp"], 0)
        self.assertEqual(ho["ML30 Cascade"]["tn"], 798)
        self.assertEqual(ho["ML30 Cascade"]["fn"], 0)
        self.assertAlmostEqual(ho["ML30 Cascade"]["recall"], 1.0, places=4)
        self.assertAlmostEqual(ho["ML30 Cascade"]["fpr"], 0.0, places=4)

        self.assertEqual(ho["ML30 + Burst-Taint"]["tp"], 916)
        self.assertEqual(ho["ML30 + Burst-Taint"]["fp"], 0)
        self.assertEqual(ho["ML30 + Burst-Taint"]["tn"], 798)
        self.assertEqual(ho["ML30 + Burst-Taint"]["fn"], 0)
        self.assertAlmostEqual(ho["ML30 + Burst-Taint"]["recall"], 1.0, places=4)
        self.assertAlmostEqual(ho["ML30 + Burst-Taint"]["fpr"], 0.0, places=4)

    def test_delimiter_burst_taint_breakdown(self):
        """Verifies the exact 5 queries that fall below the direct ML threshold (P < 0.20)."""
        missed = self.data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"]
        self.assertEqual(len(missed), 5)

        # Query #1: hello.attacker.lab must not be taint-propagated (causal handshake)
        q1 = missed[0]
        self.assertEqual(q1["1_based_index"], 1)
        self.assertEqual(q1["domain"], "hello.attacker.lab")
        self.assertEqual(q1["burst_taint_decision"], "BENIGN")
        self.assertEqual(q1["burst_taint_detection_source"], "DIRECT_CLEAR")
        self.assertFalse(q1["burst_taint_propagated"])

        # Queries #10, #19, #28, #37: Delimiters must be taint-propagated
        expected_indices = [10, 19, 28, 37]
        for idx, expected_num in enumerate(expected_indices, start=1):
            q = missed[idx]
            self.assertEqual(q["1_based_index"], expected_num)
            self.assertTrue(q["domain"].endswith(".end.attacker.lab"))
            self.assertEqual(q["burst_taint_decision"], "MALICIOUS")
            self.assertEqual(q["burst_taint_detection_source"], "TAINT_PROPAGATED")
            self.assertTrue(q["burst_taint_propagated"])

    def test_strict_provenance_separation_and_undefined_metrics(self):
        """Verifies provenance tags and that undefined metrics are strictly represented as None."""
        # 1. Provenance separation tags
        self.assertEqual(self.data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["provenance_type"], "historical_lab")
        self.assertEqual(self.data["Historical Lab Benign Trace (lab_trace_benign.jsonl)"]["provenance_type"], "historical_lab")
        self.assertEqual(self.data["Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)"]["provenance_type"], "synthetic_scenario")
        self.assertEqual(self.data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["provenance_type"], "historical_lab")
        self.assertEqual(self.data["Phase 6D Held-Out Zero-Day Benchmark Partition"]["provenance_type"], "held_out_benchmark")

        # 2. Undefined metrics must be None in json
        tb_pipes = self.data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["pipelines"]
        for p in tb_pipes.values():
            self.assertIsNone(p["fpr"], "FPR must be None when neg_count == 0")

        benign_pipes = self.data["Historical Lab Benign Trace (lab_trace_benign.jsonl)"]["pipelines"]
        for p in benign_pipes.values():
            self.assertIsNone(p["recall"], "Recall must be None when pos_count == 0")
            self.assertIsNone(p["f1"], "F1 must be None when pos_count == 0")

        cold_pipes = self.data["Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)"]["pipelines"]
        for p in cold_pipes.values():
            self.assertIsNone(p["recall"], "Recall must be None when pos_count == 0")
            self.assertIsNone(p["f1"], "F1 must be None when pos_count == 0")


if __name__ == "__main__":
    unittest.main()
