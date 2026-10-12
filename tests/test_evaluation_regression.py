"""
Regression tests for DNSentinel Four-Pipeline Evaluation Results and Metrics Invariants.
Verifies:
1. Confusion matrix completeness (TP + FP + TN + FN == N) across all workloads.
2. Proper representation of mathematically undefined metrics (None / null).
3. Exact audited confusion matrix numbers and recall on historical and held-out traces.
4. Correctness of missed attack queries (#1 hello.attacker.lab, #10, #19, #28, #37 *.end.attacker.lab).
5. Untested status of danger.edu hard negatives on the held-out partition.
"""

import json
import unittest
from pathlib import Path

from src.utils.config import Config


class TestEvaluationReportRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results_file = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation.json"
        cls.report_file = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation_report.md"

        if not cls.results_file.exists():
            raise FileNotFoundError(f"Missing evaluation results file: {cls.results_file}")
        if not cls.report_file.exists():
            raise FileNotFoundError(f"Missing evaluation report file: {cls.report_file}")

        with open(cls.results_file, "r", encoding="utf-8") as f:
            cls.results = json.load(f)

        with open(cls.report_file, "r", encoding="utf-8") as f:
            cls.report_md = f.read()

    def test_workload_keys_exist(self):
        expected_keys = [
            "Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)",
            "Historical Lab Benign Trace (lab_trace_benign.jsonl)",
            "Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)",
            "Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)",
            "Phase 6D Held-Out Zero-Day Benchmark Partition",
        ]
        for key in expected_keys:
            self.assertIn(key, self.results, f"Missing workload key: {key}")

    def test_confusion_matrix_invariants_and_undefined_metrics(self):
        for w_name, w_data in self.results.items():
            pipelines = w_data["pipelines"]
            for p_name, m in pipelines.items():
                # Totals
                self.assertEqual(
                    m["tp"] + m["fn"],
                    m["pos_count"],
                    f"[{w_name}][{p_name}] TP + FN != pos_count"
                )
                self.assertEqual(
                    m["fp"] + m["tn"],
                    m["neg_count"],
                    f"[{w_name}][{p_name}] FP + TN != neg_count"
                )
                self.assertEqual(
                    m["tp"] + m["fp"] + m["tn"] + m["fn"],
                    m["n"],
                    f"[{w_name}][{p_name}] Confusion sum != n"
                )
                self.assertEqual(
                    m["direct_detections"] + m["taint_detections"],
                    m["tp"] + m["fp"],
                    f"[{w_name}][{p_name}] Detection breakdown != TP + FP"
                )

                # Undefined metric representation
                if m["pos_count"] == 0:
                    self.assertIsNone(m["recall"], f"[{w_name}][{p_name}] Recall should be None when pos_count == 0")
                    self.assertIsNone(m["f1"], f"[{w_name}][{p_name}] F1 should be None when pos_count == 0")
                if m["neg_count"] == 0:
                    self.assertIsNone(m["fpr"], f"[{w_name}][{p_name}] FPR should be None when neg_count == 0")
                if (m["tp"] + m["fp"]) == 0:
                    self.assertIsNone(m["precision"], f"[{w_name}][{p_name}] Precision should be None when TP + FP == 0")
                    self.assertIsNone(m["f1"], f"[{w_name}][{p_name}] F1 should be None when TP + FP == 0")

    def test_tunnel_burst_audited_counts(self):
        tb = self.results["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["pipelines"]
        self.assertEqual(tb["Pipeline A1"]["tp"], 36)
        self.assertEqual(tb["Pipeline A1"]["fn"], 79)
        self.assertEqual(tb["Pipeline A1"]["contamination"], 79)
        self.assertEqual(tb["Pipeline A1"]["recall"], 0.313)

        self.assertEqual(tb["Pipeline B"]["tp"], 65)
        self.assertEqual(tb["Pipeline B"]["fn"], 50)
        self.assertEqual(tb["Pipeline B"]["contamination"], 0)
        self.assertEqual(tb["Pipeline B"]["recall"], 0.5652)

        self.assertEqual(tb["ML30 Cascade"]["tp"], 110)
        self.assertEqual(tb["ML30 Cascade"]["fn"], 5)
        self.assertEqual(tb["ML30 Cascade"]["contamination"], 0)
        self.assertEqual(tb["ML30 Cascade"]["recall"], 0.9565)

        self.assertEqual(tb["ML30 + Burst-Taint"]["tp"], 114)
        self.assertEqual(tb["ML30 + Burst-Taint"]["fn"], 1)
        self.assertEqual(tb["ML30 + Burst-Taint"]["contamination"], 0)
        self.assertEqual(tb["ML30 + Burst-Taint"]["recall"], 0.9913)
        self.assertEqual(tb["ML30 + Burst-Taint"]["taint_detections"], 4)

    def test_missed_queries_breakdown(self):
        missed = self.results["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"]
        self.assertEqual(len(missed), 5)

        expected = [
            (1, "hello.attacker.lab", "BENIGN", "DIRECT_CLEAR"),
            (10, "525443.end.attacker.lab", "MALICIOUS", "TAINT_PROPAGATED"),
            (19, "0c8e0e.end.attacker.lab", "MALICIOUS", "TAINT_PROPAGATED"),
            (28, "626833.end.attacker.lab", "MALICIOUS", "TAINT_PROPAGATED"),
            (37, "b78dd1.end.attacker.lab", "MALICIOUS", "TAINT_PROPAGATED"),
        ]

        for item, (exp_idx, exp_dom, exp_taint_dec, exp_source) in zip(missed, expected):
            self.assertEqual(item["1_based_index"], exp_idx)
            self.assertEqual(item["domain"], exp_dom)
            self.assertEqual(item["cascade_decision"], "BENIGN")
            self.assertEqual(item["burst_taint_decision"], exp_taint_dec)
            self.assertEqual(item["burst_taint_detection_source"], exp_source)

    def test_held_out_benchmark_audited_numbers(self):
        ho = self.results["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]

        # Pipeline A1
        self.assertEqual(ho["Pipeline A1"]["tp"], 338)
        self.assertEqual(ho["Pipeline A1"]["fp"], 300)
        self.assertEqual(ho["Pipeline A1"]["tn"], 498)
        self.assertEqual(ho["Pipeline A1"]["fn"], 578)
        self.assertEqual(ho["Pipeline A1"]["recall"], 0.369)
        self.assertEqual(ho["Pipeline A1"]["fpr"], 0.3759)

        # Pipeline B
        self.assertEqual(ho["Pipeline B"]["tp"], 427)
        self.assertEqual(ho["Pipeline B"]["fp"], 124)
        self.assertEqual(ho["Pipeline B"]["tn"], 674)
        self.assertEqual(ho["Pipeline B"]["fn"], 489)
        self.assertEqual(ho["Pipeline B"]["recall"], 0.4662)
        self.assertEqual(ho["Pipeline B"]["fpr"], 0.1554)

        # ML30 Cascade
        self.assertEqual(ho["ML30 Cascade"]["tp"], 916)
        self.assertEqual(ho["ML30 Cascade"]["fp"], 0)
        self.assertEqual(ho["ML30 Cascade"]["tn"], 798)
        self.assertEqual(ho["ML30 Cascade"]["fn"], 0)
        self.assertEqual(ho["ML30 Cascade"]["recall"], 1.0)
        self.assertEqual(ho["ML30 Cascade"]["fpr"], 0.0)

        # ML30 + Burst-Taint
        self.assertEqual(ho["ML30 + Burst-Taint"]["tp"], 916)
        self.assertEqual(ho["ML30 + Burst-Taint"]["fp"], 0)
        self.assertEqual(ho["ML30 + Burst-Taint"]["tn"], 798)
        self.assertEqual(ho["ML30 + Burst-Taint"]["fn"], 0)
        self.assertEqual(ho["ML30 + Burst-Taint"]["recall"], 1.0)
        self.assertEqual(ho["ML30 + Burst-Taint"]["fpr"], 0.0)

        # Untested Danger.edu status
        status = self.results["Phase 6D Held-Out Zero-Day Benchmark Partition"]["hard_negative_danger_edu_status"]
        self.assertEqual(status, "UNTESTED_IN_PARTITION")


if __name__ == "__main__":
    unittest.main()
