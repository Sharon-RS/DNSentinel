"""
Tests for Phase 6D: Machine Learning Evaluation, Calibration, and Metrics Engine.
"""

import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path
import numpy as np

from experiments.ml.causal_extractor import CausalMLFeatureExtractor
from experiments.ml.models import (
    DNSentinelClassifier,
    ML30_FEATURE_NAMES,
    ML31_FEATURE_NAMES,
    extract_feature_matrix,
    build_and_train_ml30,
    build_and_train_ml31,
)
from experiments.ml.calibration import (
    FrozenCalibrationConfig,
    find_optimal_threshold,
    calibrate_hybrid_beta,
    calibrate_cascade_pipeline,
    calibrate_all_on_validation,
)
from experiments.ml.metrics import (
    ALL_CAMPAIGNS,
    HELD_OUT_TEST_CAMPAIGNS,
    PerformanceMetrics,
    calculate_nearest_rank_percentile,
    compute_metrics,
)
from experiments.runners.run_ml_experiment import (
    load_dataset,
    TRAINING_CAMPAIGNS,
    HELD_OUT_TEST_CAMPAIGNS_SET,
)


class TestMLEvaluation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_feature_names_and_group_definitions(self):
        """Validates ML30 (30 raw features) vs ML31 (31 features incl. behavior)."""
        self.assertEqual(len(ML30_FEATURE_NAMES), 30)
        self.assertEqual(len(ML31_FEATURE_NAMES), 31)
        self.assertNotIn("behavior_score", ML30_FEATURE_NAMES)
        self.assertIn("behavior_score", ML31_FEATURE_NAMES)
        self.assertEqual(ML31_FEATURE_NAMES[-1], "behavior_score")

        # Verify no forbidden identifiers leaked into feature set
        for fname in ML31_FEATURE_NAMES:
            self.assertNotIn("ip", fname)
            self.assertNotIn("raw_domain", fname)
            self.assertNotIn("timestamp", fname)
            self.assertNotIn("provenance", fname)

    def test_feature_matrix_extraction(self):
        """Verifies conversion of record dicts to 2D numpy matrix."""
        sample_records = [
            {
                "label": 0,
                "features": {f: 1.0 for f in ML31_FEATURE_NAMES}
            },
            {
                "label": 1,
                "features": {f: 2.0 for f in ML31_FEATURE_NAMES}
            }
        ]
        X30, y30 = extract_feature_matrix(sample_records, ML30_FEATURE_NAMES)
        X31, y31 = extract_feature_matrix(sample_records, ML31_FEATURE_NAMES)

        self.assertEqual(X30.shape, (2, 30))
        self.assertEqual(X31.shape, (2, 31))
        self.assertEqual(list(y30), [0, 1])
        self.assertEqual(list(y31), [0, 1])
        self.assertEqual(X30[0, 0], 1.0)
        self.assertEqual(X30[1, 0], 2.0)

    def test_classifier_fit_predict_and_serialization(self):
        """Verifies deterministic Random Forest fitting, inference, and serialization."""
        rng = np.random.RandomState(42)
        X_synth = rng.randn(100, 30)
        y_synth = (X_synth[:, 0] + X_synth[:, 1] > 0).astype(np.int64)

        clf = DNSentinelClassifier(
            name="TestClf",
            feature_names=ML30_FEATURE_NAMES,
            n_estimators=10,
            max_depth=4,
            random_state=42
        )
        clf.fit(X_synth, y_synth)
        self.assertTrue(clf.is_fitted)

        probs = clf.predict_proba(X_synth)
        self.assertEqual(len(probs), 100)
        self.assertTrue(np.all((probs >= 0.0) & (probs <= 1.0)))

        preds = clf.predict(X_synth, threshold=0.5)
        self.assertEqual(len(preds), 100)
        self.assertTrue(np.all(np.isin(preds, [0, 1])))

        # Feature importances
        importances = clf.get_feature_importances()
        self.assertEqual(len(importances), 30)
        self.assertAlmostEqual(sum(importances.values()), 1.0, places=2)

        # Serialization round-trip
        model_path = self.temp_dir / "test_model.joblib"
        clf.save(model_path)
        self.assertTrue(model_path.exists())

        loaded_clf = DNSentinelClassifier.load(model_path)
        self.assertTrue(loaded_clf.is_fitted)
        loaded_probs = loaded_clf.predict_proba(X_synth)
        np.testing.assert_allclose(probs, loaded_probs)

    def test_calibration_enforces_fpr_constraint(self):
        """Verifies threshold calibration satisfies operational constraint FPR <= 5.0%."""
        y_true = np.array([0] * 100 + [1] * 100)
        # Synthetic scores with slight overlap
        scores = np.concatenate([
            np.linspace(10.0, 60.0, 100),  # negatives
            np.linspace(40.0, 95.0, 100),  # positives
        ])

        thresh, rec, fpr = find_optimal_threshold(
            y_true=y_true,
            scores_or_probs=scores,
            max_fpr=0.050,
            is_probability=False
        )
        self.assertLessEqual(fpr, 0.050)
        self.assertGreater(rec, 0.0)

        # Frozen calibration config serialization
        calib_cfg = FrozenCalibrationConfig(
            max_operational_fpr=0.050,
            behavioral_threshold=thresh,
            behavioral_val_recall=rec,
            behavioral_val_fpr=fpr,
            ml30_threshold=0.55,
            ml30_val_recall=0.88,
            ml30_val_fpr=0.03,
            ml31_threshold=0.52,
            ml31_val_recall=0.91,
            ml31_val_fpr=0.02,
            hybrid_beta=0.45,
            hybrid_threshold=52.0,
            hybrid_val_recall=0.92,
            hybrid_val_fpr=0.025,
            cascade_s_low=30.0,
            cascade_s_high=70.0,
            cascade_ml_threshold=0.50,
            cascade_val_recall=0.90,
            cascade_val_fpr=0.028,
        )
        cfg_path = self.temp_dir / "calibration.json"
        calib_cfg.save(cfg_path)
        self.assertTrue(cfg_path.exists())

        loaded_cfg = FrozenCalibrationConfig.load(cfg_path)
        self.assertEqual(loaded_cfg.max_operational_fpr, 0.050)
        self.assertEqual(loaded_cfg.behavioral_threshold, thresh)

    def test_nearest_rank_percentile(self):
        """Verifies deterministic nearest-rank percentile calculation."""
        data = list(range(1, 101))  # 1 to 100
        p50 = calculate_nearest_rank_percentile(data, 50.0)
        p99 = calculate_nearest_rank_percentile(data, 99.0)
        p100 = calculate_nearest_rank_percentile(data, 100.0)
        self.assertEqual(p50, 50)
        self.assertEqual(p99, 99)
        self.assertEqual(p100, 100)

    def test_compute_metrics_accuracy_and_confusion_matrix(self):
        """Verifies confusion matrix and metrics accuracy."""
        y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        y_pred = np.array([0, 0, 0, 1, 0, 1, 1, 1])
        scores = np.array([0.1, 0.2, 0.3, 0.8, 0.4, 0.7, 0.8, 0.9])
        prov = ["benign"] * 4 + ["campaign_c2_stealth_gamma"] * 4

        m = compute_metrics(
            configuration="TestSys",
            dataset_partition="TestPartition",
            y_true=y_true,
            y_pred=y_pred,
            scores_or_probs=scores,
            provenance_list=prov,
            threshold=0.5,
            latencies_ns=[1000, 2000, 1500, 1800, 1200, 1300, 1400, 1600],
        )

        self.assertEqual(m.total_samples, 8)
        self.assertEqual(m.true_negatives, 3)
        self.assertEqual(m.false_positives, 1)
        self.assertEqual(m.false_negatives, 1)
        self.assertEqual(m.true_positives, 3)
        self.assertAlmostEqual(m.accuracy, 6 / 8, places=3)
        self.assertAlmostEqual(m.precision, 3 / 4, places=3)
        self.assertAlmostEqual(m.recall, 3 / 4, places=3)
        self.assertAlmostEqual(m.false_positive_rate, 1 / 4, places=3)
        self.assertAlmostEqual(m.zero_day_recall, 3 / 4, places=3)
        self.assertGreater(m.latency_p50_us, 0.0)
        self.assertGreater(m.latency_p99_us, 0.0)

    def test_partition_isolation_and_integrity(self):
        """Validates the frozen Phase 6C Architecture 1 dataset partitions."""
        feat_records, bench_records, partitions = load_dataset()

        # Check total record count
        self.assertEqual(len(feat_records), 6000)
        self.assertEqual(len(bench_records), 6000)

        # Check partition counts
        self.assertEqual(len(partitions["train"]), 3010)
        self.assertEqual(len(partitions["val"]), 1276)
        self.assertEqual(len(partitions["test"]), 1714)
        self.assertEqual(3010 + 1276 + 1714, 6000)

        # Check disjointness of partitions
        train_set = set(partitions["train"])
        val_set = set(partitions["val"])
        test_set = set(partitions["test"])
        self.assertEqual(len(train_set.intersection(val_set)), 0)
        self.assertEqual(len(train_set.intersection(test_set)), 0)
        self.assertEqual(len(val_set.intersection(test_set)), 0)

        # Check campaign isolation
        train_provs = {bench_records[i]["provenance"] for i in partitions["train"]}
        val_provs = {bench_records[i]["provenance"] for i in partitions["val"]}
        test_provs = {bench_records[i]["provenance"] for i in partitions["test"]}

        # Held-out campaigns must NOT exist in train or val
        for camp in HELD_OUT_TEST_CAMPAIGNS:
            self.assertNotIn(camp, train_provs)
            self.assertNotIn(camp, val_provs)
            self.assertIn(camp, test_provs)

        # Training campaigns must NOT exist in test
        for camp in TRAINING_CAMPAIGNS:
            self.assertNotIn(camp, test_provs)


if __name__ == "__main__":
    unittest.main()
