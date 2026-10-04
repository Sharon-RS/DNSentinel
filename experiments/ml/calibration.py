"""
DNSentinel Phase 6D: Threshold Calibration & Parameter Freezing Module.

Calibrates decision thresholds, hybrid fusion weights, and cascade cutoffs
EXCLUSIVELY on the Validation Partition (1,276 records).
Enforces the operational security constraint: False Positive Rate <= 5.0%.
Freezes all parameters into an immutable configuration before test evaluation.
"""

from dataclasses import dataclass, asdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import precision_recall_curve, auc


@dataclass
class FrozenCalibrationConfig:
    max_operational_fpr: float
    # Behavioral Baseline Calibration
    behavioral_threshold: float
    behavioral_val_recall: float
    behavioral_val_fpr: float
    # ML30 Calibration
    ml30_threshold: float
    ml30_val_recall: float
    ml30_val_fpr: float
    # ML31 Calibration
    ml31_threshold: float
    ml31_val_recall: float
    ml31_val_fpr: float
    # Hybrid Calibration
    hybrid_beta: float
    hybrid_threshold: float
    hybrid_val_recall: float
    hybrid_val_fpr: float
    # Cascade Calibration
    cascade_s_low: float
    cascade_s_high: float
    cascade_ml_threshold: float
    cascade_val_recall: float
    cascade_val_fpr: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, filepath: Path) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, filepath: Path) -> "FrozenCalibrationConfig":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


def find_optimal_threshold(
    y_true: np.ndarray,
    scores_or_probs: np.ndarray,
    max_fpr: float = 0.050,
    is_probability: bool = True
) -> Tuple[float, float, float]:
    """
    Finds the decision threshold that maximizes Recall subject to FPR <= max_fpr.
    Returns: (optimal_threshold, achieved_recall, achieved_fpr)
    """
    negatives = np.sum(y_true == 0)
    positives = np.sum(y_true == 1)

    if negatives == 0 or positives == 0:
        return 0.5, 0.0, 0.0

    if is_probability:
        threshold_candidates = np.linspace(0.01, 0.99, 197)
    else:
        # Score range [0, 100]
        threshold_candidates = np.linspace(0.0, 100.0, 201)

    best_thresh = threshold_candidates[-1]
    best_recall = -1.0
    best_fpr = 1.0

    for thresh in threshold_candidates:
        y_pred = (scores_or_probs >= thresh).astype(np.int64)
        fp = np.sum((y_true == 0) & (y_pred == 1))
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fpr = fp / negatives
        recall = tp / positives

        if fpr <= max_fpr:
            # We want to maximize recall; if recall is tied, minimize FPR
            if recall > best_recall or (recall == best_recall and fpr < best_fpr):
                best_thresh = thresh
                best_recall = recall
                best_fpr = fpr

    return round(float(best_thresh), 4), round(float(best_recall), 4), round(float(best_fpr), 4)


def calibrate_hybrid_beta(
    y_true: np.ndarray,
    behavioral_scores: np.ndarray,
    ml_probs: np.ndarray,
    max_fpr: float = 0.050
) -> Tuple[float, float, float, float]:
    """
    Sweeps beta in [0.05, 0.95] for the ensemble:
      S_hybrid = beta * Score_behavior + (1 - beta) * (100 * P_ML)
    Selects (best_beta, best_threshold, achieved_recall, achieved_fpr).
    """
    beta_candidates = np.linspace(0.05, 0.95, 19)
    best_beta = 0.5
    best_thresh = 50.0
    best_recall = -1.0
    best_fpr = 1.0

    for beta in beta_candidates:
        hybrid_scores = beta * behavioral_scores + (1.0 - beta) * (100.0 * ml_probs)
        thresh, recall, fpr = find_optimal_threshold(
            y_true=y_true,
            scores_or_probs=hybrid_scores,
            max_fpr=max_fpr,
            is_probability=False
        )
        if recall > best_recall or (recall == best_recall and fpr < best_fpr):
            best_beta = beta
            best_thresh = thresh
            best_recall = recall
            best_fpr = fpr

    return (
        round(float(best_beta), 2),
        round(float(best_thresh), 4),
        round(float(best_recall), 4),
        round(float(best_fpr), 4)
    )


def calibrate_cascade_pipeline(
    y_true: np.ndarray,
    behavioral_scores: np.ndarray,
    ml_probs: np.ndarray,
    max_fpr: float = 0.050
) -> Tuple[float, float, float, float, float]:
    """
    Calibrates a tiered cascade pipeline:
      - If behavioral_score < S_low: Suppress immediately as Normal (label 0)
      - If behavioral_score >= S_high: Trigger immediately as Malicious (label 1)
      - Else: Escalate to ML model with decision threshold P_ml >= P_cascade
    Selects (S_low, S_high, P_cascade, achieved_recall, achieved_fpr)
    maximizing recall subject to FPR <= max_fpr.
    """
    negatives = np.sum(y_true == 0)
    positives = np.sum(y_true == 1)

    best_s_low = 30.0
    best_s_high = 70.0
    best_p_ml = 0.5
    best_recall = -1.0
    best_fpr = 1.0

    # Grid search across standard operational thresholds
    s_low_candidates = [20.0, 30.0, 35.0, 40.0]
    s_high_candidates = [60.0, 70.0, 80.0]
    p_ml_candidates = np.linspace(0.1, 0.9, 17)

    for s_low in s_low_candidates:
        for s_high in s_high_candidates:
            if s_low >= s_high:
                continue
            for p_ml in p_ml_candidates:
                # Fast path decisions
                y_pred = np.zeros(len(y_true), dtype=np.int64)
                y_pred[behavioral_scores >= s_high] = 1

                # Ambiguous window escalated to ML
                escalated = (behavioral_scores >= s_low) & (behavioral_scores < s_high)
                y_pred[escalated & (ml_probs >= p_ml)] = 1

                fp = np.sum((y_true == 0) & (y_pred == 1))
                tp = np.sum((y_true == 1) & (y_pred == 1))
                fpr = fp / negatives
                recall = tp / positives

                if fpr <= max_fpr:
                    if recall > best_recall or (recall == best_recall and fpr < best_fpr):
                        best_s_low = s_low
                        best_s_high = s_high
                        best_p_ml = p_ml
                        best_recall = recall
                        best_fpr = fpr

    return (
        round(float(best_s_low), 1),
        round(float(best_s_high), 1),
        round(float(best_p_ml), 4),
        round(float(best_recall), 4),
        round(float(best_fpr), 4)
    )


def calibrate_all_on_validation(
    y_val: np.ndarray,
    behavioral_scores_val: np.ndarray,
    ml30_probs_val: np.ndarray,
    ml31_probs_val: np.ndarray,
    max_operational_fpr: float = 0.050
) -> FrozenCalibrationConfig:
    """
    Rigorously tunes all thresholds and hyperparameters on the Validation Partition only.
    Returns frozen configuration ready to be applied once to Final Test.
    """
    # 1. Behavioral Baseline
    b_thresh, b_rec, b_fpr = find_optimal_threshold(
        y_val, behavioral_scores_val, max_fpr=max_operational_fpr, is_probability=False
    )

    # 2. ML30 Classifier
    m30_thresh, m30_rec, m30_fpr = find_optimal_threshold(
        y_val, ml30_probs_val, max_fpr=max_operational_fpr, is_probability=True
    )

    # 3. ML31 Classifier
    m31_thresh, m31_rec, m31_fpr = find_optimal_threshold(
        y_val, ml31_probs_val, max_fpr=max_operational_fpr, is_probability=True
    )

    # 4. Hybrid (Behavioral + ML30)
    h_beta, h_thresh, h_rec, h_fpr = calibrate_hybrid_beta(
        y_val, behavioral_scores_val, ml30_probs_val, max_fpr=max_operational_fpr
    )

    # 5. Cascaded Pipeline (Fast-path + ML30)
    c_low, c_high, c_ml_thresh, c_rec, c_fpr = calibrate_cascade_pipeline(
        y_val, behavioral_scores_val, ml30_probs_val, max_fpr=max_operational_fpr
    )

    return FrozenCalibrationConfig(
        max_operational_fpr=max_operational_fpr,
        behavioral_threshold=b_thresh,
        behavioral_val_recall=b_rec,
        behavioral_val_fpr=b_fpr,
        ml30_threshold=m30_thresh,
        ml30_val_recall=m30_rec,
        ml30_val_fpr=m30_fpr,
        ml31_threshold=m31_thresh,
        ml31_val_recall=m31_rec,
        ml31_val_fpr=m31_fpr,
        hybrid_beta=h_beta,
        hybrid_threshold=h_thresh,
        hybrid_val_recall=h_rec,
        hybrid_val_fpr=h_fpr,
        cascade_s_low=c_low,
        cascade_s_high=c_high,
        cascade_ml_threshold=c_ml_thresh,
        cascade_val_recall=c_rec,
        cascade_val_fpr=c_fpr
    )
