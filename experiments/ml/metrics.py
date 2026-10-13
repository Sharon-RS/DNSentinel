"""
DNSentinel Phase 6D: Comprehensive Research Metrics Engine.

Computes confusion matrix, classification metrics (accuracy, precision, recall,
F1, FPR, FNR), ROC-AUC, PR-AUC, per-campaign recall breakdown, zero-day recall,
hard-negative evaluation, and nearest-rank P50/P99 latency benchmarks.
"""

from dataclasses import dataclass, asdict
import math
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, roc_curve


HELD_OUT_TEST_CAMPAIGNS: List[str] = [
    "campaign_c2_stealth_gamma",
    "campaign_tunnel_base64_zeta",
    "campaign_tunnel_random_theta",
    "campaign_exfil_chunk_iota"
]

ALL_CAMPAIGNS: List[str] = [
    "campaign_c2_stealth_alpha",
    "campaign_c2_stealth_beta",
    "campaign_c2_stealth_gamma",
    "campaign_tunnel_hex_delta",
    "campaign_tunnel_base32_epsilon",
    "campaign_tunnel_base64_zeta",
    "campaign_tunnel_random_theta",
    "campaign_exfil_chunk_eta",
    "campaign_exfil_chunk_iota"
]


@dataclass
class PerformanceMetrics:
    configuration: str
    dataset_partition: str
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    pr_auc: float
    # Operational evaluation metrics
    operating_threshold: float
    zero_day_recall: float
    hard_negative_fp_count: int
    hard_negative_fp_rate: float
    per_campaign_recall: Dict[str, Dict[str, Any]]
    # High-precision empirical latency (microseconds per query)
    latency_p50_us: float
    latency_p99_us: float
    latency_mean_us: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_nearest_rank_percentile(data: List[float], percentile: float) -> float:
    """Computes nearest-rank percentile (0.0 to 100.0) deterministically."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    rank = int(math.ceil((percentile / 100.0) * n))
    idx = max(0, min(rank - 1, n - 1))
    return sorted_data[idx]


def compute_metrics(
    configuration: str,
    dataset_partition: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores_or_probs: np.ndarray,
    provenance_list: List[str],
    threshold: float,
    latencies_ns: Optional[List[int]] = None
) -> PerformanceMetrics:
    """
    Computes all standard classification and cybersecurity evaluation metrics.
    """
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    total = len(y_true)
    positives = tp + fn
    negatives = tn + fp

    accuracy = round(float((tp + tn) / total), 4) if total > 0 else 0.0
    precision = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
    recall = round(float(tp / positives), 4) if positives > 0 else 0.0
    f1 = round(float(2 * precision * recall / (precision + recall)), 4) if (precision + recall) > 0 else 0.0
    fpr = round(float(fp / negatives), 4) if negatives > 0 else 0.0
    fnr = round(float(fn / positives), 4) if positives > 0 else 0.0

    # ROC-AUC and PR-AUC
    try:
        if len(np.unique(y_true)) > 1:
            roc_auc = round(float(roc_auc_score(y_true, scores_or_probs)), 4)
            precisions, recalls, _ = precision_recall_curve(y_true, scores_or_probs)
            pr_auc = round(float(auc(recalls, precisions)), 4)
        else:
            roc_auc = 1.0
            pr_auc = 1.0
    except Exception:
        roc_auc = 0.0
        pr_auc = 0.0

    # Per-campaign breakdown
    per_campaign = {}
    for camp in ALL_CAMPAIGNS:
        indices = [i for i, prov in enumerate(provenance_list) if prov == camp]
        if indices:
            camp_y_true = y_true[indices]
            camp_y_pred = y_pred[indices]
            camp_tp = int(np.sum((camp_y_true == 1) & (camp_y_pred == 1)))
            camp_total = len(indices)
            camp_rec = round(float(camp_tp / camp_total), 4) if camp_total > 0 else 0.0
            per_campaign[camp] = {
                "total": camp_total,
                "detected": camp_tp,
                "recall": camp_rec
            }

    # Zero-day recall (aggregate across the 4 unseen campaigns)
    zero_day_indices = [
        i for i, prov in enumerate(provenance_list)
        if prov in HELD_OUT_TEST_CAMPAIGNS
    ]
    if zero_day_indices:
        zd_tp = int(np.sum((y_true[zero_day_indices] == 1) & (y_pred[zero_day_indices] == 1)))
        zero_day_recall = round(float(zd_tp / len(zero_day_indices)), 4)
    else:
        zero_day_recall = 0.0

    # Hard-negative evaluation (danger.edu)
    hn_indices = [
        i for i, prov in enumerate(provenance_list)
        if prov == "authentic_lab_trace_hard_negative_danger_edu"
    ]
    if hn_indices:
        hn_fp = int(np.sum(y_pred[hn_indices] == 1))
        hn_rate = round(float(hn_fp / len(hn_indices)), 4)
    else:
        hn_fp = 0
        hn_rate = 0.0

    # Latencies in microseconds
    if latencies_ns:
        lat_us = [ns / 1000.0 for ns in latencies_ns]
        p50_us = round(calculate_nearest_rank_percentile(lat_us, 50.0), 2)
        p99_us = round(calculate_nearest_rank_percentile(lat_us, 99.0), 2)
        mean_us = round(float(np.mean(lat_us)), 2)
    else:
        p50_us = 0.0
        p99_us = 0.0
        mean_us = 0.0

    return PerformanceMetrics(
        configuration=configuration,
        dataset_partition=dataset_partition,
        total_samples=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        operating_threshold=round(float(threshold), 4),
        zero_day_recall=zero_day_recall,
        hard_negative_fp_count=hn_fp,
        hard_negative_fp_rate=hn_rate,
        per_campaign_recall=per_campaign,
        latency_p50_us=p50_us,
        latency_p99_us=p99_us,
        latency_mean_us=mean_us
    )
