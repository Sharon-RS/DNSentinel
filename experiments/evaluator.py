import math
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from experiments.context import IsolatedEvaluationContext
from src.pipeline.detection_pipeline import DetectionPipeline


@dataclass
class EvaluationMetrics:
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    # Binary metrics (Target Class: Tunneling / Positive)
    precision: float
    recall: float
    f1_score: float
    binary_precision: float
    binary_recall: float
    binary_f1: float
    # Class-weighted metrics (Weighted by class support N_0, N_1)
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    false_positive_rate: float
    false_negative_rate: float
    baseline_contamination_count: int
    # Empirical latency measurements (milliseconds per query)
    mean_latency_ms: float
    median_latency_ms: float
    p99_latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DNSentinelEvaluator:
    """
    Deterministic evaluation engine for DNSentinel.
    Processes labeled query streams and computes empirical research metrics.
    """

    def __init__(self, pipeline: Optional[DetectionPipeline] = None):
        self.pipeline = pipeline

    def evaluate_stream(
        self,
        events: List[Dict[str, Any]],
        pipeline: Optional[DetectionPipeline] = None
    ) -> EvaluationMetrics:
        """
        Processes a sequence of events.
        Each event must contain:
          - 'host': str
          - 'domain': str
          - 'features': dict (entropy, domain_length, query_type, optional timestamp)
          - 'label': int (0 = benign, 1 = malicious / tunneling)
        """
        active_pipeline = pipeline or self.pipeline
        if active_pipeline is None:
            raise ValueError("No DetectionPipeline provided for evaluation.")

        tp = 0
        fp = 0
        tn = 0
        fn = 0
        contamination_count = 0
        latencies_ms = []

        for event in events:
            host = event["host"]
            domain = event["domain"]
            features = event["features"]
            true_label = int(event["label"])

            t_start = time.perf_counter_ns()
            result = active_pipeline.process(host, domain, features)
            t_end = time.perf_counter_ns()
            latencies_ms.append((t_end - t_start) / 1_000_000.0)

            # Classify: SUSPICIOUS and HIGH_RISK are flagged as positive (tunneling)
            predicted_label = 1 if result["risk_level"] in ("SUSPICIOUS", "HIGH_RISK") else 0

            if true_label == 1 and predicted_label == 1:
                tp += 1
            elif true_label == 0 and predicted_label == 1:
                fp += 1
            elif true_label == 0 and predicted_label == 0:
                tn += 1
            elif true_label == 1 and predicted_label == 0:
                fn += 1

            # Contamination Guard Verification:
            # Did a malicious query trigger baseline learning?
            if true_label == 1 and result.get("baseline_updated") is True:
                contamination_count += 1

        total = tp + fp + tn + fn
        accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0

        # Binary metrics (Class 1 = Tunneling)
        bin_prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        bin_rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        bin_f1 = (
            round(2 * (bin_prec * bin_rec) / (bin_prec + bin_rec), 4)
            if (bin_prec + bin_rec) > 0
            else 0.0
        )

        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

        # Benign metrics (Class 0) for weighted average
        benign_prec = round(tn / (tn + fn), 4) if (tn + fn) > 0 else 0.0
        benign_rec = round(tn / (tn + fp), 4) if (tn + fp) > 0 else 0.0
        benign_f1 = (
            round(2 * (benign_prec * benign_rec) / (benign_prec + benign_rec), 4)
            if (benign_prec + benign_rec) > 0
            else 0.0
        )

        n_benign = tn + fp
        n_malicious = tp + fn
        if total > 0:
            weighted_prec = round(
                (n_benign * benign_prec + n_malicious * bin_prec) / total,
                4
            )
            weighted_rec = round(
                (n_benign * benign_rec + n_malicious * bin_rec) / total,
                4
            )
            weighted_f1 = round(
                (n_benign * benign_f1 + n_malicious * bin_f1) / total,
                4
            )
        else:
            weighted_prec = 0.0
            weighted_rec = 0.0
            weighted_f1 = 0.0

        # Empirical Latency Statistics (ms)
        if latencies_ms:
            sorted_lat = sorted(latencies_ms)
            n_lat = len(sorted_lat)
            mean_lat = round(sum(sorted_lat) / n_lat, 4)
            med_lat = round(
                sorted_lat[n_lat // 2]
                if n_lat % 2 != 0
                else (sorted_lat[n_lat // 2 - 1] + sorted_lat[n_lat // 2]) / 2.0,
                4
            )
            # Nearest-rank definition for p99 percentile: rank = ceil(0.99 * N), clamped to [1, N]
            rank = min(max(math.ceil(0.99 * n_lat), 1), n_lat)
            p99_lat = round(sorted_lat[rank - 1], 4)
        else:
            mean_lat, med_lat, p99_lat = 0.0, 0.0, 0.0

        return EvaluationMetrics(
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            accuracy=accuracy,
            precision=bin_prec,
            recall=bin_rec,
            f1_score=bin_f1,
            binary_precision=bin_prec,
            binary_recall=bin_rec,
            binary_f1=bin_f1,
            weighted_precision=weighted_prec,
            weighted_recall=weighted_rec,
            weighted_f1=weighted_f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            baseline_contamination_count=contamination_count,
            mean_latency_ms=mean_lat,
            median_latency_ms=med_lat,
            p99_latency_ms=p99_lat
        )

    @classmethod
    def evaluate_isolated(
        cls,
        events: List[Dict[str, Any]],
        sandbox_dir: Optional[str] = None
    ) -> EvaluationMetrics:
        """
        Runs an evaluation stream inside a strictly isolated sandbox context.
        Guarantees that live profiles are never touched.
        """
        with IsolatedEvaluationContext(sandbox_dir=sandbox_dir) as ctx:
            pipeline = ctx.create_pipeline()
            evaluator = cls(pipeline=pipeline)
            return evaluator.evaluate_stream(events, pipeline=pipeline)


class StaticRuleEvaluator:
    """
    Deterministic static heuristic baseline evaluator with zero external dependencies.
    Evaluates individual DNS events using fixed entropy, length, and query-type thresholds:
        Alert = True iff (Entropy >= 4.0 AND Domain Length >= 30) OR (Query Type not in {1, 28})
    """

    @staticmethod
    def classify_event(event: Dict[str, Any]) -> int:
        """
        Returns 1 (Alert / Tunneling) or 0 (Benign) according to the static rule:
            (Entropy >= 4.0 AND Domain Length >= 30) OR (Query Type not in {1, 28})
        """
        features = event.get("features", {})
        entropy = float(features.get("entropy", 0.0))
        length = float(features.get("domain_length", len(event.get("domain", ""))))
        qtype = int(features.get("query_type", 1))

        if (entropy >= 4.0 and length >= 30) or (qtype not in (1, 28)):
            return 1
        return 0

    def evaluate_stream(self, events: List[Dict[str, Any]]) -> EvaluationMetrics:
        """
        Evaluates a labeled query stream using the static rule and computes standard metrics.
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        latencies_ms = []

        for event in events:
            true_label = int(event["label"])

            t_start = time.perf_counter_ns()
            pred_label = self.classify_event(event)
            t_end = time.perf_counter_ns()
            latencies_ms.append((t_end - t_start) / 1_000_000.0)

            if true_label == 1 and pred_label == 1:
                tp += 1
            elif true_label == 0 and pred_label == 1:
                fp += 1
            elif true_label == 0 and pred_label == 0:
                tn += 1
            elif true_label == 1 and pred_label == 0:
                fn += 1

        total = tp + fp + tn + fn
        accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
        bin_prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        bin_rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        bin_f1 = (
            round(2 * (bin_prec * bin_rec) / (bin_prec + bin_rec), 4)
            if (bin_prec + bin_rec) > 0
            else 0.0
        )
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

        benign_prec = round(tn / (tn + fn), 4) if (tn + fn) > 0 else 0.0
        benign_rec = round(tn / (tn + fp), 4) if (tn + fp) > 0 else 0.0
        benign_f1 = (
            round(2 * (benign_prec * benign_rec) / (benign_prec + benign_rec), 4)
            if (benign_prec + benign_rec) > 0
            else 0.0
        )

        n_benign = tn + fp
        n_malicious = tp + fn
        if total > 0:
            weighted_prec = round(
                (n_benign * benign_prec + n_malicious * bin_prec) / total, 4
            )
            weighted_rec = round(
                (n_benign * benign_rec + n_malicious * bin_rec) / total, 4
            )
            weighted_f1 = round(
                (n_benign * benign_f1 + n_malicious * bin_f1) / total, 4
            )
        else:
            weighted_prec, weighted_rec, weighted_f1 = 0.0, 0.0, 0.0

        if latencies_ms:
            sorted_lat = sorted(latencies_ms)
            n_lat = len(sorted_lat)
            mean_lat = round(sum(sorted_lat) / n_lat, 4)
            med_lat = round(
                sorted_lat[n_lat // 2]
                if n_lat % 2 != 0
                else (sorted_lat[n_lat // 2 - 1] + sorted_lat[n_lat // 2]) / 2.0,
                4
            )
            rank = min(max(math.ceil(0.99 * n_lat), 1), n_lat)
            p99_lat = round(sorted_lat[rank - 1], 4)
        else:
            mean_lat, med_lat, p99_lat = 0.0, 0.0, 0.0

        return EvaluationMetrics(
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            accuracy=accuracy,
            precision=bin_prec,
            recall=bin_rec,
            f1_score=bin_f1,
            binary_precision=bin_prec,
            binary_recall=bin_rec,
            binary_f1=bin_f1,
            weighted_precision=weighted_prec,
            weighted_recall=weighted_rec,
            weighted_f1=weighted_f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            baseline_contamination_count=0,
            mean_latency_ms=mean_lat,
            median_latency_ms=med_lat,
            p99_latency_ms=p99_lat
        )
