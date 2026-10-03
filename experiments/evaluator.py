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
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    baseline_contamination_count: int

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

        for event in events:
            host = event["host"]
            domain = event["domain"]
            features = event["features"]
            true_label = int(event["label"])

            result = active_pipeline.process(host, domain, features)

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
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = (
            round(2 * (precision * recall) / (precision + recall), 4)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

        return EvaluationMetrics(
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
            baseline_contamination_count=contamination_count
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
