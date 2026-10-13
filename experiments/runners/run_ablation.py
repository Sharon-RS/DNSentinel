"""
Weight-Renormalized Feature-Tier Sensitivity Analysis.
Evaluates DNSentinel composite detection sensitivity across progressive feature tiers
(Tier A: Lexical -> Tier B: +Host Behavioral -> Tier C: +Temporal Rate -> Tier D: Full Composite).

Methodological Disclaimer:
The measured performance differences reflect the sensitivity of the composite engine to the
inclusion of specific feature tiers under uniform scale renormalization ([0, 100]), and do NOT
represent pure causal contributions of individual features in isolation because renormalization
inherently shifts the relative weight distribution among remaining active components.
"""

import json
import csv
import copy
from pathlib import Path
from typing import Dict, Any, List

from experiments.context import IsolatedEvaluationContext
from src.behavior.deviation_engine import BehaviorDeviationEngine

ABLATION_TIERS = {
    "tier_a": {
        "name": "Tier A: Lexical Only",
        "weights": {"entropy": 0.25 / 0.45, "length": 0.20 / 0.45},
        "raw_weights": {"entropy": 0.25, "length": 0.20}
    },
    "tier_b": {
        "name": "Tier B: + Host Behavioral",
        "weights": {"entropy": 0.25 / 0.65, "length": 0.20 / 0.65, "novel": 0.20 / 0.65},
        "raw_weights": {"entropy": 0.25, "length": 0.20, "novel": 0.20}
    },
    "tier_c": {
        "name": "Tier C: + Temporal Rate",
        "weights": {"entropy": 0.25 / 0.80, "length": 0.20 / 0.80, "novel": 0.20 / 0.80, "rate": 0.15 / 0.80},
        "raw_weights": {"entropy": 0.25, "length": 0.20, "novel": 0.20, "rate": 0.15}
    },
    "tier_d": {
        "name": "Tier D: Full Composite (+ Org)",
        "weights": {"entropy": 0.25, "length": 0.20, "novel": 0.20, "rate": 0.15, "rarity": 0.20},
        "raw_weights": {"entropy": 0.25, "length": 0.20, "novel": 0.20, "rate": 0.15, "rarity": 0.20}
    }
}


def _safe_mean(vals: List[float]) -> float:
    return round(float(sum(vals) / len(vals)), 4) if vals else 0.0


class AblatedDeviationEngine(BehaviorDeviationEngine):
    """
    Subclasses BehaviorDeviationEngine to dynamically apply renormalized weights
    for feature sensitivity analysis without modifying production configuration.
    """

    def __init__(self, active_weights: Dict[str, float]):
        super().__init__()
        # Renormalize weights so they sum to 1.0
        total_w = sum(active_weights.values())
        if total_w <= 0:
            raise ValueError("Sum of active weights must be > 0")
        self.weights = {k: v / total_w for k, v in active_weights.items()}

    def calculate(self, snapshot):
        raw = super().calculate(snapshot)

        # Compute ablated composite score using renormalized weights
        score = (
            raw["entropy_deviation"] * self.weights.get("entropy", 0.0)
            + raw["domain_length_deviation"] * self.weights.get("length", 0.0)
            + raw["query_rate_deviation"] * self.weights.get("rate", 0.0)
            + raw["novel_domain_score"] * self.weights.get("novel", 0.0)
            + raw["organization_rarity_score"] * self.weights.get("rarity", 0.0)
        )

        raw["behavior_score"] = round(min(score * 100, 100), 2)
        return raw


def evaluate_ablation_tier(
    events: List[Dict[str, Any]],
    tier_name: str,
    active_weights: Dict[str, float]
) -> Dict[str, Any]:
    engine = AblatedDeviationEngine(active_weights)

    with IsolatedEvaluationContext() as ctx:
        pipeline = ctx.create_pipeline()
        pipeline.deviation_engine = engine

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        # Mean component deviation tracking
        devs_benign = {"entropy": [], "length": [], "rate": [], "novel": [], "rarity": []}
        devs_tunnel = {"entropy": [], "length": [], "rate": [], "novel": [], "rarity": []}

        for ev in events:
            host = ev["host"]
            domain = ev["domain"]
            features = ev["features"]
            true_label = int(ev["label"])

            res = pipeline.process(host, domain, features)
            pred_label = 1 if res["risk_level"] in ("SUSPICIOUS", "HIGH_RISK") else 0

            if true_label == 1 and pred_label == 1:
                tp += 1
            elif true_label == 0 and pred_label == 1:
                fp += 1
            elif true_label == 0 and pred_label == 0:
                tn += 1
            elif true_label == 1 and pred_label == 0:
                fn += 1

            target_devs = devs_tunnel if true_label == 1 else devs_benign
            target_devs["entropy"].append(res["entropy_deviation"])
            target_devs["length"].append(res["domain_length_deviation"])
            target_devs["rate"].append(res["query_rate_deviation"])
            target_devs["novel"].append(res["novel_domain_score"])
            target_devs["rarity"].append(res["organization_rarity_score"])

    total = tp + fp + tn + fn
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (prec * rec) / (prec + rec), 4) if (prec + rec) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

    return {
        "tier": tier_name,
        "weights": str({k: round(v, 4) for k, v in engine.weights.items()}),
        "accuracy": accuracy,
        "binary_precision": prec,
        "binary_recall": rec,
        "binary_f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "mean_dev_entropy_tunnel": _safe_mean(devs_tunnel["entropy"]),
        "mean_dev_length_tunnel": _safe_mean(devs_tunnel["length"]),
        "mean_dev_rate_tunnel": _safe_mean(devs_tunnel["rate"]),
        "mean_dev_novel_tunnel": _safe_mean(devs_tunnel["novel"]),
        "mean_dev_rarity_tunnel": _safe_mean(devs_tunnel["rarity"]),
        "mean_dev_entropy_benign": _safe_mean(devs_benign["entropy"]),
        "mean_dev_length_benign": _safe_mean(devs_benign["length"]),
        "mean_dev_rate_benign": _safe_mean(devs_benign["rate"]),
        "mean_dev_novel_benign": _safe_mean(devs_benign["novel"]),
        "mean_dev_rarity_benign": _safe_mean(devs_benign["rarity"]),
    }


def run_ablation_study(dataset_path: str, output_csv: str = None):
    path = Path(dataset_path)
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    results = []
    for tier_id, tier_info in ABLATION_TIERS.items():
        res = evaluate_ablation_tier(events, tier_info["name"], tier_info["raw_weights"])
        results.append(res)

    print("\n" + "=" * 95)
    print(" WEIGHT-RENORMALIZED FEATURE-TIER SENSITIVITY ANALYSIS")
    print("=" * 95)
    print(f"{'Tier Name':<28} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'FPR':<8}")
    print("-" * 95)
    for r in results:
        print(f"{r['tier']:<28} | {r['accuracy']:<10.4f} | {r['binary_precision']:<10.4f} | {r['binary_recall']:<10.4f} | {r['binary_f1']:<10.4f} | {r['false_positive_rate']:<8.4f}")
    print("=" * 95)
    print(" * Note: Differences reflect sensitivity under scale renormalization ([0, 100]), not pure causal attribution.")
    print("=" * 95 + "\n")

    if output_csv:
        out_p = Path(output_csv)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Saved sensitivity analysis results to {out_p}")

    return results


if __name__ == "__main__":
    run_ablation_study("experiments/datasets/synthetic_mixed_stream.jsonl", "experiments/results/ablation_study.csv")
