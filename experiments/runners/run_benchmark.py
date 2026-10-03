"""
Tier 1 Benchmark Runner: Evaluates DNSentinel on labeled query streams.
Measures empirical detection accuracy, precision, recall, F1, FPR, FNR, and actual processing latency.
Guarantees 100% data directory isolation.
"""

import argparse
import json
from pathlib import Path

from experiments.context import IsolatedEvaluationContext
from experiments.evaluator import DNSentinelEvaluator


def run_benchmark(dataset_path: str, output_path: str = None):
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    print(f"[*] Running benchmark on '{path.name}' ({len(events)} events)...")

    # Execute inside isolated evaluation context
    with IsolatedEvaluationContext() as ctx:
        pipeline = ctx.create_pipeline()
        evaluator = DNSentinelEvaluator(pipeline=pipeline)
        metrics = evaluator.evaluate_stream(events, pipeline=pipeline)

    print("\n" + "=" * 65)
    print(f" BENCHMARK EMPIRICAL RESULTS: {path.name}")
    print("=" * 65)
    print(f" Total Samples Evaluated    : {metrics.total_samples}")
    print(f" True Positives (TP)        : {metrics.true_positives}")
    print(f" False Positives (FP)       : {metrics.false_positives}")
    print(f" True Negatives (TN)        : {metrics.true_negatives}")
    print(f" False Negatives (FN)       : {metrics.false_negatives}")
    print("-" * 65)
    print(f" Overall Accuracy           : {metrics.accuracy:.4f}")
    print(f" Binary Precision (Class 1) : {metrics.binary_precision:.4f}")
    print(f" Binary Recall (Class 1)    : {metrics.binary_recall:.4f}")
    print(f" Binary F1-Score (Class 1)  : {metrics.binary_f1:.4f}")
    print("-" * 65)
    print(f" Weighted Precision         : {metrics.weighted_precision:.4f}")
    print(f" Weighted Recall            : {metrics.weighted_recall:.4f}")
    print(f" Weighted F1-Score          : {metrics.weighted_f1:.4f}")
    print("-" * 65)
    print(f" False Positive Rate (FPR)  : {metrics.false_positive_rate:.4f}")
    print(f" False Negative Rate (FNR)  : {metrics.false_negative_rate:.4f}")
    print(f" Contamination Count        : {metrics.baseline_contamination_count}")
    print("-" * 65)
    print(f" Empirical Mean Latency     : {metrics.mean_latency_ms:.4f} ms")
    print(f" Empirical Median Latency   : {metrics.median_latency_ms:.4f} ms")
    print(f" Empirical p99 Latency      : {metrics.p99_latency_ms:.4f} ms")
    print("=" * 65 + "\n")

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(metrics.to_dict(), f, indent=4)
        print(f"[+] Saved results to {out_p}")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNSentinel Benchmark Runner")
    parser.add_argument("--dataset", required=True, help="Path to input .jsonl dataset")
    parser.add_argument("--output", required=False, help="Path to output .json results file")
    args = parser.parse_args()

    run_benchmark(args.dataset, args.output)
