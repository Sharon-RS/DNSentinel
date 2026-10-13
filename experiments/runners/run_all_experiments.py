"""
Master Experiment Orchestrator for DNSentinel Phase 2.
Executes all four experimental tiers sequentially in isolated sandboxes
and generates structured outputs in experiments/results/.
"""

import json
from pathlib import Path

from experiments.runners.run_benchmark import run_benchmark
from experiments.runners.run_burst_validation import run_burst_validation
from experiments.runners.run_ablation import run_ablation_study
from experiments.runners.run_poisoning_test import run_poisoning_experiment
from experiments.runners.run_tunneleye_comparison import run_comparison

RESULTS_DIR = Path("experiments/results").resolve()
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
DATASETS_DIR = Path("experiments/datasets").resolve()


def execute_master_suite():
    print("\n" + "#" * 80)
    print(" STARTING DNSENTINEL PHASE 2 RESEARCH EVALUATION SUITE")
    print("#" * 80 + "\n")

    # 1. Tier 1: Real Lab Benign Trace Benchmark
    print("[+] Phase 2.1: Running benchmark on Real Lab Benign Trace...")
    benign_metrics = run_benchmark(
        dataset_path=str(DATASETS_DIR / "lab_trace_benign.jsonl"),
        output_path=str(RESULTS_DIR / "lab_trace_benign_metrics.json")
    )

    # 2. Tier 1: Real Lab Tunnel Burst Trace Benchmark
    print("\n[+] Phase 2.2: Running benchmark on Real Lab Tunnel Burst Trace...")
    tunnel_metrics = run_benchmark(
        dataset_path=str(DATASETS_DIR / "lab_trace_tunnel_burst.jsonl"),
        output_path=str(RESULTS_DIR / "lab_trace_tunnel_metrics.json")
    )

    # 3. Tier 1: Synthetic Mixed Stream Benchmark
    print("\n[+] Phase 2.3: Running benchmark on Synthetic Mixed Stream...")
    mixed_metrics = run_benchmark(
        dataset_path=str(DATASETS_DIR / "synthetic_mixed_stream.jsonl"),
        output_path=str(RESULTS_DIR / "benchmark_summary.json")
    )

    # 4. Tier 2A: Temporal Burst Response Validation
    print("\n[+] Phase 2.4: Running Tier 2A Temporal Query-Rate Burst Validation...")
    burst_results = run_burst_validation(
        output_csv=str(RESULTS_DIR / "burst_validation.csv")
    )

    # 5. Tier 2C: 4-Tier Renormalized Feature Ablation Study
    print("\n[+] Phase 2.5: Running Tier 2C Feature Ablation Study (Renormalized Weights)...")
    ablation_results = run_ablation_study(
        dataset_path=str(DATASETS_DIR / "synthetic_mixed_stream.jsonl"),
        output_csv=str(RESULTS_DIR / "ablation_study.csv")
    )

    # 6. Tier 2B: Baseline Contamination Defense Experiment
    print("\n[+] Phase 2.6: Running Tier 2B Baseline Poisoning Defense Experiment...")
    poisoning_results = run_poisoning_experiment(
        dataset_path=str(DATASETS_DIR / "synthetic_poisoning_attack.jsonl"),
        output_csv=str(RESULTS_DIR / "poisoning_protection.csv")
    )

    # 7. Tier 3 & 4: TunnelEye Comparison
    print("\n[+] Phase 2.7: Generating Factual TunnelEye Comparison Report...")
    run_comparison(
        dnsentinel_json=str(RESULTS_DIR / "benchmark_summary.json"),
        output_md=str(RESULTS_DIR / "tunneleye_comparison.md")
    )

    print("\n" + "#" * 80)
    print(" ALL EXPERIMENTS COMPLETE — ARTIFACTS WRITTEN TO experiments/results/")
    print("#" * 80 + "\n")


if __name__ == "__main__":
    execute_master_suite()
