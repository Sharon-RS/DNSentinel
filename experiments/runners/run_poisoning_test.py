"""
Tier 2B Mechanism Validation: Baseline-Poisoning Protection Experiment.
Compares Protected Pipeline against Unprotected Control (replicating pre-baseline-protection behavior).
Calculates exact attack_phase_drift relative to pre-attack baseline and logs contamination count.
"""

import json
import csv
from pathlib import Path

from experiments.context import IsolatedEvaluationContext
from src.pipeline.detection_pipeline import DetectionPipeline


class UnprotectedDetectionPipeline(DetectionPipeline):
    """
    Replicates the authentic pre-baseline-protection behavior from
    detection_pipeline.backup.py: updates host and organization baselines
    unconditionally on every query, while respecting data_dir sandbox isolation.
    """

    def process(self, host, domain, features):
        host_profile = self.host_profile.load(host).to_dict()
        organization_profile = self.organization_profile.load()

        self.window.update(host, domain, features)
        window_statistics = self.window.get_statistics(host)

        from src.behavior.behavior_snapshot import BehaviorSnapshot
        snapshot = BehaviorSnapshot(
            host=host,
            domain=domain,
            packet_features=features,
            host_profile=host_profile,
            organization_profile=organization_profile,
            window_statistics=window_statistics
        )

        behavior_result = self.deviation_engine.calculate(snapshot)
        risk_result = self.risk_engine.evaluate(behavior_result)

        # UNCONDITIONAL UPDATE (Replicates detection_pipeline.backup.py)
        self.host_profile.update(host, domain, features)
        self.organization_profile.update(host, domain, features)
        risk_result["baseline_updated"] = True

        return risk_result


def run_single_pipeline_test(pipeline_class, events, name):
    with IsolatedEvaluationContext() as ctx:
        pipeline = pipeline_class(data_dir=ctx.sandbox_path)

        pre_attack_entropy = 0.0
        pre_attack_length = 0.0
        final_attack_entropy = 0.0
        final_attack_length = 0.0
        contamination_count = 0

        trace_log = []

        for i, ev in enumerate(events):
            host = ev["host"]
            domain = ev["domain"]
            features = ev["features"]
            is_attack = ev["label"] == 1

            res = pipeline.process(host, domain, features)

            if is_attack and res["baseline_updated"]:
                contamination_count += 1

            profile = pipeline.host_profile.load(host).to_dict()
            current_entropy = profile.get("average_entropy", 0.0)
            current_length = profile.get("average_domain_length", 0.0)

            # Record baseline at the transition point (end of warmup)
            if i == 19:  # Query 20 (0-indexed 19)
                pre_attack_entropy = current_entropy
                pre_attack_length = current_length

            trace_log.append({
                "pipeline": name,
                "query_index": i + 1,
                "domain": domain,
                "label": ev["label"],
                "risk_level": res["risk_level"],
                "baseline_updated": res["baseline_updated"],
                "host_avg_entropy": current_entropy,
                "host_avg_length": current_length
            })

        final_attack_entropy = current_entropy
        final_attack_length = current_length

        entropy_drift = round(abs(final_attack_entropy - pre_attack_entropy), 4)
        length_drift = round(abs(final_attack_length - pre_attack_length), 4)

        summary = {
            "pipeline": name,
            "pre_attack_entropy": pre_attack_entropy,
            "final_attack_entropy": final_attack_entropy,
            "attack_phase_entropy_drift": entropy_drift,
            "pre_attack_length": pre_attack_length,
            "final_attack_length": final_attack_length,
            "attack_phase_length_drift": length_drift,
            "malicious_contamination_count": contamination_count,
            "total_attack_queries": sum(1 for e in events if e["label"] == 1)
        }

        return summary, trace_log


def run_poisoning_experiment(dataset_path: str, output_csv: str = None):
    path = Path(dataset_path)
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    # Run Protected Pipeline
    prot_summary, prot_trace = run_single_pipeline_test(
        DetectionPipeline, events, "Protected Pipeline (Current Stable)"
    )

    # Run Unprotected Control
    unprot_summary, unprot_trace = run_single_pipeline_test(
        UnprotectedDetectionPipeline, events, "Unprotected Control (Pre-Protection Behavior)"
    )

    print("\n" + "=" * 88)
    print(" TIER 2B: BASELINE-POISONING DEFENSE EXPERIMENT")
    print("=" * 88)
    print(f"{'Condition':<40} | {'Pre-H':<8} | {'Post-H':<8} | {'H-Drift':<8} | {'L-Drift':<8} | {'Contamination'}")
    print("-" * 88)
    for s in [prot_summary, unprot_summary]:
        print(f"{s['pipeline']:<40} | {s['pre_attack_entropy']:<8.4f} | {s['final_attack_entropy']:<8.4f} | {s['attack_phase_entropy_drift']:<8.4f} | {s['attack_phase_length_drift']:<8.4f} | {s['malicious_contamination_count']}/{s['total_attack_queries']}")
    print("=" * 88 + "\n")

    if output_csv:
        out_p = Path(output_csv)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=prot_trace[0].keys())
            writer.writeheader()
            writer.writerows(prot_trace)
            writer.writerows(unprot_trace)
        print(f"[+] Saved poisoning trace logs to {out_p}")

    return [prot_summary, unprot_summary]


if __name__ == "__main__":
    run_poisoning_experiment("experiments/datasets/synthetic_poisoning_attack.jsonl", "experiments/results/poisoning_protection.csv")
