"""
Tier 2A Mechanism Validation: Validates temporal query-rate burst response.
Measures QPS, rate deviation score, and behavior score across sub-threshold, threshold, and burst traffic.
"""

import csv
from pathlib import Path

from experiments.context import IsolatedEvaluationContext
from src.features.traditional_features import TraditionalFeatureExtractor


def run_burst_validation(output_csv: str = None):
    extractor = TraditionalFeatureExtractor()
    results = []

    regimes = [
        {"name": "Sub-Threshold Steady", "interval_s": 1.50, "count": 10},
        {"name": "At-Threshold Limit",    "interval_s": 0.50, "count": 10},
        {"name": "High-Speed Tunnel Burst", "interval_s": 0.04, "count": 10},
    ]

    with IsolatedEvaluationContext() as ctx:
        pipeline = ctx.create_pipeline()

        current_time = 1700000000.0
        for reg in regimes:
            reg_name = reg["name"]
            interval = reg["interval_s"]
            count = reg["count"]
            host = f"10.10.1.{len(results) + 1}"

            for i in range(count):
                current_time += interval
                domain = f"sub{i}.example.com"
                raw_event = {
                    "timestamp": current_time,
                    "source_ip": host,
                    "domain": domain,
                    "query_type": 1,
                    "packet_size": len(domain) + 40
                }
                features = extractor.extract(raw_event)
                features["timestamp"] = current_time

                res = pipeline.process(host, domain, features)
                stats = pipeline.window.get_statistics(host)

                results.append({
                    "regime": reg_name,
                    "query_index": i + 1,
                    "interval_seconds": interval,
                    "measured_qps": stats["query_rate"],
                    "window_duration_seconds": stats["window_duration"],
                    "rate_deviation": res.get("query_rate_deviation", 0.0),
                    "behavior_score": res["behavior_score"],
                    "risk_level": res["risk_level"]
                })

    print("\n" + "=" * 80)
    print(" TIER 2A: TEMPORAL QUERY-RATE BURST VALIDATION")
    print("=" * 80)
    print(f"{'Regime':<25} | {'Interval (s)':<12} | {'Measured QPS':<14} | {'D_rate':<8} | {'Score':<8} | {'Risk Level'}")
    print("-" * 80)
    for row in results:
        if row["query_index"] in (1, 5, 10):
            print(f"{row['regime']:<25} | {row['interval_seconds']:<12.2f} | {row['measured_qps']:<14.2f} | {row['rate_deviation']:<8.4f} | {row['behavior_score']:<8.2f} | {row['risk_level']}")
    print("=" * 80 + "\n")

    if output_csv:
        out_p = Path(output_csv)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Saved burst validation results to {out_p}")

    return results


if __name__ == "__main__":
    run_burst_validation("experiments/results/burst_validation.csv")
