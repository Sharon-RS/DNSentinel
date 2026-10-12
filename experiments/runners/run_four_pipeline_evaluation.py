"""
Master Evaluator & Verification Runner for DNSentinel Detection Pipelines:
1. Pipeline A1: Unmitigated DetectionPipeline (cold-start baseline)
2. Pipeline B: ColdStartMitigatedPipeline (heuristic with enterprise prior)
3. ML30 Cascade: CascadeDetectionPipeline (Random Forest tiered cascade)
4. ML30 + Burst-Taint: BurstTaintCascadePipeline (cascade with parent-domain burst taint)

Evaluates:
- Historical Lab Attack Trace (lab_trace_tunnel_burst.jsonl, N=115, Pos=115, Neg=0)
- Historical Lab Benign Trace (lab_trace_benign.jsonl, N=119, Pos=0, Neg=119)
- Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl, N=100, Pos=0, Neg=100)
- Combined Historical Lab Stream (Burst + Benign, N=234, Pos=115, Neg=119)
- Held-Out Zero-Day Benchmark Partition (dnsentinel_ml_benchmark.jsonl test split, N=1,714, Pos=916, Neg=798)

Strictly preserves live disk baselines and models via IsolatedEvaluationContext.
Enforces correct mathematical definitions (null / N/A for undefined division by zero).
"""

import hashlib
import json
import math
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.config import Config
from experiments.context import IsolatedEvaluationContext
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cold_start_pipeline import ColdStartMitigatedPipeline
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline, BurstTaintCascadePipeline
from experiments.runners.run_ml_experiment import load_dataset


def get_dir_hashes(directory: Path) -> Dict[str, str]:
    hashes = {}
    if not directory.exists():
        return hashes
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            hashes[str(p.relative_to(directory))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def calculate_metrics(
    y_true: List[int],
    y_pred: List[int],
    latencies_ms: List[float],
    contaminations: int,
    direct_detections: int,
    taint_detections: int
) -> Dict[str, Any]:
    n = len(y_true)
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    pos_count = sum(1 for yt in y_true if yt == 1)
    neg_count = sum(1 for yt in y_true if yt == 0)

    # Precision: undefined if no predicted positives (tp + fp == 0)
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None

    # Recall: undefined if no actual positives (pos_count == 0)
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None

    # F1: undefined if precision or recall is None or sum is 0
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = round(2 * precision * recall / (precision + recall), 4)
    else:
        f1 = None

    # FPR: undefined if no actual negatives (neg_count == 0)
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else None

    # Accuracy: defined if n > 0
    accuracy = round((tp + tn) / n, 4) if n > 0 else 0.0

    sorted_lat = sorted(latencies_ms) if latencies_ms else [0.0]
    n_lat = len(sorted_lat)
    mean_lat = round(sum(sorted_lat) / n_lat, 4)
    med_lat = round(sorted_lat[n_lat // 2], 4)
    rank_p99 = min(max(math.ceil(0.99 * n_lat), 1), n_lat)
    p99_lat = round(sorted_lat[rank_p99 - 1], 4)

    return {
        "n": n,
        "pos_count": pos_count,
        "neg_count": neg_count,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "accuracy": accuracy,
        "contamination": contaminations,
        "direct_detections": direct_detections,
        "taint_detections": taint_detections,
        "mean_latency_ms": mean_lat,
        "median_latency_ms": med_lat,
        "p99_latency_ms": p99_lat
    }


def evaluate_pipeline_on_events(
    pipeline_factory,
    events: List[Dict[str, Any]],
    copy_org_baseline: bool = True
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    org_src = Config.PROJECT_ROOT / "experiments" / "datasets" / "enterprise_org_baseline.json"

    with IsolatedEvaluationContext() as ctx:
        if copy_org_baseline and org_src.exists():
            dst = ctx.sandbox_path / "organization" / "organization.json"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(org_src, dst)

        pipeline = pipeline_factory(ctx.sandbox_path)

        y_true = []
        y_pred = []
        latencies_ms = []
        contamination = 0
        direct_det = 0
        taint_det = 0
        detailed_records = []

        for ev in events:
            host = ev.get("host") or ev.get("source_ip", "10.0.0.1")
            domain = ev.get("domain", "")
            features = ev.get("features", {})
            if "timestamp" not in features:
                features["timestamp"] = ev.get("timestamp") or time.time()

            label = int(ev.get("label", 0))
            y_true.append(label)

            t0 = time.perf_counter_ns()
            res = pipeline.process(host=host, domain=domain, features=features)
            t1 = time.perf_counter_ns()
            latencies_ms.append((t1 - t0) / 1_000_000.0)

            # Detection decision
            risk_level = res.get("risk_level", "NORMAL")
            cascade_decision = res.get("cascade_decision")
            is_malicious = (
                cascade_decision == "MALICIOUS"
                if cascade_decision is not None
                else (risk_level in ("SUSPICIOUS", "HIGH_RISK"))
            )
            pred = 1 if is_malicious else 0
            y_pred.append(pred)

            # Baseline contamination check
            if label == 1 and res.get("baseline_updated") is True:
                contamination += 1

            # Telemetry breakdown
            if pred == 1:
                if res.get("taint_propagated") is True or res.get("detection_source") == "TAINT_PROPAGATED":
                    taint_det += 1
                else:
                    direct_det += 1

            detailed_records.append({
                "host": host,
                "domain": domain,
                "label": label,
                "pred": pred,
                "risk_level": risk_level,
                "cascade_decision": cascade_decision,
                "cascade_path": res.get("cascade_path"),
                "detection_source": res.get("detection_source"),
                "taint_propagated": res.get("taint_propagated", False),
                "ml_probability": res.get("ml_probability")
            })

        metrics = calculate_metrics(
            y_true=y_true,
            y_pred=y_pred,
            latencies_ms=latencies_ms,
            contaminations=contamination,
            direct_detections=direct_det,
            taint_detections=taint_det
        )

        return metrics, detailed_records


def audit_missed_queries_on_tunnel_burst(
    attack_events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Directly replays lab_trace_tunnel_burst.jsonl on Cascade and Burst-Taint
    to identify the exact domains, indices, and cascade decisions.
    """
    org_src = Config.PROJECT_ROOT / "experiments" / "datasets" / "enterprise_org_baseline.json"

    with IsolatedEvaluationContext() as ctx:
        if org_src.exists():
            dst = ctx.sandbox_path / "organization" / "organization.json"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(org_src, dst)

        cascade_pipe = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
        cascade_results = [
            cascade_pipe.process(
                host=ev.get("host", "10.0.0.1"),
                domain=ev["domain"],
                features=ev.get("features", {})
            )
            for ev in attack_events
        ]

    with IsolatedEvaluationContext() as ctx:
        if org_src.exists():
            dst = ctx.sandbox_path / "organization" / "organization.json"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(org_src, dst)

        taint_pipe = BurstTaintCascadePipeline(data_dir=ctx.sandbox_path)
        taint_results = [
            taint_pipe.process(
                host=ev.get("host", "10.0.0.1"),
                domain=ev["domain"],
                features=ev.get("features", {})
            )
            for ev in attack_events
        ]

    missed_records = []
    for idx, (ev, res_c, res_t) in enumerate(zip(attack_events, cascade_results, taint_results)):
        dec_c = res_c.get("cascade_decision")
        if dec_c != "MALICIOUS":
            missed_records.append({
                "0_based_index": idx,
                "1_based_index": idx + 1,
                "domain": ev["domain"],
                "cascade_decision": dec_c,
                "cascade_path": res_c.get("cascade_path"),
                "ml_probability": res_c.get("ml_probability"),
                "burst_taint_decision": res_t.get("cascade_decision"),
                "burst_taint_detection_source": res_t.get("detection_source"),
                "burst_taint_propagated": res_t.get("taint_propagated", False),
            })

    return missed_records


def run_evaluation() -> Dict[str, Any]:
    print("=" * 80)
    print(" DNSENTINEL VERIFIED FOUR-PIPELINE EVALUATION RUNNER")
    print("=" * 80)

    # 1. Snapshot directory hashes for immutability verification
    profiles_dir = Config.PROJECT_ROOT / "data" / "profiles"
    org_dir = Config.PROJECT_ROOT / "data" / "organization"
    models_dir = Config.PROJECT_ROOT / "models"

    pre_profiles_h = get_dir_hashes(profiles_dir)
    pre_org_h = get_dir_hashes(org_dir)
    pre_models_h = get_dir_hashes(models_dir)

    datasets_dir = Config.PROJECT_ROOT / "experiments" / "datasets"

    attack_events = load_jsonl(datasets_dir / "lab_trace_tunnel_burst.jsonl")
    benign_lab_events = load_jsonl(datasets_dir / "lab_trace_benign.jsonl")
    benign_cold_events = load_jsonl(datasets_dir / "lab_trace_benign_new_host.jsonl")
    combined_lab_events = attack_events + benign_lab_events

    # Load Phase 6D dataset partitions for held-out zero-day evaluation
    _, bench_records, partitions = load_dataset()
    held_out_test_events = [bench_records[i] for i in partitions["test"]]

    pipelines = [
        ("Pipeline A1", lambda sbox: DetectionPipeline(data_dir=sbox), False),
        ("Pipeline B", lambda sbox: ColdStartMitigatedPipeline(data_dir=sbox), True),
        ("ML30 Cascade", lambda sbox: CascadeDetectionPipeline(data_dir=sbox), True),
        ("ML30 + Burst-Taint", lambda sbox: BurstTaintCascadePipeline(data_dir=sbox), True),
    ]

    all_results: Dict[str, Any] = {}

    # Define workloads with clear provenance categories
    workloads = [
        (
            "Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)",
            "historical_lab",
            "Real lab BIND9 query trace of Kali Linux DNS tunneling burst against attacker.lab",
            attack_events
        ),
        (
            "Historical Lab Benign Trace (lab_trace_benign.jsonl)",
            "historical_lab",
            "Real lab BIND9 query trace of benign background browsing activity",
            benign_lab_events
        ),
        (
            "Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)",
            "synthetic_scenario",
            "Synthetic cold-host scenario evaluating cold-start false alarm suppression",
            benign_cold_events
        ),
        (
            "Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)",
            "historical_lab",
            "Continuous stream of 115 tunnel-burst queries immediately followed by 119 benign queries",
            combined_lab_events
        ),
        (
            "Phase 6D Held-Out Zero-Day Benchmark Partition",
            "held_out_benchmark",
            "Held-out final test partition of dnsentinel_ml_benchmark.jsonl (4 unseen zero-day campaigns + ambient benign)",
            held_out_test_events
        ),
    ]

    for w_name, prov_type, desc, w_events in workloads:
        print(f"\n[*] Evaluating Workload: {w_name} ({len(w_events)} events)...")
        w_dict = {
            "provenance_type": prov_type,
            "description": desc,
            "sample_size": len(w_events),
            "pipelines": {}
        }

        if prov_type == "held_out_benchmark":
            w_dict["hard_negative_danger_edu_status"] = "UNTESTED_IN_PARTITION"
            w_dict["hard_negative_note"] = (
                "Both authentic m92xk7qlp81zr4.danger.edu queries are confined to the training partition (t < 18,000s). "
                "The validation and final test partitions contain 0 danger.edu queries. Generalization on hard negatives cannot be claimed."
            )

        for p_name, p_factory, copy_org in pipelines:
            t0_pipe = time.perf_counter()
            metrics, _ = evaluate_pipeline_on_events(p_factory, w_events, copy_org_baseline=copy_org)
            t1_pipe = time.perf_counter()
            w_dict["pipelines"][p_name] = metrics
            print(f"    - {p_name:20s}: TP={metrics['tp']:4d} FP={metrics['fp']:4d} TN={metrics['tn']:4d} FN={metrics['fn']:4d} "
                  f"({t1_pipe - t0_pipe:.2f}s)")

        all_results[w_name] = w_dict

    # 2. Extract and attach exact missed-query breakdown on lab_trace_tunnel_burst
    missed_attack_queries = audit_missed_queries_on_tunnel_burst(attack_events)
    all_results["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"] = missed_attack_queries

    # 3. Perform Rigorous Regression Checks on Totals & Mathematical Invariants
    print("\n[*] Running self-contained regression checks on metrics and constraints...")
    for w_name, w_data in all_results.items():
        for p_name, m in w_data["pipelines"].items():
            # Check sum invariants
            assert m["tp"] + m["fn"] == m["pos_count"], f"[{w_name}][{p_name}] TP + FN != pos_count"
            assert m["fp"] + m["tn"] == m["neg_count"], f"[{w_name}][{p_name}] FP + TN != neg_count"
            assert m["tp"] + m["fp"] + m["tn"] + m["fn"] == m["n"], f"[{w_name}][{p_name}] Confusion sum != n"
            assert m["direct_detections"] + m["taint_detections"] == m["tp"] + m["fp"], f"[{w_name}][{p_name}] Detections != TP + FP"

            # Check undefined metric rules
            if m["pos_count"] == 0:
                assert m["recall"] is None, f"[{w_name}][{p_name}] Expected recall to be None when pos_count == 0"
                assert m["f1"] is None, f"[{w_name}][{p_name}] Expected f1 to be None when pos_count == 0"
            if m["neg_count"] == 0:
                assert m["fpr"] is None, f"[{w_name}][{p_name}] Expected fpr to be None when neg_count == 0"
            if (m["tp"] + m["fp"]) == 0:
                assert m["precision"] is None, f"[{w_name}][{p_name}] Expected precision to be None when TP + FP == 0"
                assert m["f1"] is None, f"[{w_name}][{p_name}] Expected f1 to be None when TP + FP == 0"

    # Specific audited assertion checks
    tb_data = all_results["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["pipelines"]
    assert tb_data["Pipeline A1"]["tp"] == 36 and tb_data["Pipeline A1"]["fn"] == 79
    assert tb_data["Pipeline B"]["tp"] == 65 and tb_data["Pipeline B"]["fn"] == 50
    assert tb_data["ML30 Cascade"]["tp"] == 110 and tb_data["ML30 Cascade"]["fn"] == 5
    assert tb_data["ML30 + Burst-Taint"]["tp"] == 114 and tb_data["ML30 + Burst-Taint"]["fn"] == 1
    assert tb_data["ML30 + Burst-Taint"]["taint_detections"] == 4

    assert len(missed_attack_queries) == 5, f"Expected 5 missed queries, got {len(missed_attack_queries)}"
    assert missed_attack_queries[0]["1_based_index"] == 1 and missed_attack_queries[0]["domain"] == "hello.attacker.lab"
    assert missed_attack_queries[1]["1_based_index"] == 10 and missed_attack_queries[1]["domain"] == "525443.end.attacker.lab"
    assert missed_attack_queries[2]["1_based_index"] == 19 and missed_attack_queries[2]["domain"] == "0c8e0e.end.attacker.lab"
    assert missed_attack_queries[3]["1_based_index"] == 28 and missed_attack_queries[3]["domain"] == "626833.end.attacker.lab"
    assert missed_attack_queries[4]["1_based_index"] == 37 and missed_attack_queries[4]["domain"] == "b78dd1.end.attacker.lab"

    ho_data = all_results["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]
    assert ho_data["Pipeline A1"]["tp"] == 338 and ho_data["Pipeline A1"]["fp"] == 300 and ho_data["Pipeline A1"]["tn"] == 498 and ho_data["Pipeline A1"]["fn"] == 578
    assert ho_data["Pipeline B"]["tp"] == 427 and ho_data["Pipeline B"]["fp"] == 124 and ho_data["Pipeline B"]["tn"] == 674 and ho_data["Pipeline B"]["fn"] == 489
    assert ho_data["ML30 Cascade"]["tp"] == 916 and ho_data["ML30 Cascade"]["fp"] == 0 and ho_data["ML30 Cascade"]["tn"] == 798 and ho_data["ML30 Cascade"]["fn"] == 0
    assert ho_data["ML30 + Burst-Taint"]["tp"] == 916 and ho_data["ML30 + Burst-Taint"]["fp"] == 0 and ho_data["ML30 + Burst-Taint"]["tn"] == 798 and ho_data["ML30 + Burst-Taint"]["fn"] == 0
    print("[+] ALL REGRESSION INVARIANTS & AUDITED VALUES VERIFIED!")

    # 4. Save results to JSON
    out_json = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"[+] Saved corrected results to {out_json.relative_to(Config.PROJECT_ROOT)}")

    # 5. Generate Comprehensive Markdown Research Report
    out_md = Config.PROJECT_ROOT / "experiments" / "results" / "final_four_pipeline_evaluation_report.md"
    generate_markdown_report(all_results, out_md)
    print(f"[+] Saved corrected research report to {out_md.relative_to(Config.PROJECT_ROOT)}")

    # 6. Verify Post-Execution Immutability
    post_profiles_h = get_dir_hashes(profiles_dir)
    post_org_h = get_dir_hashes(org_dir)
    post_models_h = get_dir_hashes(models_dir)

    assert pre_profiles_h == post_profiles_h, "CRITICAL: Live data/profiles modified!"
    assert pre_org_h == post_org_h, "CRITICAL: Live data/organization modified!"
    assert pre_models_h == post_models_h, "CRITICAL: Live models/ modified!"
    print("[+] 100% BITWISE IMMUTABILITY CONFIRMED FOR ALL LIVE BASELINES AND MODELS!")

    return all_results


def format_pct(val: Optional[float]) -> str:
    return f"{val * 100:.2f}%" if val is not None else "N/A"


def generate_markdown_report(all_results: Dict[str, Any], output_path: Path):
    lines = [
        "# Corrected Evaluation Report: DNSentinel Four-Pipeline Detection Performance",
        "",
        "This report documents the audited, reproducible empirical performance of DNSentinel's four detection pipelines:",
        "1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`",
        "2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)",
        "3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path + Random Forest cascade)",
        "4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (Cascade with parent-domain burst taint propagation)",
        "",
        "---",
        "",
        "## 1. Workload Categorization & Provenance",
        "",
        "- **Historical Lab Traces**:",
        "  - `lab_trace_tunnel_burst.jsonl` ($N=115$): BIND9 query log of an authentic Kali Linux DNS tunneling burst against `attacker.lab`.",
        "  - `lab_trace_benign.jsonl` ($N=119$): BIND9 query log of authentic benign enterprise browsing activity.",
        "  - Combined Lab Stream ($N=234$): 115 tunnel queries followed immediately by 119 benign queries to evaluate baseline poisoning.",
        "- **Synthetic Scenario Traces**:",
        "  - `lab_trace_benign_new_host.jsonl` ($N=100$): Synthetic traffic evaluating cold-host prior behavior without baseline poisoning.",
        "- **Held-Out Zero-Day Benchmark (Phase 6D)**:",
        "  - `dnsentinel_ml_benchmark.jsonl` test partition ($N=1,714$, Pos=916, Neg=798): 4 completely unseen zero-day attack campaigns (`gamma`, `zeta`, `theta`, `iota`) interleaved with ambient enterprise traffic across 16 hosts.",
        "",
        "---",
        "",
        "## 2. Historical & Synthetic Lab Trace Results",
        ""
    ]

    lab_workload_keys = [
        "Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)",
        "Historical Lab Benign Trace (lab_trace_benign.jsonl)",
        "Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)",
        "Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)",
    ]

    for w_name in lab_workload_keys:
        w_data = all_results[w_name]
        p_dict = w_data["pipelines"]
        first_m = list(p_dict.values())[0]
        lines.append(f"### {w_name}")
        lines.append(f"*{w_data['description']}*  ")
        lines.append(f"**Sample Size:** $N = {first_m['n']}$ | **Ground-Truth Positives:** {first_m['pos_count']} | **Ground-Truth Negatives:** {first_m['neg_count']}\n")
        lines.append("| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Contamination | Direct ML | Tainted | Mean Latency | P99 Latency |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for p_name, m in p_dict.items():
            lines.append(
                f"| **{p_name}** | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
                f"{format_pct(m['recall'])} | {format_pct(m['precision'])} | {format_pct(m['f1'])} | {format_pct(m['fpr'])} | "
                f"{m['contamination']} | {m['direct_detections']} | {m['taint_detections']} | {m['mean_latency_ms']:.3f} ms | {m['p99_latency_ms']:.3f} ms |"
            )
        lines.append("")

    # Missed query breakdown section
    lines.extend([
        "---",
        "",
        "## 3. Audited Missed-Query Breakdown on Tunnel-Burst Attack Trace",
        "",
        "On `lab_trace_tunnel_burst.jsonl`, standard ML30 Cascade misses exactly 5 queries out of 115. `BurstTaintCascadePipeline` recovers 4 of these 5 queries via parent-domain burst taint propagation:",
        "",
        "| Query # (1-Based) | Domain | True Label | Cascade Decision | ML Prob | Cascade Path | Burst-Taint Decision | Detection Source |",
        "| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :--- |",
    ])
    missed_list = all_results["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"]
    for q in missed_list:
        lines.append(
            f"| **#{q['1_based_index']}** | `{q['domain']}` | 1 (Attack) | {q['cascade_decision']} | "
            f"{q['ml_probability'] if q['ml_probability'] is not None else 'N/A'} | `{q['cascade_path']}` | "
            f"**{q['burst_taint_decision']}** | `{q['burst_taint_detection_source']}` |"
        )
    lines.extend([
        "",
        "> [!NOTE]",
        "> **Causal Handshake Limitation:** Query #1 (`hello.attacker.lab`) arrives at the start of the session prior to any malicious observation. Because no attack has been confirmed yet, no active taint exists, and the query is evaluated purely on its benign lexical features ($P_{\\text{ML}} = 0.0000$).",
        "> Queries #10, #19, #28, and #37 (`*.end.attacker.lab`) are short delimiter chunks that score below the ML threshold ($P < 0.20$), but are successfully recovered because they share the parent domain `attacker.lab` with confirmed attack chunks from the same host.",
        "",
        "---",
        "",
        "## 4. Held-Out Zero-Day Benchmark Partition Evaluation",
        "",
        "Evaluated on the 1,714 held-out test events from `dnsentinel_ml_benchmark.jsonl` ($N=1,714$, Pos=916, Neg=798).",
        "",
        "| Pipeline Architecture | Execution Mode | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    ho_data = all_results["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]
    for p_name, m in ho_data.items():
        lines.append(
            f"| **{p_name}** | Online Live | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
            f"**{format_pct(m['recall'])}** | {format_pct(m['precision'])} | {format_pct(m['f1'])} | {format_pct(m['fpr'])} | {format_pct(m['accuracy'])} |"
        )

    lines.extend([
        "",
        "### Key Findings on Held-Out Zero-Day Benchmark",
        "1. **Failure of Heuristic Baselines on Cold Hosts:**",
        "   - **Pipeline A1** detects only 338 of 916 attacks (Recall: 36.90%) and generates 300 false positives (FPR: 37.59%) due to cold-start baseline contamination.",
        "   - **Pipeline B** leverages the enterprise prior to avoid full poisoning, improving recall to 46.62% and reducing FPR to 15.54%, but still misses 489 zero-day queries.",
        "2. **Cascade Superiority:**",
        "   - Both **ML30 Cascade** and **ML30 + Burst-Taint** achieve **100.00% Recall** (916/916 attacks detected) and **0.00% FPR** (798/798 benign cleared) on completely unseen zero-day campaigns.",
        "3. **Hard-Negative Evaluation Status:**",
        "   - In `dnsentinel_ml_benchmark.jsonl`, both `m92xk7qlp81zr4.danger.edu` queries reside in the training split ($t < 18,000$s). The validation and test partitions contain **0** `danger.edu` observations.",
        "   - Hard-negative generalization on `danger.edu` is therefore labeled **UNTESTED** on the test partition.",
        "",
        "---",
        "",
        "## 5. Mathematical Metric Definitions & Undefined Conventions",
        "",
        "Let $y \\in \\{0, 1\\}$ denote the ground-truth label and $\\hat{y} \\in \\{0, 1\\}$ denote the binary prediction:",
        "- $\\text{Recall} = \\frac{\\text{TP}}{\\text{TP} + \\text{FN}}$ (Undefined / `N/A` when $\\text{TP} + \\text{FN} = 0$)",
        "- $\\text{Precision} = \\frac{\\text{TP}}{\\text{TP} + \\text{FP}}$ (Undefined / `N/A` when $\\text{TP} + \\text{FP} = 0$)",
        "- $\\text{F1-Score} = \\frac{2 \\cdot \\text{Precision} \\cdot \\text{Recall}}{\\text{Precision} + \\text{Recall}}$ (Undefined / `N/A` when Precision or Recall is undefined)",
        "- $\\text{FPR} = \\frac{\\text{FP}}{\\text{FP} + \\text{TN}}$ (Undefined / `N/A` when $\\text{FP} + \\text{TN} = 0$)",
        "- $\\text{Accuracy} = \\frac{\\text{TP} + \\text{TN}}{N}$",
        "",
        "All calculations strictly enforce these definitions without substituting arbitrary default values."
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    run_evaluation()
