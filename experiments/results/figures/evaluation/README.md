# DNSentinel Four-Pipeline Evaluation Research Figures

This directory contains publication-quality vector research figures and summary tables comparing DNSentinel's four detection pipelines:
1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`
2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)
3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path heuristic triage + Random Forest)
4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (ML30 Cascade + Parent-domain burst taint propagation)

All figures derive strictly from the verified, reproducible evaluation results saved in:
- `experiments/results/final_four_pipeline_evaluation.json`
- `experiments/results/final_four_pipeline_evaluation_report.md`

No detection logic was rerun, no models were retrained, no thresholds were altered, and no data was fabricated.

---

## Catalog of Generated Figures

### 1. `fig01_combined_stream_recall_fpr.png`
- **Title:** Detection Recall and False-Positive Rate (FPR) on Historical Combined Lab Stream
- **Dimensions:** 1600 x 950 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workload:** Historical Combined Lab Benchmark Stream ($N = 234$: 115 Tunnel Positives + 119 Benign Negatives).
- **Contents:**
  - **Panel (a) Recall (%):** Compares attack detection recall across all four pipelines: Pipeline A1 (31.30%), Pipeline B (56.52%), ML30 Cascade (95.65%), and ML30 + Burst-Taint (99.13%).
  - **Panel (b) False-Positive Rate (%):** Demonstrates catastrophic baseline self-poisoning in Pipeline A1 (FPR = 97.48%, 116 false alarms), mitigation in Pipeline B (FPR = 4.20%), and high-precision discrimination in ML30 Cascade and ML30 + Burst-Taint (FPR = 1.68%, 2 false alarms).

### 2. `fig02_latency_comparison.png`
- **Title:** Mean and P99 Latency Profiling Across Four Detection Pipelines
- **Dimensions:** 1600 x 950 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - **Panel (a):** Combined Historical Lab Stream ($N = 234$)
  - **Panel (b):** Phase 6D Held-Out Zero-Day Benchmark Partition ($N = 1,714$)
- **Contents:** Paired bar charts displaying Mean Latency and 99th Percentile ($P99$) Tail Latency in milliseconds (ms). Highlights the sub-millisecond execution of heuristic baselines (0.06–0.27 ms) versus the ~3–5 ms execution of the ML cascade, while noting that Burst-Taint introduces virtually zero incremental overhead (+0.024 ms mean).

### 3. `fig03_confusion_matrices.png`
- **Title:** Empirical Confusion Matrix Grid Across Detection Pipelines
- **Dimensions:** 1700 x 1080 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - **Row 1:** Combined Historical Lab Stream ($N = 234$: 115 Positives, 119 Negatives)
  - **Row 2:** Phase 6D Held-Out Zero-Day Benchmark Partition ($N = 1,714$: 916 Positives, 798 Negatives)
- **Contents:** Complete 2x2 confusion matrix grid (TP, FP, TN, FN) for each of the four pipelines, annotated with exact query counts, Recall, Precision, FPR, and Accuracy. Shows how the ML cascades eliminate the severe baseline misclassifications of Pipeline A1 and Pipeline B.

### 4. `fig04_direct_vs_taint_detections.png`
- **Title:** Direct ML Detections vs. Parent-Domain Burst-Taint Propagation
- **Dimensions:** 1650 x 980 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - `lab_trace_tunnel_burst.jsonl` ($N = 115$)
  - `lab_trace_benign.jsonl` ($N = 119$)
  - Combined Lab Stream ($N = 234$)
- **Contents:**
  - **Panel (a):** Stacked bar charts decomposing total detections into Direct ML classifications versus Taint-Propagated alerts.
  - **Panel (b):** Lollipop probability trajectory of the 5 queries falling below the Random Forest decision threshold ($P < 0.20$). Explains why Query #1 (`hello.attacker.lab`) cannot be tainted due to causal ordering (opening handshake), while delimiter chunks #10, #19, #28, and #37 (`*.end.attacker.lab`) are successfully rescued by parent-domain taint.

### 5. `fig05_cross_workload_provenance.png`
- **Title:** Strict Provenance-Separated Evaluation Across Five Workloads
- **Dimensions:** 1750 x 1050 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:** All 5 evaluation workloads partitioned into three distinct provenance domains:
  1. **Historical Lab Traces:** Tunnel Burst ($N=115$), Benign Lab ($N=119$), Combined Stream ($N=234$)
  2. **Synthetic Cold-Host Scenario:** Benign Cold Host ($N=100$)
  3. **Held-Out Zero-Day Benchmark:** Final Test Partition ($N=1,714$)
- **Contents:** Grouped comparison bars honoring strict provenance isolation. All mathematically undefined metrics (e.g., Recall when Pos=0, FPR when Neg=0) are rendered with explicit hatched `N/A` badges rather than misleading zero values. Includes an explicit callout documenting that hard-negative `danger.edu` queries were confined to training and are untested in the held-out partition.

---

## Summary Tables

- `experiments/results/tables/table5_four_pipeline_evaluation.md`: Complete markdown table formatted for publication inclusion, summarizing TP, FP, TN, FN, Recall, Precision, F1, FPR, Accuracy, Contamination, Direct vs. Tainted detections, and Latency for all workloads.
- Duplicate copy also saved in `experiments/results/figures/evaluation/summary_tables.md`.

---

## Command to Regenerate All Artifacts

To regenerate all figures and summary tables from the evaluation results:

```bash
PYTHONPATH=. venv/bin/python experiments/runners/generate_evaluation_figures.py
```

To run with built-in validation checks:

```bash
PYTHONPATH=. venv/bin/python experiments/runners/generate_evaluation_figures.py --verify
```

---

## Methodological Invariants Enforced

1. **Strict Provenance Separation:** Historical lab traces, synthetic cold host, and held-out zero-day benchmarks are never merged into a combined metric calculation.
2. **Undefined Metric Representation:** When sample counts in a class are zero, metrics are strictly represented as `N/A`, never zero.
3. **Data Immutability:** Generated purely from frozen evaluation artifacts. Detection engines, models, baselines, and configurations are untouched.
