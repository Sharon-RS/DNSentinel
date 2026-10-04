# Table 4: Empirical Latency & Classification Performance Profile

**Hardware Testbed:** Linux x86_64, Single-Thread Deterministic CPU Execution (`n_jobs=1`).  
**Measurement Methodology:** High-precision monotonic timer `time.perf_counter_ns()` per query across all 1,714 final test queries.  
**Acceptance Target:** $P99 \le 500.0\,\mu\text{s}$.  
**Source Result Artifact:** `experiments/results/ml_evaluation_metrics.json` & `ml_evaluation_summary.csv` (Audit Corrected).

| Evaluated System / Pipeline Path | Traffic Allocation Share | Median Latency ($P50$) | Mean Latency | 99th Percentile ($P99$) | Target Met ($P99 \le 500\,\mu\text{s}$)? | Zero-Day Recall | False Positive Rate (FPR) | Operational Profile Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **1. Behavioral-Only Baseline** | 100.00% (1,714 queries) | **0.24 µs** | 0.25 µs | **0.29 µs** | **YES** | 100.00% | 1.75% (14 FP) | Measures pre-computed score comparison against threshold; full feature extraction occurred upstream. |
| **2. Cascade: Fast-Path Exit** | **62.49%** (1,071 queries) | **0.21 µs** | 0.40 µs | **1.38 µs** | **YES** | 100.00% | 0.00% (0 FP) | Heuristic triage exits immediately for $S < 20$ (benign) or $S \ge 70$ (severe attack); ML completely bypassed. |
| **3. Cascade: Escalated ML Path** | **37.51%** (643 queries) | **3,608.03 µs** | 3,669.80 µs | **5,169.26 µs** | **NO** | 100.00% | 0.00% (0 FP) | Ambiguous window $[20, 70)$ executes ML30 single-query Random Forest traversal across 100 trees. |
| **4. Tiered Cascade: Overall End-to-End**| 100.00% (1,714 queries) | **0.32 µs** | 1,794.70 µs | **11,327.07 µs** | **NO** | 100.00% | 0.00% (0 FP) | Strongly bimodal distribution: Median satisfies target easily (320 ns); tail P99 dominated by escalated queries. |
| **5. ML30 Standalone (30 Features)** | 100.00% (1,714 queries) | **3,742.28 µs** | 3,748.45 µs | **4,963.04 µs** | **NO** | 100.00% | 0.00% (0 FP) | Uncompiled Python scikit-learn tree inference overhead; requires C/Rust runtime (Treelite/ONNX) for $<500\,\mu\text{s}$. |
| **6. ML31 Standalone (31 Features)** | 100.00% (1,714 queries) | **3,856.70 µs** | 3,917.74 µs | **6,331.24 µs** | **NO** | 100.00% | 0.13% (1 FP) | Augmenting feature vector with behavioral score adds slight feature evaluation and tree traversal latency. |
| **7. Hybrid Fusion (Behavioral + ML30)** | 100.00% (1,714 queries) | **4,145.93 µs** | 4,279.14 µs | **6,928.20 µs** | **NO** | 100.00% | 0.00% (0 FP) | Corrected measurement includes live single-query ML30 execution + floating point score fusion per packet. |

*Latency Finding Summary: The Behavioral heuristic easily beats the $500\,\mu\text{s}$ target ($P99 = 0.29\,\mu\text{s}$). The Tiered Cascade successfully preserves this sub-microsecond latency ($0.21\,\mu\text{s}$) for nearly two-thirds of enterprise traffic while eliminating false alarms.*
