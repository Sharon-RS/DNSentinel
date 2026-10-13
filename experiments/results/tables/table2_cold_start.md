# Table 2: Controlled Three-Way Cold-Start Evaluation Results

**Dataset Reference:** `lab_trace_tunnel_burst.jsonl` (115 tunneling queries across 4 client hosts) & `lab_trace_benign_new_host.jsonl` (100 legitimate queries).  
**Source Result Artifact:** `experiments/results/cold_start_ab_summary.csv` & `cold_start_ab_report.md`.

| Evaluation Dimension | Pipeline A1 (Fresh-Install Control) | Pipeline A2 (Matched Mature-Org Control) | Pipeline B (Mitigated Treatment Architecture) | Controlled Treatment Lift (B vs. A2) | Source Verification File |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Host Profile Baseline** | Empty (Unprofiled, $N=0$) | Empty (Unprofiled, $N=0$) | Empty (Unprofiled, $N=0$) | Strictly Controlled Baseline | `cold_start_ab_summary.csv:2-4` |
| **Organization Baseline** | None (`org_baseline=None`) | `enterprise_org_baseline.json` | `enterprise_org_baseline.json` | Matched Enterprise Prior | `cold_start_ab_summary.csv:2-4` |
| **Cold-Start Buffer & Gating** | Disabled (Immediate Update) | Disabled (Immediate Update) | **Enabled (10-Query Buffer + Gate)** | Architectural Safeguard Active | `src/pipeline/cold_start_pipeline.py` |
| **Full Tunnel Stream Recall** | **31.30%** (36 / 115) | **32.17%** (37 / 115) | **56.52%** (65 / 115) | **+24.35% absolute** (+75.7% relative) | `cold_start_ab_summary.csv:2-4` |
| **Calibration Window Recall ($k \le 10$)** | **10.00%** (1 / 10) | **10.00%** (1 / 10) | **80.00%** (8 / 10) | **+70.00% absolute** (8x lift) | `cold_start_ab_summary.csv:2-4` |
| **First Detection Index ($k_{\text{first}}$)** | Query #10 | Query #10 | **Query #2** | **-8 queries earlier** | `cold_start_ab_summary.csv:2-4` |
| **Cumulative Stream Contamination** | 79 / 115 queries admitted | 78 / 115 queries admitted | **0 / 115 queries admitted** | **-100% (Complete Poisoning Immunity)** | `cold_start_ab_summary.csv:2-4` |
| **Primary Host Persisted Contamination** | 39 / 75 queries admitted | 38 / 75 queries admitted | **0 / 75 queries admitted** | **-100% (0 Poisoned Observations)** | `cold_start_ab_summary.csv:2-4` |
| **Primary Host Entropy Drift** | +4.5265 bits (Severe) | +4.5389 bits (Severe) | **0.0000 bits (Zero Drift)** | **-4.5389 bits** | `cold_start_ab_summary.csv:2-4` |
| **Primary Host Length Drift** | +55.6154 chars | +56.4474 chars | **0.0000 chars (Zero Drift)** | **-56.4474 chars** | `cold_start_ab_summary.csv:2-4` |
| **Legitimate Host Overall FPR** | 11.00% (11 / 100 FP) | 11.00% (11 / 100 FP) | **6.00%** (6 / 100 FP) | **-5.00% absolute** (Stabilized Onboarding) | `cold_start_ab_summary.csv:5-7` |
| **Legitimate Calibration Window FPR** | 10.00% (1 / 10 FP) | 10.00% (1 / 10 FP) | **0.00%** (0 / 10 FP) | **-10.00% absolute** (Zero Early Jitter) | `cold_start_ab_summary.csv:5-7` |
| **Legitimate Host Graduation Status** | N/A (Immediate Updates) | N/A (Immediate Updates) | **Graduated Successfully** | Verified Clean Transition | `cold_start_ab_report.md:92` |
| **Empirical Median Latency ($P50$)** | 0.2830 ms | 0.2905 ms | **0.0516 ms** (51.6 µs) | **-0.2389 ms** | `cold_start_ab_summary.csv:2-4` |
| **Empirical 99th Percentile ($P99$)** | 1.0845 ms | 1.4773 ms | **0.8518 ms** (851.8 µs) | **-0.6255 ms** | `cold_start_ab_summary.csv:2-4` |

*Attribution Note: Decomposing Pipeline A1 -> A2 (+0.87% lift) vs. A2 -> B (+24.35% lift) confirms that organizational priors alone cannot stop cold-start self-poisoning; memory isolation and provisional gating are strictly required.*
