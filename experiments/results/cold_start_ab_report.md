# Phase 3 Cold-Start Mitigation: Research Three-Way Comparative Evaluation Report

## 1. Executive Summary & Methodology Correction

This report presents the corrected, three-way experimental evaluation of DNSentinel's cold-start mitigation architecture (**Pipeline B**) against pre-mitigation controls (**Pipeline A**, commit `831c233`).

### Methodology Audit & Experimental Initialization Asymmetry

A prior methodology audit identified an experimental initialization asymmetry in the initial A/B reporting:
- Pipeline A was initially evaluated with an empty organization profile (`org_baseline_file=None`), reflecting a fresh-install scenario (**31.30% recall**, 79 cumulative admitted malicious queries).
- Pipeline B was evaluated with a mature organization baseline (`enterprise_org_baseline.json`), reflecting a mature enterprise deployment (**56.52% recall**, 0 baseline contamination).

To eliminate this asymmetry, the evaluation layer was restructured into three strictly controlled experiments:
1. **Experiment 1 (Pipeline A1 — Fresh/Unprofiled Control):** Empty host profiles, empty organization baseline (`org_baseline_file=None`). Reproduces historical baseline performance.
2. **Experiment 2 (Pipeline A2 — Mature Organization Control):** Empty host profiles, exact same `enterprise_org_baseline.json` as Pipeline B. Measures the isolated contribution of a mature organizational baseline without cold-start mitigation.
3. **Experiment 3 (Pipeline B — Cold-Start Mitigated Treatment):** Empty host profiles, exact same `enterprise_org_baseline.json`. Measures the full cold-start mitigation architecture (provisional calibration buffer, zero unverified persistence, dynamic rate scaling, and post-calibration gating).

> [!IMPORTANT]
> **Controlled Attribution Rule:** The experimental reporting must **NOT** present "31.30% -> 56.52%" as a single controlled A/B improvement. Instead:
> - Fresh-Install Control (A1): **31.30%**
> - Mature-Org Control (A2): **32.17%**
> - Mitigated Treatment (B): **56.52%**
>
> The true effect of the cold-start mitigation architecture relative to the matched mature-organization baseline is **+24.35% absolute** (**+75.7% relative** recall improvement) and a **100% reduction** in baseline contamination (from 78 down to 0 admitted queries).

---

## 2. Three-Way Results Table (Historical Tunnel Burst Trace)

Evaluated on `lab_trace_tunnel_burst.jsonl` (115 tunneling queries across 4 client hosts).

| Evaluation Metric | Pipeline A1 (Fresh Control) | Pipeline A2 (Mature Control) | Pipeline B (Mitigated Treatment) | Treatment Delta (B vs. A2) |
| :--- | :--- | :--- | :--- | :--- |
| **Historical Tunnel Recall (Full Stream)** | **0.3130** (31.30%) | **0.3217** (32.17%) | **0.5652** (56.52%) | **+0.2435** (+24.35%) |
| **Calibration Window Recall ($k \le 10$)** | **0.1000** (10.00%) | **0.1000** (10.00%) | **0.8000** (80.00%) | **+0.7000** (+70.00%) |
| **Full Stream Precision** | 1.0000 | 1.0000 | 1.0000 | +0.0000 |
| **Full Stream F1-Score** | 0.4768 | 0.4868 | 0.7222 | **+0.2354** |
| **False Negative Rate (FNR)** | 0.6870 | 0.6783 | 0.4348 | **-0.2435** |
| **First Detection Query Index ($k_{\text{first}}$)** | Query #10 | Query #10 | Query #2 | **-8 queries earlier** |
| **Malicious Queries Scoring $< 30$** | 40 / 115 | 38 / 115 | 0 / 115 | -38 |
| **Malicious Admitted in Calibration ($k \le 10$)** | 9 / 10 | 9 / 10 | 0 / 10 | **-9** (-100%) |
| **Cumulative Stream Contamination (All Hosts)** | **79 / 115** | **78 / 115** | **0 / 115** | **-78** (-100%) |
| **Primary Host Persisted Queries (`192.168.145.128`)** | **39 / 75** | **38 / 75** | **0 / 75** | **-38** (-100%) |
| **Primary Host Baseline Entropy Drift** | +4.5265 | +4.5389 | **0.0000** | -4.5389 |
| **Primary Host Baseline Length Drift** | +55.6154 | +56.4474 | **0.0000** | -56.4474 |
| **Mean Query Processing Latency** | 0.2924 ms | 0.3156 ms | 0.0806 ms | -0.2350 ms |
| **Median Query Processing Latency** | 0.2830 ms | 0.2905 ms | 0.0516 ms | -0.2389 ms |
| **p99 Latency (Nearest-Rank)** | 1.0845 ms | 1.4773 ms | 0.8518 ms | -0.6255 ms |

---

## 3. Contamination Metric Semantics & Multi-Host Architecture

The recorded lab tunnel trace (`lab_trace_tunnel_burst.jsonl`) contains 115 total queries originating from **4 distinct IP addresses**:
- `192.168.145.128`: 75 queries (primary attacking tunneling client)
- `192.168.145.1`: 26 queries (gateway/resolver queries)
- `192.168.145.130`: 12 queries (auxiliary test client)
- `192.168.145.129`: 2 queries (auxiliary test client)

To prevent ambiguity, two distinct contamination metrics are tracked and reported:

1. **Cumulative Stream Contamination (`cumulative_stream_contamination`):**
   - **Scope:** Across all 115 queries in the multi-host stream.
   - **Definition:** The total number of malicious DNS queries whose behavioral score was below the update cutoff (`< 30` in steady-state, or admitted via unmitigated pipeline logic) that resulted in a baseline update to *any* host profile.
   - **Empirical Results:**
     - Pipeline A1: **79 / 115** queries admitted across the stream.
     - Pipeline A2: **78 / 115** queries admitted across the stream.
     - Pipeline B: **0 / 115** queries admitted across the stream.

2. **Primary Host Persisted Query Count (`primary_host_persisted_queries`):**
   - **Scope:** Specifically for the primary attacking host `192.168.145.128` (75 total queries).
   - **Definition:** The number of observations committed to `data/profiles/192.168.145.128.json` at the conclusion of the evaluation stream.
   - **Empirical Results:**
     - Pipeline A1: **39 / 75** queries persisted (40 queries flagged $\ge 30$ and dropped by standard baseline protection).
     - Pipeline A2: **38 / 75** queries persisted (37 queries flagged $\ge 30$ and dropped by standard baseline protection).
     - Pipeline B: **0 / 75** queries persisted (quarantined during calibration and discarded upon graduation failure).

Both metrics demonstrate that Pipeline B achieves complete immunity (**0 contamination**) against baseline poisoning during cold start.

---

## 4. Legitimate New-Host Workload Evaluation

Evaluated on `lab_trace_benign_new_host.jsonl` (100 legitimate queries from an unprofiled internal host `10.0.0.99`).

| Evaluation Metric | Pipeline A1 (Fresh Control) | Pipeline A2 (Mature Control) | Pipeline B (Mitigated Treatment) |
| :--- | :--- | :--- | :--- |
| **Total Legitimate Queries** | 100 | 100 | 100 |
| **False Positive Count ($FP$)** | 11 | 11 | **6** |
| **False Positive Rate (FPR)** | 0.1100 (11.00%) | 0.1100 (11.00%) | **0.0600** (6.00%) |
| **Calibration Window FPR ($k \le 10$)** | 0.1000 (10.00%) | 0.1000 (10.00%) | **0.0000** (0.00%) |
| **Calibration Graduation Status** | N/A (Immediate Updates) | N/A (Immediate Updates) | **Graduated Successfully** |
| **Final Persisted Profile Observations** | 89 queries | 89 queries | **94 queries** |
| **Mean Processing Latency** | 0.2546 ms | 0.2674 ms | 0.2987 ms |
| **p99 Latency (Nearest-Rank)** | 1.1102 ms | 0.9342 ms | 1.5149 ms |

### Legitimate Host Findings:
- In Pipeline B, the legitimate host incurred **0 false positives** in the calibration window ($k \le 10$).
- All 10 calibration queries passed post-calibration graduation gating (`max_score = 25.0 < 50.0`, `mean_score = 15.6 < 30.0`).
- Observations were safely committed into `data/profiles/10.0.0.99.json`, graduating the host to steady-state operation.
- Overall FPR for Pipeline B dropped to **6.00%**, compared to 11.00% in both Pipeline A1 and A2, demonstrating that cold-start calibration stabilizes legitimate hosts and suppresses initialization jitter.

---

## 5. Architectural & Forensic Analysis

### Why Pipeline A2 Achieves Only Marginal Improvement (31.30% -> 32.17%)

Providing a mature organization baseline to Pipeline A increased recall by only **+0.87%** (from 36/115 to 37/115 detections). Forensic inspection reveals the exact cause:

1. **Immediate Host Baseline Creation:** In Pipeline A, the very first query from an unprofiled host initializes `ProfileManager.get_profile(ip)`.
2. **Prioritization of Host Profile over Org Baseline:** In `DeviationCalculator`, when `host_profile.total_queries > 0`, query distance is calculated strictly against the host profile, completely ignoring the mature organization baseline.
3. **Immediate Self-Poisoning:** Because the first query scores below the `NORMAL < 30` cutoff (due to absent query-rate history and zero prior deviations), it is committed directly to the host profile. The host profile's baseline entropy jumps from 0 to 4.2, and mean domain length jumps to 28.
4. **Suppression of Future Deviations:** For subsequent queries #2 through #10, incoming tunnel queries are compared against this newly poisoned host profile. Because the host profile now expects entropy ~4.2 and length ~28, deviations are near zero, allowing the attack to progress undetected.

### How Pipeline B Resolves the Cold-Start Vulnerability

Pipeline B combines four architectural safeguards:
1. **Provisional Calibration Window ($k \le 10$):** Early observations are buffered in memory and isolated from persistent disk baselines.
2. **Clean Organization Fallback:** Because the host profile remains uncommitted during calibration, `DeviationCalculator` consistently evaluates queries against the clean enterprise organization baseline.
3. **Early Burst Dynamics:** Query rate tracking detects high-frequency bursts immediately, scaling deviation scores without waiting for host maturation.
4. **Post-Calibration Graduation Gating:** At Query #11, the buffer is evaluated. If any query breached the suspicion threshold (`max_score >= 50.0`), graduation is aborted, the buffer is purged, and the host profile is preserved in an uncontaminated state.

---

## 6. Experimental Verification & Integrity Checklist

- [x] Complete sandbox filesystem isolation (`sandbox_env` per evaluation run).
- [x] Bitwise verification of live profiles in `data/profiles/` and `data/organization/`.
- [x] No modifications to production pipeline `src/pipeline/detection_pipeline.py`.
- [x] No modifications to production thresholds or scoring formulas.
- [x] Deterministic nearest-rank p99 latency calculation.
- [x] Three-way evaluation separating Fresh-Install Control, Mature-Org Control, and Treatment.
