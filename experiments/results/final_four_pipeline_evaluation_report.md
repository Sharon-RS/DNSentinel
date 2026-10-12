# Corrected Evaluation Report: DNSentinel Four-Pipeline Detection Performance

This report documents the audited, reproducible empirical performance of DNSentinel's four detection pipelines:
1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`
2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)
3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path + Random Forest cascade)
4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (Cascade with parent-domain burst taint propagation)

---

## 1. Workload Categorization & Provenance

- **Historical Lab Traces**:
  - `lab_trace_tunnel_burst.jsonl` ($N=115$): BIND9 query log of an authentic Kali Linux DNS tunneling burst against `attacker.lab`.
  - `lab_trace_benign.jsonl` ($N=119$): BIND9 query log of authentic benign enterprise browsing activity.
  - Combined Lab Stream ($N=234$): 115 tunnel queries followed immediately by 119 benign queries to evaluate baseline poisoning.
- **Synthetic Scenario Traces**:
  - `lab_trace_benign_new_host.jsonl` ($N=100$): Synthetic traffic evaluating cold-host prior behavior without baseline poisoning.
- **Held-Out Zero-Day Benchmark (Phase 6D)**:
  - `dnsentinel_ml_benchmark.jsonl` test partition ($N=1,714$, Pos=916, Neg=798): 4 completely unseen zero-day attack campaigns (`gamma`, `zeta`, `theta`, `iota`) interleaved with ambient enterprise traffic across 16 hosts.

---

## 2. Historical & Synthetic Lab Trace Results

### Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)
*Real lab BIND9 query trace of Kali Linux DNS tunneling burst against attacker.lab*
**Sample Size:** $N = 115$ | **Ground-Truth Positives:** 115 | **Ground-Truth Negatives:** 0

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Contamination | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 36 | 0 | 0 | 79 | 31.30% | 100.00% | 47.68% | N/A | 79 | 36 | 0 | 0.289 ms | 0.910 ms |
| **Pipeline B** | 65 | 0 | 0 | 50 | 56.52% | 100.00% | 72.22% | N/A | 0 | 65 | 0 | 0.056 ms | 0.214 ms |
| **ML30 Cascade** | 110 | 0 | 0 | 5 | 95.65% | 100.00% | 97.78% | N/A | 0 | 110 | 0 | 4.721 ms | 5.873 ms |
| **ML30 + Burst-Taint** | 114 | 0 | 0 | 1 | 99.13% | 100.00% | 99.56% | N/A | 0 | 110 | 4 | 4.955 ms | 5.558 ms |

### Historical Lab Benign Trace (lab_trace_benign.jsonl)
*Real lab BIND9 query trace of benign background browsing activity*
**Sample Size:** $N = 119$ | **Ground-Truth Positives:** 0 | **Ground-Truth Negatives:** 119

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Contamination | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 0 | 21 | 98 | 0 | N/A | 0.00% | N/A | 17.65% | 0 | 21 | 0 | 0.267 ms | 0.838 ms |
| **Pipeline B** | 0 | 19 | 100 | 0 | N/A | 0.00% | N/A | 15.97% | 0 | 19 | 0 | 0.249 ms | 1.976 ms |
| **ML30 Cascade** | 0 | 5 | 114 | 0 | N/A | 0.00% | N/A | 4.20% | 0 | 5 | 0 | 1.266 ms | 5.579 ms |
| **ML30 + Burst-Taint** | 0 | 7 | 112 | 0 | N/A | 0.00% | N/A | 5.88% | 0 | 5 | 2 | 1.271 ms | 5.514 ms |

### Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)
*Synthetic cold-host scenario evaluating cold-start false alarm suppression*
**Sample Size:** $N = 100$ | **Ground-Truth Positives:** 0 | **Ground-Truth Negatives:** 100

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Contamination | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 0 | 11 | 89 | 0 | N/A | 0.00% | N/A | 11.00% | 0 | 11 | 0 | 0.301 ms | 0.481 ms |
| **Pipeline B** | 0 | 6 | 94 | 0 | N/A | 0.00% | N/A | 6.00% | 0 | 6 | 0 | 0.333 ms | 0.540 ms |
| **ML30 Cascade** | 0 | 0 | 100 | 0 | N/A | N/A | N/A | 0.00% | 0 | 0 | 0 | 2.242 ms | 5.682 ms |
| **ML30 + Burst-Taint** | 0 | 0 | 100 | 0 | N/A | N/A | N/A | 0.00% | 0 | 0 | 0 | 2.308 ms | 6.040 ms |

### Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)
*Continuous stream of 115 tunnel-burst queries immediately followed by 119 benign queries*
**Sample Size:** $N = 234$ | **Ground-Truth Positives:** 115 | **Ground-Truth Negatives:** 119

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Contamination | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 36 | 116 | 3 | 79 | 31.30% | 23.68% | 26.96% | 97.48% | 79 | 152 | 0 | 0.229 ms | 0.549 ms |
| **Pipeline B** | 65 | 5 | 114 | 50 | 56.52% | 92.86% | 70.27% | 4.20% | 0 | 70 | 0 | 0.062 ms | 0.142 ms |
| **ML30 Cascade** | 110 | 2 | 117 | 5 | 95.65% | 98.21% | 96.91% | 1.68% | 0 | 112 | 0 | 2.937 ms | 5.439 ms |
| **ML30 + Burst-Taint** | 114 | 2 | 117 | 1 | 99.13% | 98.28% | 98.70% | 1.68% | 0 | 112 | 4 | 2.961 ms | 5.506 ms |

---

## 3. Audited Missed-Query Breakdown on Tunnel-Burst Attack Trace

On `lab_trace_tunnel_burst.jsonl`, standard ML30 Cascade misses exactly 5 queries out of 115. `BurstTaintCascadePipeline` recovers 4 of these 5 queries via parent-domain burst taint propagation:

| Query # (1-Based) | Domain | True Label | Cascade Decision | ML Prob | Cascade Path | Burst-Taint Decision | Detection Source |
| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :--- |
| **#1** | `hello.attacker.lab` | 1 (Attack) | BENIGN | 0.0 | `ML_ESCALATED` | **BENIGN** | `DIRECT_CLEAR` |
| **#10** | `525443.end.attacker.lab` | 1 (Attack) | BENIGN | 0.1493 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` |
| **#19** | `0c8e0e.end.attacker.lab` | 1 (Attack) | BENIGN | 0.066 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` |
| **#28** | `626833.end.attacker.lab` | 1 (Attack) | BENIGN | 0.1368 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` |
| **#37** | `b78dd1.end.attacker.lab` | 1 (Attack) | BENIGN | 0.056 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` |

> [!NOTE]
> **Causal Handshake Limitation:** Query #1 (`hello.attacker.lab`) arrives at the start of the session prior to any malicious observation. Because no attack has been confirmed yet, no active taint exists, and the query is evaluated purely on its benign lexical features ($P_{\text{ML}} = 0.0000$).
> Queries #10, #19, #28, and #37 (`*.end.attacker.lab`) are short delimiter chunks that score below the ML threshold ($P < 0.20$), but are successfully recovered because they share the parent domain `attacker.lab` with confirmed attack chunks from the same host.

---

## 4. Held-Out Zero-Day Benchmark Partition Evaluation

Evaluated on the 1,714 held-out test events from `dnsentinel_ml_benchmark.jsonl` ($N=1,714$, Pos=916, Neg=798).

| Pipeline Architecture | Execution Mode | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | Online Live | 338 | 300 | 498 | 578 | **36.90%** | 52.98% | 43.50% | 37.59% | 48.77% |
| **Pipeline B** | Online Live | 427 | 124 | 674 | 489 | **46.62%** | 77.50% | 58.22% | 15.54% | 64.24% |
| **ML30 Cascade** | Online Live | 916 | 0 | 798 | 0 | **100.00%** | 100.00% | 100.00% | 0.00% | 100.00% |
| **ML30 + Burst-Taint** | Online Live | 916 | 0 | 798 | 0 | **100.00%** | 100.00% | 100.00% | 0.00% | 100.00% |

### Key Findings on Held-Out Zero-Day Benchmark
1. **Failure of Heuristic Baselines on Cold Hosts:**
   - **Pipeline A1** detects only 338 of 916 attacks (Recall: 36.90%) and generates 300 false positives (FPR: 37.59%) due to cold-start baseline contamination.
   - **Pipeline B** leverages the enterprise prior to avoid full poisoning, improving recall to 46.62% and reducing FPR to 15.54%, but still misses 489 zero-day queries.
2. **Cascade Superiority:**
   - Both **ML30 Cascade** and **ML30 + Burst-Taint** achieve **100.00% Recall** (916/916 attacks detected) and **0.00% FPR** (798/798 benign cleared) on completely unseen zero-day campaigns.
3. **Hard-Negative Evaluation Status:**
   - In `dnsentinel_ml_benchmark.jsonl`, both `m92xk7qlp81zr4.danger.edu` queries reside in the training split ($t < 18,000$s). The validation and test partitions contain **0** `danger.edu` observations.
   - Hard-negative generalization on `danger.edu` is therefore labeled **UNTESTED** on the test partition.

---

## 5. Mathematical Metric Definitions & Undefined Conventions

Let $y \in \{0, 1\}$ denote the ground-truth label and $\hat{y} \in \{0, 1\}$ denote the binary prediction:
- $\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$ (Undefined / `N/A` when $\text{TP} + \text{FN} = 0$)
- $\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$ (Undefined / `N/A` when $\text{TP} + \text{FP} = 0$)
- $\text{F1-Score} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ (Undefined / `N/A` when Precision or Recall is undefined)
- $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$ (Undefined / `N/A` when $\text{FP} + \text{TN} = 0$)
- $\text{Accuracy} = \frac{\text{TP} + \text{TN}}{N}$

All calculations strictly enforce these definitions without substituting arbitrary default values.
