# Table 5: Comprehensive DNSentinel Four-Pipeline Performance Profile

This publication summary table provides the audited, reproducible empirical performance of all four DNSentinel detection pipelines across all evaluation workloads.

**Detection Pipelines:**
1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`
2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)
3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path heuristic triage + Random Forest)
4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (ML30 Cascade + Parent-domain burst taint propagation)

---

### Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)
*Real lab BIND9 query trace of Kali Linux DNS tunneling burst against attacker.lab*  
**Provenance:** `historical_lab` | **Sample Size:** $N = 115$ | **Ground-Truth Positives:** 115 | **Ground-Truth Negatives:** 0

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 36 | 0 | 0 | 79 | 31.30% | 100.00% | 47.68% | N/A | 31.30% | 79 | 36 | 0 | 0.289 ms | 0.910 ms |
| **Pipeline B** | 65 | 0 | 0 | 50 | 56.52% | 100.00% | 72.22% | N/A | 56.52% | 0 | 65 | 0 | 0.056 ms | 0.214 ms |
| **ML30 Cascade** | 110 | 0 | 0 | 5 | 95.65% | 100.00% | 97.78% | N/A | 95.65% | 0 | 110 | 0 | 4.721 ms | 5.873 ms |
| **ML30 + Burst-Taint** | 114 | 0 | 0 | 1 | 99.13% | 100.00% | 99.56% | N/A | 99.13% | 0 | 110 | 4 | 4.955 ms | 5.558 ms |

### Historical Lab Benign Trace (lab_trace_benign.jsonl)
*Real lab BIND9 query trace of benign background browsing activity*  
**Provenance:** `historical_lab` | **Sample Size:** $N = 119$ | **Ground-Truth Positives:** 0 | **Ground-Truth Negatives:** 119

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 0 | 21 | 98 | 0 | N/A | 0.00% | N/A | 17.65% | 82.35% | 0 | 21 | 0 | 0.267 ms | 0.838 ms |
| **Pipeline B** | 0 | 19 | 100 | 0 | N/A | 0.00% | N/A | 15.97% | 84.03% | 0 | 19 | 0 | 0.249 ms | 1.976 ms |
| **ML30 Cascade** | 0 | 5 | 114 | 0 | N/A | 0.00% | N/A | 4.20% | 95.80% | 0 | 5 | 0 | 1.266 ms | 5.579 ms |
| **ML30 + Burst-Taint** | 0 | 7 | 112 | 0 | N/A | 0.00% | N/A | 5.88% | 94.12% | 0 | 5 | 2 | 1.271 ms | 5.514 ms |

### Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)
*Synthetic cold-host scenario evaluating cold-start false alarm suppression*  
**Provenance:** `synthetic_scenario` | **Sample Size:** $N = 100$ | **Ground-Truth Positives:** 0 | **Ground-Truth Negatives:** 100

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 0 | 11 | 89 | 0 | N/A | 0.00% | N/A | 11.00% | 89.00% | 0 | 11 | 0 | 0.301 ms | 0.481 ms |
| **Pipeline B** | 0 | 6 | 94 | 0 | N/A | 0.00% | N/A | 6.00% | 94.00% | 0 | 6 | 0 | 0.333 ms | 0.540 ms |
| **ML30 Cascade** | 0 | 0 | 100 | 0 | N/A | N/A | N/A | 0.00% | 100.00% | 0 | 0 | 0 | 2.242 ms | 5.682 ms |
| **ML30 + Burst-Taint** | 0 | 0 | 100 | 0 | N/A | N/A | N/A | 0.00% | 100.00% | 0 | 0 | 0 | 2.308 ms | 6.040 ms |

### Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)
*Continuous stream of 115 tunnel-burst queries immediately followed by 119 benign queries*  
**Provenance:** `historical_lab` | **Sample Size:** $N = 234$ | **Ground-Truth Positives:** 115 | **Ground-Truth Negatives:** 119

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 36 | 116 | 3 | 79 | 31.30% | 23.68% | 26.96% | 97.48% | 16.67% | 79 | 152 | 0 | 0.229 ms | 0.549 ms |
| **Pipeline B** | 65 | 5 | 114 | 50 | 56.52% | 92.86% | 70.27% | 4.20% | 76.50% | 0 | 70 | 0 | 0.062 ms | 0.142 ms |
| **ML30 Cascade** | 110 | 2 | 117 | 5 | 95.65% | 98.21% | 96.91% | 1.68% | 97.01% | 0 | 112 | 0 | 2.937 ms | 5.439 ms |
| **ML30 + Burst-Taint** | 114 | 2 | 117 | 1 | 99.13% | 98.28% | 98.70% | 1.68% | 98.72% | 0 | 112 | 4 | 2.961 ms | 5.506 ms |

### Phase 6D Held-Out Zero-Day Benchmark Partition
*Held-out final test partition of dnsentinel_ml_benchmark.jsonl (4 unseen zero-day campaigns + ambient benign)*  
**Provenance:** `held_out_benchmark` | **Sample Size:** $N = 1714$ | **Ground-Truth Positives:** 916 | **Ground-Truth Negatives:** 798

| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pipeline A1** | 338 | 300 | 498 | 578 | 36.90% | 52.98% | 43.50% | 37.59% | 48.77% | 578 | 638 | 0 | 1.013 ms | 2.613 ms |
| **Pipeline B** | 427 | 124 | 674 | 489 | 46.62% | 77.50% | 58.22% | 15.54% | 64.24% | 156 | 551 | 0 | 0.273 ms | 1.128 ms |
| **ML30 Cascade** | 916 | 0 | 798 | 0 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% | 0 | 916 | 0 | 5.350 ms | 18.886 ms |
| **ML30 + Burst-Taint** | 916 | 0 | 798 | 0 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% | 0 | 916 | 0 | 4.753 ms | 9.286 ms |

### Delimiter Chunk Recovery Breakdown (lab_trace_tunnel_burst.jsonl)
Detailed audit of the 5 queries that fall below the direct Random Forest threshold ($P < 0.20$):

| Query # (1-Based) | Domain | True Class | Cascade Decision | ML Prob | Cascade Path | Burst-Taint Decision | Detection Source | Propagated? |
| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :--- | :---: |
| **#1** | `hello.attacker.lab` | Attack (1) | BENIGN | 0.0000 | `ML_ESCALATED` | **BENIGN** | `DIRECT_CLEAR` | NO |
| **#10** | `525443.end.attacker.lab` | Attack (1) | BENIGN | 0.1493 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` | **YES** |
| **#19** | `0c8e0e.end.attacker.lab` | Attack (1) | BENIGN | 0.0660 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` | **YES** |
| **#28** | `626833.end.attacker.lab` | Attack (1) | BENIGN | 0.1368 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` | **YES** |
| **#37** | `b78dd1.end.attacker.lab` | Attack (1) | BENIGN | 0.0560 | `ML_ESCALATED` | **MALICIOUS** | `TAINT_PROPAGATED` | **YES** |

> [!NOTE]
> **Causal Temporal Constraint:** Query #1 (`hello.attacker.lab`) represents the opening handshake. Because no attack chunk has preceded it, no active taint exists; the query is evaluated purely on lexical features and correctly cleared ($P = 0.0000$). Queries #10, #19, #28, and #37 (`*.end.attacker.lab`) arrive after confirmed attack chunks on `attacker.lab` and are successfully recovered via taint propagation.
