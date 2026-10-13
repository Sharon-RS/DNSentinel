# Phase 6D: Machine Learning Evaluation & Zero-Day Benchmark Report

**Methodology:** Campaign-disjoint zero-day evaluation with temporal progression within the known-campaign training/validation regime.  
**Dataset Reference:** `dnsentinel_ml_features.jsonl` (6,000 records, 31 causal streaming features).  
**Protocol Isolation:** Validation partition (1,276 records) used exclusively for threshold, operating point, and hyperparameter selection. Final test partition (1,714 records) held out and evaluated exactly once.  

---

## 1. Executive Summary & Core Results

| Evaluation Metric | System 1: Behavioral-Only Baseline | System 2: ML30 (30 Raw Features) | System 3: ML31 (31 Features incl. Behavior) | System 4: Hybrid (Behavioral + ML30) | System 5: Tiered Cascade (Fast-Path + ML30) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Operating Threshold** | Score $\ge 62.00$ | $P \ge 0.1850$ | $P \ge 0.1500$ | Score $\ge 20.50$ ($\\beta=0.05$) | $S_{low}=20.0, S_{high}=70.0, P \ge 0.20$ |
| **Zero-Day Recall (@ FPR $\le$ 5%)** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Overall Accuracy** | 99.18% | 100.00% | 99.94% | 100.00% | 100.00% |
| **Precision** | 98.49% | 100.00% | 99.89% | 100.00% | 100.00% |
| **Recall (Sensitivity)** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| **F1-Score** | 99.24% | 100.00% | 99.94% | 100.00% | 100.00% |
| **False Positive Rate (FPR)** | 1.75% | 0.00% | 0.13% | 0.00% | 0.00% |
| **False Negative Rate (FNR)** | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| **ROC-AUC** | 0.9981 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **PR-AUC** | 0.9983 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Empirical Latency P50** | 0.24 $\mu$s | 3742.28 $\mu$s | 3856.70 $\mu$s | 4145.93 $\mu$s | 0.32 $\mu$s |
| **Empirical Latency P99** | 0.29 $\mu$s | 4963.04 $\mu$s | 6331.24 $\mu$s | 6928.20 $\mu$s | 11327.07 $\mu$s |

---

## 2. Confusion Matrices (Final Held-Out Test Set: 1,714 Records)

- **Ground Truth:** 798 Benign queries, 916 Malicious zero-day queries.

```
System 1: Behavioral-Only Baseline
               Predicted Normal (0)   Predicted Attack (1)
Actual Normal (0)       784 (TN)               14 (FP)
Actual Attack (1)         0 (FN)              916 (TP)

System 2: ML30 (30 Raw Causal Features)
               Predicted Normal (0)   Predicted Attack (1)
Actual Normal (0)       798 (TN)                0 (FP)
Actual Attack (1)         0 (FN)              916 (TP)

System 3: ML31 (31 Features incl. Behavior Score)
               Predicted Normal (0)   Predicted Attack (1)
Actual Normal (0)       797 (TN)                1 (FP)
Actual Attack (1)         0 (FN)              916 (TP)

System 4: Hybrid (Behavioral + ML30 Score Fusion)
               Predicted Normal (0)   Predicted Attack (1)
Actual Normal (0)       798 (TN)                0 (FP)
Actual Attack (1)         0 (FN)              916 (TP)

System 5: Tiered Cascade (Fast-Path + ML30)
               Predicted Normal (0)   Predicted Attack (1)
Actual Normal (0)       798 (TN)                0 (FP)
Actual Attack (1)         0 (FN)              916 (TP)
```

---

## 3. Per-Campaign Zero-Day Recall Breakdown

The final test set evaluates four completely unseen attack campaigns that were held out with 0.0% campaign overlap during training and validation:

| Campaign | Threat Archetype | Total Test Queries | Behavioral Baseline Recall | ML30 Recall | ML31 Recall | Hybrid Recall | Cascade Recall |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `campaign_c2_stealth_gamma` | Low-and-Slow C2 Beacons | 166 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| `campaign_tunnel_base64_zeta` | High-Entropy Base64 Tunnel | 250 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| `campaign_tunnel_random_theta`| High-Rate Random Tunnel Burst | 250 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| `campaign_exfil_chunk_iota` | Staged Subdomain Exfiltration | 250 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| **Aggregate Zero-Day** | **All 4 Unseen Campaigns** | **916** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |

---

## 4. Hard-Negative Evaluation

Hard-negative evaluation measures the resilience of the detection models against non-malicious queries with anomalous or suspicious characteristics:

1. **Authentic Hard-Negative Probe (`danger.edu`):**
   - Present in the training stream (samples 2331 and 2334, high entropy 4.32, labeled benign).
   - Behavioral baseline heuristic assigned elevated suspicion ($S = 62.78$).
   - ML30 model predicted probability: $P = 0.1425$ (correctly classified as benign).
   - ML31 model predicted probability: $P = 0.1088$ (correctly classified as benign).
   - Both machine learning architectures successfully suppressed false alarms on high-entropy benign tokens.

2. **Held-Out Ambient Benign Traffic (Session 5: 798 Queries):**
   - Behavioral baseline: FPR = 1.75% (14 false positives / 798 benign).
   - ML30 model: FPR = 0.00% (0 false positives / 798 benign).
   - ML31 model: FPR = 0.13% (1 false positives / 798 benign).
   - Hybrid model: FPR = 0.00% (0 false positives / 798 benign).
   - Tiered Cascade: FPR = 0.00% (0 false positives / 798 benign).

---

## 5. Validation vs. Final Test Generalization Comparison

Operating thresholds were selected **exclusively on the Validation partition (1,276 records)** to satisfy the operational constraint $\text{FPR}_{\text{val}} \le 5.0\%$. Below is the generalization comparison against the held-out Final Test partition (1,714 records):

| Configuration | Validation Recall (@ FPR $\le$ 5%) | Final Test Recall | Validation FPR | Final Test FPR | Generalization Delta (Recall) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Behavioral-Only** | 100.00% | 100.00% | 3.12% | 1.75% | +0.00% |
| **ML30** | 100.00% | 100.00% | 0.00% | 0.00% | +0.00% |
| **ML31** | 100.00% | 100.00% | 0.00% | 0.13% | +0.00% |
| **Hybrid** | 100.00% | 100.00% | 0.00% | 0.00% | +0.00% |
| **Tiered Cascade** | 100.00% | 100.00% | 0.00% | 0.00% | +0.00% |

---

## 6. Latency Acceptance Target Evaluation ($P99 \le 500\,\mu\text{s}$)

Measured using monotonic high-precision timer `time.perf_counter_ns()` across all 1,714 final test observations:

- **Latency Acceptance Target:** $P99 \le 500.0\,\mu\text{s}$
- **Empirical Measurements:**
  - Behavioral Baseline: Mean = 0.25 $\mu$s, P50 = 0.24 $\mu$s, **P99 = 0.29 $\mu$s**
  - ML30 Model: Mean = 3748.45 $\mu$s, P50 = 3742.28 $\mu$s, **P99 = 4963.04 $\mu$s**
  - ML31 Model: Mean = 3917.74 $\mu$s, P50 = 3856.70 $\mu$s, **P99 = 6331.24 $\mu$s**
  - Hybrid Model: Mean = 4279.14 $\mu$s, P50 = 4145.93 $\mu$s, **P99 = 6928.20 $\mu$s**
  - Tiered Cascade: Mean = 1794.70 $\mu$s, P50 = 0.32 $\mu$s, **P99 = 11327.07 $\mu$s**

---

## 7. Protocol Compliance & Isolation Confirmation

- **Untouched Final Test Partition:** The Final Test partition (1,714 records) was evaluated exactly once. Zero final test records were accessed during training, feature selection, probability threshold calibration, $\beta$ optimization, or cascade tuning.
- **Zero Label/State Leakage:** Feature values in the feature dataset `dnsentinel_ml_features.jsonl` were replayed using the audited Option A causal extraction, proving zero temporal state contamination from final test campaigns into training or validation records.

---

## 8. Methodological Limitations & Boundary Framing

1. **Campaign-Disjoint Generalization, Not Future-Time Prediction:**  
   The primary scientific finding establishes that DNSentinel with machine learning generalizes to structurally novel attack campaigns (Base64 encoding, high-entropy bursts, new C2 domains) never seen during training or calibration. It does not claim strict temporal prediction.
2. **Cross-Layer Boundary vs. TunnelEye:**  
   As established in Phase 4, DNSentinel operates at the application/DNS layer with causal sliding windows and organizational profiling, whereas TunnelEye is a flow/packet-level network architecture. Direct numerical comparison between DNSentinel ML and TunnelEye is methodologically invalid because the threat models, feature spaces, and hardware pipeline assumptions differ fundamentally. No claim of superiority over TunnelEye is made.
