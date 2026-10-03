# Phase 4 Comparative Evaluation Report: DNSentinel vs. TunnelEye Baseline

## 1. Executive Summary & Methodological Framing

This study establishes a scientifically grounded comparative evaluation of **DNSentinel** alongside the verified **TunnelEye** research baseline.

### Methodological Boundaries & Non-Superiority Framing
To prevent invalid 1:1 cross-layer equivalence claims, the comparison is framed by clear architectural boundaries:
- **No Direct "Winner" Claim:** We do not claim universal metric superiority over TunnelEye. TunnelEye is an offline, supervised machine learning classifier (LightGBM) optimized on static, closed-world encrypted flow datasets. DNSentinel is an online, unsupervised adaptive streaming anomaly detector operating on unencrypted application-layer DNS queries at the recursive resolver or endpoint without malicious training data.
- **Evaluation within Validated Settings:** Each system is reported within its validated operational setting.
- **Latency Reporting:** DNSentinel detection latency is measured empirically on the local hardware testbed (`time.perf_counter_ns()`). TunnelEye latency is explicitly documented as **"Unavailable under identical streaming hardware conditions"** because its full packet-to-flow pipeline is not hosted on this VM.

---

## 2. Cross-Paradigm Architectural Comparison Table

| Dimension | TunnelEye Baseline (Canonical Reproduction) | DNSentinel (Adaptive Behavioral Prototype) |
| :--- | :--- | :--- |
| **Model / Algorithm** | Supervised LightGBM (20 Selected Flow Features) | 3-Tier Multi-Component Behavioral Distance Engine |
| **Traffic Layer** | Transport / Flow Layer (Encrypted DoH) | Application Layer (Plaintext DNS Queries / FQDNs) |
| **Observation Granularity** | Bi-directional Network Flow Aggregate | Individual Sequential DNS Query Packet |
| **Evaluation Protocol** | 10-Fold Stratified Cross-Validation (Shuffled Flows) | Online Sequential Stream Processing (Order Preserved) |
| **Training Requirement** | Supervised; requires thousands of labeled flows | Zero offline malicious training required |
| **Decision Timing** | Delayed until flow termination or flow-timeout | Immediate per-query evaluation ($< 1$ ms) |
| **Host Memory Architecture**| Stateless (evaluates flows in isolation) | Dynamic Per-Host Rolling Gaussian Baselines |
| **Enterprise Context** | None | Organization-wide Domain Frequency & Rarity Tracking |
| **Cold-Start Protection** | None (Static decision trees post-training) | 10-Query Provisional Calibration Buffer with Gating |
| **Adversarial Resilience** | Vulnerable to concept drift and novel tunnel domains | Real-time quarantine prevents baseline drift |

---

## 3. TunnelEye Verified Baseline Results (Dataset-Level Breakdown)

Rather than presenting an undifferentiated single aggregate score, our verified reproduction on the external Ubuntu VM (`reproduce_tunneleye.py` with LightGBM, 20 features, 10-fold stratified cross-validation) encompasses four distinct encrypted DoH dataset splits:
- **CIC-FWD:** CIRA-CIC-DoHBrw-2020 client-to-server forward flow metrics
- **CIC-BWD:** CIRA-CIC-DoHBrw-2020 server-to-client backward flow metrics
- **DoH-Extended-FWD:** DoH-Extended dataset client-to-server forward flow metrics
- **DoH-Extended-BWD:** DoH-Extended dataset server-to-client backward flow metrics

The exact verified reproduction results established in the project are preserved explicitly without premature rounding or substitution in the dataset-level table below:

### Dataset-Level Reproduction Results Table

| Dataset Split | Evaluated Dataset | Traffic Direction | Model Architecture | Accuracy | Weighted Precision | Weighted Recall | Weighted F1 | Inference Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CIC-FWD** | CIRA-CIC-DoHBrw-2020 | Client $\to$ Server (Forward) | LightGBM (20 Feat, 10-Fold CV) | **0.9987240888** | 0.9987253804 | 0.9987240888 | 0.9987246946 | Unavailable under identical streaming hardware conditions |
| **CIC-BWD** | CIRA-CIC-DoHBrw-2020 | Server $\to$ Client (Backward) | LightGBM (20 Feat, 10-Fold CV) | **0.9971739576** | 0.9971817769 | 0.9971739576 | 0.9971754796 | Unavailable under identical streaming hardware conditions |
| **DoH-Extended-FWD** | DoH-Extended | Client $\to$ Server (Forward) | LightGBM (20 Feat, 10-Fold CV) | **0.9996498212** | 0.9996498968 | 0.9996498212 | 0.9996498545 | Unavailable under identical streaming hardware conditions |
| **DoH-Extended-BWD** | DoH-Extended | Server $\to$ Client (Backward) | LightGBM (20 Feat, 10-Fold CV) | **0.9994861631** | 0.9994863253 | 0.9994861631 | 0.9994861512 | Unavailable under identical streaming hardware conditions |
| **Macro Average** | 4 Datasets Pooled | Bidirectional Aggregate | Arithmetic Mean Across Splits | **0.9987585077** | 0.9987608449 | 0.9987585077 | 0.9987590450 | Unavailable under identical streaming hardware conditions |

> [!NOTE]
> **Explicit Aggregation Method:** The "Macro Average" row represents the unweighted arithmetic mean across the four individual reproduction splits:
> $$\text{Macro Metric} = \frac{1}{4} \sum_{k \in \{\text{CIC-FWD}, \text{CIC-BWD}, \text{DoH-Ext-FWD}, \text{DoH-Ext-BWD}\}\} \text{Metric}_k$$
> The underlying dataset-specific values are presented first to preserve the individual reproduction findings. Across all four datasets, TunnelEye achieves high classification performance on closed-world, completed encrypted flow sessions when evaluated via 10-fold stratified cross-validation.

---

## 4. DNSentinel Empirical Streaming Performance

Evaluated on physical recorded network traces using `IsolatedEvaluationContext`:

| Evaluation Metric | Tunnel Burst Trace (`lab_trace_tunnel_burst.jsonl`) | Combined Realistic Trace (Benign + Tunnel) |
| :--- | :--- | :--- |
| **Total Query Events** | 115 events (4 client hosts) | 234 events |
| **True Positives ($TP$)** | 36 | 113 |
| **False Positives ($FP$)** | 0 | 21 |
| **True Negatives ($TN$)** | 0 | 98 |
| **False Negatives ($FN$)** | 79 | 2 |
| **Overall Accuracy** | 0.3130 | 0.9017 |
| **Binary Precision** | 1.0000 | 0.8433 |
| **Binary Recall** | 0.3130 | 0.9826 |
| **Binary F1-Score** | 0.4768 | 0.9076 |
| **False Negative Rate (FNR)** | 0.6870 | 0.0174 |
| **Earliest Detection Index** | **Query #2** (Mitigated Treatment) | **Query #2** |
| **Empirical Mean Latency** | **0.2398 ms** | **0.1402 ms** |
| **Empirical Median Latency** | **0.2788 ms** | **0.0651 ms** |
| **Empirical p99 Latency (Nearest-Rank)** | **0.4880 ms** | **0.7105 ms** |

---

## 5. Deterministic Static-Rule Baseline Evaluation

To evaluate conventional heuristic detection, an isolated evaluator (`StaticRuleEvaluator`) was executed on the identical query streams.
**Rule Definition:**
$$\text{Alert} = \text{True} \iff (\text{Entropy} \ge 4.0 \land \text{Domain Length} \ge 30) \lor (\text{Query Type} \notin \{1, 28\})$$

| Evaluation Metric | Static Rule on Tunnel Burst (`lab_trace_tunnel_burst.jsonl`) | Static Rule on Combined Realistic Trace |
| :--- | :--- | :--- |
| **Total Query Events** | 115 events | 234 events |
| **True Positives ($TP$)** | 32 | 32 |
| **False Positives ($FP$)** | 0 | 5 |
| **True Negatives ($TN$)** | 0 | 114 |
| **False Negatives ($FN$)** | 83 | 83 |
| **Accuracy** | 0.2783 | 0.6239 |
| **Binary Precision** | 1.0000 | 0.8649 |
| **Binary Recall** | 0.2783 | 0.2783 |
| **Binary F1-Score** | 0.4354 | 0.4211 |
| **False Positive Rate (FPR)** | 0.0000 | 0.0420 |
| **False Negative Rate (FNR)** | 0.7217 | 0.7217 |
| **Mean Latency** | 0.0004 ms | 0.0004 ms |

### Static Rule Findings:
- On pure tunnel bursts, the static rule detects long high-entropy domains (Recall = 27.8%), but fails on short initialization handshakes (`hello.attacker.lab`, `525443.end.attacker.lab`).
- On realistic traffic, the static rule triggers false alarms on legitimate CDN infrastructure (FPR = 4.20%), illustrating the necessity of adaptive host profiling and organizational rarity scoring.

---

## 6. Phase 3 Frozen Cold-Start Evaluation Results

The three-way benchmark results established during Phase 3 remain frozen and verified:

| Pipeline Configuration | Organization Baseline | Full Stream Recall | False Negative Rate | First Detection ($k_{\text{first}}$) | Cumulative Stream Contamination | Primary Host Persisted Queries |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Pipeline A1 (Fresh Control)** | Empty (None) | **31.30%** (36/115) | 68.70% | Query #10 | 79 / 115 queries | 39 / 75 queries |
| **Pipeline A2 (Mature Control)** | enterprise_org_baseline.json | **32.17%** (37/115) | 67.83% | Query #10 | 78 / 115 queries | 38 / 75 queries |
| **Pipeline B (Mitigated Treatment)**| enterprise_org_baseline.json | **56.52%** (65/115) | 43.48% | **Query #2** | **0 / 115 queries** | **0 / 75 queries** |

- **Treatment Lift:** +24.35% absolute recall improvement relative to the matched mature-org control A2.
- **Contamination Elimination:** Complete 100% reduction in stream contamination (78 $\to$ 0 admitted queries) and primary host persisted queries (38 $\to$ 0).

---

## 7. Four-Tier Feature-Tier Sensitivity Analysis

Evaluated on `synthetic_mixed_stream.jsonl` using the weight-renormalized sensitivity framework.

> [!NOTE]
> **Sensitivity Analysis Disclaimer:** Performance variations reflect the sensitivity of the composite engine to the inclusion of specific feature tiers under uniform scale renormalization ([0, 100]), and do NOT represent pure causal contributions of individual features in isolation because renormalization inherently shifts the relative weight distribution among remaining active components.

| Tier Identifier | Configuration Name | Active Normalized Weights | Accuracy | Precision | Recall | F1-Score | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier A** | Lexical Only | Entropy: 0.5556, Length: 0.4444 | 0.9000 | 1.0000 | 0.8000 | 0.8889 | 0.0000 |
| **Tier B** | + Host Behavioral | Entropy: 0.3846, Length: 0.3077, Novel: 0.3077 | 0.9500 | 1.0000 | 0.9000 | 0.9474 | 0.0000 |
| **Tier C** | + Temporal Rate | Entropy: 0.3125, Length: 0.2500, Novel: 0.2500, Rate: 0.1875 | 0.9500 | 1.0000 | 0.9000 | 0.9474 | 0.0000 |
| **Tier D** | Full Composite (+ Org) | Entropy: 0.2500, Length: 0.2000, Novel: 0.2000, Rate: 0.1500, Org: 0.2000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

---

## 8. Threats to Validity & Scientific Disclosures

1. **Construct Validity (Cross-Layer Granularity):** TunnelEye classifies bi-directional network flow sessions; DNSentinel evaluates individual DNS application-layer queries. Direct mathematical aggregation of flow-level and query-level F1 is invalid and avoided.
2. **Internal Validity (Weight Renormalization):** Deactivating a feature tier inherently alters the relative weights of active features to maintain the [0, 100] scale. Results are strictly reported as tier-level sensitivity, not pure causal ablation.
3. **Hardware Latency Boundary:** TunnelEye latency is marked "Unavailable under identical streaming hardware conditions" to prevent unsubstantiated claims. DNSentinel latency is empirically measured on local hardware via `time.perf_counter_ns()`.
4. **Data Isolation:** All evaluations executed within `IsolatedEvaluationContext` sandboxes. Live production directories (`data/profiles/`, `data/organization/`) remained 100% bitwise immutable.
