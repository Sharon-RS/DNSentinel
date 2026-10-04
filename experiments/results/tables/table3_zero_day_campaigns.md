# Table 3: Zero-Day Campaign Detection Recall (Final Held-Out Test Set)

**Evaluation Protocol:** Architecture 1 Frozen Protocol; 0.0% campaign overlap during training/calibration.  
**Source Result Artifact:** `experiments/results/ml_evaluation_metrics.json` & `ml_evaluation_summary.csv`.  
**Operating Thresholds (Calibrated on Validation at $\text{FPR} \le 5.0\%$):**
- Behavioral-Only Baseline: $\text{Score} \ge 62.00$
- ML30 Classifier: $P \ge 0.1850$
- ML31 Classifier: $P \ge 0.1500$
- Hybrid Fusion: $\text{Score} \ge 20.50$ ($\beta = 0.05$)
- Tiered Cascade: $S_{\text{low}}=20.0, S_{\text{high}}=70.0, P_{\text{cascade}}=0.2000$

| Held-Out Attack Campaign | Threat Archetype & Encoding | Test Queries ($N$) | Behavioral Baseline Recall | ML30 Recall (30 Features) | ML31 Recall (31 Features) | Hybrid Recall ($\beta=0.05$) | Tiered Cascade Recall | Campaign Isolation Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `campaign_c2_stealth_gamma` | Low-and-Slow Command & Control Beacons (Sub-threshold rate, long intervals) | 166 | **100.00%** (166 / 166) | **100.00%** (166 / 166) | **100.00%** (166 / 166) | **100.00%** (166 / 166) | **100.00%** (166 / 166) | Disjoint Campaign (Starts $t=1478.6\text{s}$) |
| `campaign_tunnel_base64_zeta` | Encrypted High-Entropy Base64 Tunnel Payload Labels | 250 | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | Strictly Held Out (Zero Training Overlap) |
| `campaign_tunnel_random_theta` | High-Rate Random Character Tunnel Bursts (10–25 QPS) | 250 | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | Strictly Held Out (Zero Training Overlap) |
| `campaign_exfil_chunk_iota` | Staged Data Exfiltration via Chunked Structured Subdomains | 250 | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | **100.00%** (250 / 250) | Strictly Held Out (Zero Training Overlap) |
| **Aggregate Zero-Day Performance** | **All 4 Unseen Attack Archetypes Combined** | **916** | **100.00%** (916 / 916) | **100.00%** (916 / 916) | **100.00%** (916 / 916) | **100.00%** (916 / 916) | **100.00%** (916 / 916) | **Zero Campaign Leakage Verified** |
| **Held-Out Ambient Benign FPR** | Authentic Enterprise Session 5 Background Traffic | **798** | **1.75%** (14 / 798 FP) | **0.00%** (0 / 798 FP) | **0.13%** (1 / 798 FP) | **0.00%** (0 / 798 FP) | **0.00%** (0 / 798 FP) | Temporal Test Partition ($t \ge 25200\text{s}$) |
