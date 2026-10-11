"""
DNSentinel Dashboard Adapter
Provides read-only telemetry bridge, state aggregation, and demo replay orchestration
without modifying production detection logic or mutating live persistent baselines.
"""

import csv
import json
import math
import os
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from src.utils.config import Config
from src.features.traditional_features import TraditionalFeatureExtractor
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cold_start_pipeline import ColdStartMitigatedPipeline
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline
from experiments.context import IsolatedEvaluationContext


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Validates ASCII DNS hostname syntax conservatively according to RFC 1034 / 1035 / 1123.
    Rejects malformed DNS names, whitespace inside the domain, shell/terminal text, URL schemes,
    paths, empty labels, labels longer than 63 characters, and total names longer than 253 characters.
    Returns (True, None) if valid, or (False, error_message) if invalid.
    """
    if domain is None or not isinstance(domain, str):
        return False, "Domain must be a string"

    if "\n" in domain or "\r" in domain or "\t" in domain:
        return False, "Domain cannot contain newlines, carriage returns, or tabs"

    clean = domain.strip()
    if not clean:
        return False, "Domain cannot be empty"

    if any(c.isspace() for c in clean):
        return False, "Domain cannot contain whitespace"

    if "://" in clean or "/" in clean or "\\" in clean:
        return False, "Domain cannot contain URL schemes or paths"

    if ":" in clean:
        return False, "Domain cannot contain port specifications or colons"

    if clean.endswith("."):
        clean = clean[:-1]

    if not clean:
        return False, "Domain cannot be empty"

    if len(clean) > 253:
        return False, f"Domain name exceeds maximum length of 253 characters (got {len(clean)})"

    try:
        clean.encode("ascii")
    except UnicodeEncodeError:
        return False, "Domain must contain only ASCII characters"

    labels = clean.split(".")
    if len(labels) < 2:
        return False, "Domain must contain at least two labels (e.g., example.com)"

    for label in labels:
        if len(label) == 0:
            return False, "Domain cannot contain empty labels"
        if len(label) > 63:
            return False, f"Domain label exceeds maximum length of 63 characters (got {len(label)})"
        if label.startswith("-"):
            return False, f"Domain label '{label}' cannot start with a hyphen"
        if label.endswith("-"):
            return False, f"Domain label '{label}' cannot end with a hyphen"
        if not all(c.isalnum() or c == "-" for c in label):
            return False, f"Domain label '{label}' contains invalid characters (must contain only letters, digits, and hyphens)"

    if labels[-1].isdigit():
        return False, "Top-level domain cannot be all-numeric"

    return True, None


class DashboardAdapter:
    """
    Thread-safe adapter connecting the existing DNSentinel detection pipeline,
    persistent host profiles, and Phase 4 research results to the web dashboard.
    """

    MAX_RING_BUFFER = 300

    def __init__(self):
        self._lock = threading.Lock()
        self.ring_buffer: List[Dict[str, Any]] = []
        self.alerts_buffer: List[Dict[str, Any]] = []
        self.total_queries_count = 0
        self.risk_counts = {
            "NORMAL": 0,
            "LOW_RISK": 0,
            "SUSPICIOUS": 0,
            "HIGH_RISK": 0
        }
        self.is_demo_replay = False
        self.replay_mode: str = ""
        self.pipeline_mode: str = "heuristic"
        self.last_query_timestamp: Optional[str] = None
        self.extractor = TraditionalFeatureExtractor()
        self.event_id_counter = 0

    def set_pipeline_mode(self, mode: str) -> str:
        """Sets the active detection engine mode ('heuristic' or 'cascade')."""
        if mode in ("heuristic", "cascade"):
            self.pipeline_mode = mode
        return self.pipeline_mode

    def get_pipeline_mode(self) -> str:
        """Returns the active detection engine mode."""
        return self.pipeline_mode

    # ------------------------------------------------------------------
    # Telemetry Ingestion & Ring Buffer
    # ------------------------------------------------------------------

    def ingest_processed_event(
        self,
        event: Dict[str, Any],
        features: Dict[str, Any],
        result: Dict[str, Any],
        is_replay: bool = False,
        replay_mode: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Records a processed DNS detection event into the in-memory ring buffer.
        """
        with self._lock:
            self.event_id_counter += 1
            record = {
                "id": self.event_id_counter,
                "timestamp": event.get("timestamp") or datetime.now().isoformat(),
                "host": event.get("source_ip", "0.0.0.0"),
                "destination_ip": event.get("destination_ip", "0.0.0.0"),
                "domain": event.get("domain", ""),
                "query_type": event.get("query_type", 1),
                "query_type_name": self._query_type_to_name(event.get("query_type", 1)),
                "packet_size": event.get("packet_size", 0),
                "entropy": round(float(features.get("entropy", 0.0)), 4),
                "domain_length": int(features.get("domain_length", len(event.get("domain", "")))),
                "digit_ratio": round(float(features.get("digit_ratio", 0.0)), 4),
                "query_rate": round(float(features.get("query_rate", 0.0)), 2),
                # Behavioral deviation breakdown
                "entropy_deviation": round(float(result.get("entropy_deviation", 0.0)), 4),
                "domain_length_deviation": round(float(result.get("domain_length_deviation", 0.0)), 4),
                "query_rate_deviation": round(float(result.get("query_rate_deviation", 0.0)), 4),
                "novel_domain_score": round(float(result.get("novel_domain_score", 0.0)), 4),
                "organization_rarity_score": round(float(result.get("organization_rarity_score", 0.0)), 4),
                "behavior_score": round(float(result.get("behavior_score", 0.0)), 2),
                "risk_level": result.get("risk_level", "NORMAL"),
                "confidence": round(float(result.get("confidence", 0.90)), 2),
                "recommendation": result.get("recommendation", "No immediate action required."),
                "baseline_updated": bool(result.get("baseline_updated", False)),
                "provisional_held": bool(result.get("provisional_held", False) or result.get("lifecycle_state") == "COLD_START_CALIBRATION"),
                "calibration_quarantined": bool(result.get("calibration_quarantined", False) or result.get("quarantined", False)),
                "quarantined": bool(result.get("calibration_quarantined", False) or result.get("quarantined", False)),
                "baseline_status": str(result["baseline_status"]) if result.get("baseline_status") else (
                    "Learned" if bool(result.get("baseline_updated", False)) else (
                        "Quarantined" if bool(result.get("calibration_quarantined", False) or result.get("quarantined", False)) else (
                            "Calibrating" if bool(result.get("provisional_held", False) or result.get("lifecycle_state") == "COLD_START_CALIBRATION") else "Not Updated"
                        )
                    )
                ),
                # Tiered Cascade ML telemetry
                "ml_enabled": bool(result.get("ml_enabled", False)),
                "ml_probability": (
                    round(float(result["ml_probability"]), 4)
                    if (
                        result.get("ml_probability") is not None
                        and isinstance(result.get("ml_probability"), (int, float))
                        and math.isfinite(float(result["ml_probability"]))
                    )
                    else (
                        round(float(result["ml_probability"]), 4)
                        if (
                            result.get("ml_probability") is not None
                            and isinstance(result.get("ml_probability"), str)
                            and result.get("ml_probability").replace(".", "", 1).isdigit()
                        )
                        else None
                    )
                ),
                "cascade_path": result.get("cascade_path"),
                "cascade_decision": result.get("cascade_decision"),
                "is_replay": is_replay
            }

            self.ring_buffer.append(record)
            if len(self.ring_buffer) > self.MAX_RING_BUFFER:
                self.ring_buffer.pop(0)

            # Update metrics summary
            self.total_queries_count += 1
            risk_level = record["risk_level"]
            if risk_level in self.risk_counts:
                self.risk_counts[risk_level] += 1

            self.last_query_timestamp = record["timestamp"]
            if is_replay:
                self.is_demo_replay = True
                if replay_mode:
                    self.replay_mode = replay_mode

            # If suspicious or high risk, add to alerts buffer
            if risk_level in ("SUSPICIOUS", "HIGH_RISK"):
                self.alerts_buffer.append(record)
                if len(self.alerts_buffer) > 100:
                    self.alerts_buffer.pop(0)

            return record

    def clear_session(self):
        """Clears in-memory session history without modifying persistent disk state."""
        with self._lock:
            self.ring_buffer.clear()
            self.alerts_buffer.clear()
            self.total_queries_count = 0
            self.risk_counts = {k: 0 for k in self.risk_counts}
            self.is_demo_replay = False
            self.replay_mode = ""
            self.last_query_timestamp = None

    # ------------------------------------------------------------------
    # Data Getters (Thread-Safe Views)
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """Returns risk distribution and live summary metrics."""
        with self._lock:
            hosts = self.get_monitored_hosts_list()
            return {
                "total_queries": self.total_queries_count,
                "normal_count": self.risk_counts["NORMAL"],
                "low_risk_count": self.risk_counts["LOW_RISK"],
                "suspicious_count": self.risk_counts["SUSPICIOUS"],
                "high_risk_count": self.risk_counts["HIGH_RISK"],
                "monitored_hosts_count": len(hosts),
                "is_demo_replay": self.is_demo_replay,
                "replay_mode": self.replay_mode,
                "last_query_timestamp": self.last_query_timestamp,
                "buffer_size": len(self.ring_buffer)
            }

    def get_live_events(self, limit: int = 50, since_id: int = 0) -> List[Dict[str, Any]]:
        """Returns recent events from the ring buffer."""
        with self._lock:
            if since_id > 0:
                events = [e for e in self.ring_buffer if e["id"] > since_id]
            else:
                events = self.ring_buffer[-limit:]
            return list(reversed(events))

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns security alerts (SUSPICIOUS and HIGH_RISK events)."""
        with self._lock:
            return list(reversed(self.alerts_buffer[-limit:]))

    # ------------------------------------------------------------------
    # Host Profiles & Organization Baselines (Read-Only)
    # ------------------------------------------------------------------

    def get_monitored_hosts_list(self) -> List[str]:
        """Scans data/profiles/ for all registered host profiles."""
        profile_dir = Config.PROFILE_DIR
        if not profile_dir.exists():
            return []
        hosts = []
        for p in sorted(profile_dir.glob("*.json")):
            if p.is_file() and not p.name.endswith(".backup.json"):
                hosts.append(p.stem)
        return hosts

    def get_host_profile_details(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Reads a specific host baseline profile from disk."""
        profile_path = Config.PROFILE_DIR / f"{host_ip}.json"
        if not profile_path.exists():
            return None
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Format top domains
            domain_freq = data.get("domain_frequency", {})
            sorted_domains = sorted(domain_freq.items(), key=lambda x: x[1], reverse=True)[:15]
            data["top_domains"] = [{"domain": d, "count": c} for d, c in sorted_domains]
            tq = data.get("total_queries", 0)
            if tq == 0:
                data["calibration_state"] = "Unprofiled Host (k = 0)"
            elif tq <= 10:
                data["calibration_state"] = f"Cold-Start Calibration (k = {tq} / 10)"
            else:
                data["calibration_state"] = f"Graduated / Steady-State Baseline (k = {tq})"
            return data
        except Exception as e:
            return {"error": f"Failed to load profile for {host_ip}: {str(e)}"}

    def get_all_host_summaries(self) -> List[Dict[str, Any]]:
        """Returns summary cards for all monitored hosts."""
        summaries = []
        for host in self.get_monitored_hosts_list():
            details = self.get_host_profile_details(host)
            if details and "error" not in details:
                summaries.append({
                    "host": host,
                    "total_queries": details.get("total_queries", 0),
                    "calibration_state": details.get("calibration_state", "Unknown"),
                    "average_entropy": round(float(details.get("average_entropy", 0.0)), 4),
                    "average_domain_length": round(float(details.get("average_domain_length", 0.0)), 2),
                    "unique_domains_count": len(details.get("unique_domains", [])),
                    "query_types": details.get("query_type_frequency", {})
                })
        return summaries

    def get_organization_profile_details(self) -> Dict[str, Any]:
        """Reads the organization baseline from disk."""
        org_path = Config.DATA_DIR / "organization" / "organization.json"
        if not org_path.exists():
            return {"status": "uninitialized", "total_queries": 0}
        try:
            with open(org_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["status"] = "mature" if data.get("total_queries", 0) >= 20 else "calibrating"
            return data
        except Exception as e:
            return {"error": f"Failed to load organization profile: {str(e)}"}

    # ------------------------------------------------------------------
    # System Status & Detection Process Inspection
    # ------------------------------------------------------------------

    def get_system_status(self) -> Dict[str, Any]:
        """Safely inspects BIND, capture interface, and detection health."""
        # 1. Check BIND9 status
        bind_active = False
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "named"],
                capture_output=True,
                text=True,
                timeout=1
            )
            bind_active = (res.stdout.strip() == "active")
        except Exception:
            # Fallback check query.log existence
            bind_active = Path("/var/log/named/query.log").exists()

        # 2. Check if main.py is currently running
        main_running = False
        try:
            res = subprocess.run(
                ["pgrep", "-f", "python.*main.py"],
                capture_output=True,
                text=True,
                timeout=1
            )
            main_running = bool(res.stdout.strip())
        except Exception:
            main_running = False

        # 3. Check interface status
        interface_ready = Path("/sys/class/net/ens33").exists()

        # 4. Check ML model availability
        ml_models_dir = Config.PROJECT_ROOT / "experiments" / "results" / "ml_models"
        ml30_exists = (ml_models_dir / "ml30_random_forest.joblib").exists()
        ml31_exists = (ml_models_dir / "ml31_random_forest.joblib").exists()
        calibration_exists = (ml_models_dir / "calibration_config.json").exists()
        models_available = ml30_exists and ml31_exists and calibration_exists

        # 5. Cryptographic hashes from Phase 7B verified manifest
        dataset_hashes = {
            "dnsentinel_ml_benchmark.jsonl": "cbb1147ab3a241c3222c6f11529465c2e4725ec6a00aea5dc4c8df4c8286e32a",
            "dnsentinel_ml_features.jsonl": "7de0bb5a5a6b5eb7dbf335e2fcc04ab9de5db802227457c6228e7b259952e394"
        }
        model_hashes = {
            "ml30_random_forest.joblib": "0cb956069f463ef66f5de3b7f249417d67df879c91d0936eaff720628935c6e2",
            "ml31_random_forest.joblib": "208146aa46630ee026a0b8ef301aacd5a5758f3904bd151b988e8e1a41398257",
            "calibration_config.json": "69f7cbbcc66de3d3a4582ecb7a4fee7c82599216eb72244a54719e13bc034737"
        }

        return {
            "bind_service_active": bind_active,
            "main_detector_running": main_running,
            "capture_interface": "ens33",
            "interface_ready": interface_ready,
            "monitored_hosts_count": len(self.get_monitored_hosts_list()),
            "organization_initialized": (Config.DATA_DIR / "organization" / "organization.json").exists(),
            "models_available": models_available,
            "pipeline_mode": self.pipeline_mode,
            "ml30_model_ready": ml30_exists,
            "ml31_model_ready": ml31_exists,
            "calibration_ready": calibration_exists,
            "dataset_hashes": dataset_hashes,
            "model_hashes": model_hashes,
            "buffer_capacity": {
                "ring_buffer_current": len(self.ring_buffer),
                "ring_buffer_max": self.MAX_RING_BUFFER,
                "alerts_buffer_current": len(self.alerts_buffer),
                "alerts_buffer_max": 100
            },
            "is_demo_replay": self.is_demo_replay,
            "last_query_timestamp": self.last_query_timestamp,
            "timestamp": datetime.now().isoformat()
        }

    # ------------------------------------------------------------------
    # Phase 4 Research Results (Committed Artifacts Ingestion)
    # ------------------------------------------------------------------

    def get_research_results(self) -> Dict[str, Any]:
        """
        Reads already-committed Phase 4 research results directly from experiments/results/.
        Strictly preserves provenance, exact values, and boundary disclosures.
        """
        results_dir = Config.PROJECT_ROOT / "experiments" / "results"

        # 1. TunnelEye Verified Reproduction Metrics (Exact values established in project)
        tunneleye_data = {
            "system": "TunnelEye (External verified reproduction baseline)",
            "model_architecture": "LightGBM (20 Selected Flow Features, 10-Fold Stratified CV)",
            "traffic_layer": "Transport / Flow Layer (Encrypted DoH Network Flows)",
            "observation_granularity": "Bi-directional Network Flow Session Aggregate",
            "latency": "Latency unavailable under identical streaming hardware conditions",
            "notes": "External verified reproduction baseline obtained on separate dedicated Ubuntu VM. Shuffled offline flow classification.",
            "datasets": [
                {
                    "split_id": "CIC-FWD",
                    "dataset_name": "CIRA-CIC-DoHBrw-2020",
                    "direction": "Client -> Server (Forward)",
                    "accuracy": 0.9987240888,
                    "weighted_precision": 0.9987253804,
                    "weighted_recall": 0.9987240888,
                    "weighted_f1": 0.9987246946
                },
                {
                    "split_id": "CIC-BWD",
                    "dataset_name": "CIRA-CIC-DoHBrw-2020",
                    "direction": "Server -> Client (Backward)",
                    "accuracy": 0.9971739576,
                    "weighted_precision": 0.9971817769,
                    "weighted_recall": 0.9971739576,
                    "weighted_f1": 0.9971754796
                },
                {
                    "split_id": "DoH-Extended-FWD",
                    "dataset_name": "DoH-Extended",
                    "direction": "Client -> Server (Forward)",
                    "accuracy": 0.9996498212,
                    "weighted_precision": 0.9996498968,
                    "weighted_recall": 0.9996498212,
                    "weighted_f1": 0.9996498545
                },
                {
                    "split_id": "DoH-Extended-BWD",
                    "dataset_name": "DoH-Extended",
                    "direction": "Server -> Client (Backward)",
                    "accuracy": 0.9994861631,
                    "weighted_precision": 0.9994863253,
                    "weighted_recall": 0.9994861631,
                    "weighted_f1": 0.9994861512
                }
            ],
            "macro_average": {
                "aggregation_method": "Arithmetic Mean (Macro Average across the 4 verified dataset results: CIC-FWD, CIC-BWD, DoH-Extended-FWD, DoH-Extended-BWD)",
                "accuracy": 0.9987585077,
                "weighted_precision": 0.9987608449,
                "weighted_recall": 0.9987585077,
                "weighted_f1": 0.9987590450
            }
        }

        # 2. Phase 3 Cold-Start Evaluation (From cold_start_ab_summary.csv)
        cold_start_rows = []
        cold_start_csv = results_dir / "cold_start_ab_summary.csv"
        if cold_start_csv.exists():
            try:
                with open(cold_start_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        cold_start_rows.append(r)
            except Exception:
                pass

        # 3. Four-Tier Feature Sensitivity Analysis (From ablation_study.csv)
        ablation_rows = []
        ablation_csv = results_dir / "ablation_study.csv"
        if ablation_csv.exists():
            try:
                with open(ablation_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        ablation_rows.append(r)
            except Exception:
                pass

        # 4. Deterministic Static-Rule Heuristic Baseline
        static_rule_summary = {
            "rule_definition": "Alert = True iff (Entropy >= 4.0 and Domain Length >= 30) or (Query Type not in {1, 28})",
            "tunnel_burst": {
                "workload": "Historical Tunnel Burst Trace (115 queries)",
                "accuracy": 0.2783,
                "recall": 0.2783,
                "fnr": 0.7217,
                "latency_ms": 0.0004,
                "finding": "Detects high-entropy payloads but fails on handshake queries (hello.attacker.lab)"
            },
            "realistic_traffic": {
                "workload": "Combined Realistic Trace (Benign + Tunnel, 234 queries)",
                "accuracy": 0.6239,
                "precision": 0.8649,
                "recall": 0.2783,
                "fpr": 0.0420,
                "latency_ms": 0.0003,
                "finding": "Triggers false positives (4.20%) on legitimate long CDN queries without behavioral memory"
            }
        }

        # 5. Phase 6D Zero-Day Evaluation & Tiered Cascade Metrics
        ml_eval_metrics = {}
        ml_metrics_json = results_dir / "ml_evaluation_metrics.json"
        if ml_metrics_json.exists():
            try:
                with open(ml_metrics_json, "r", encoding="utf-8") as f:
                    ml_eval_metrics = json.load(f)
            except Exception:
                pass

        ml_summary_rows = []
        ml_summary_csv = results_dir / "ml_evaluation_summary.csv"
        if ml_summary_csv.exists():
            try:
                with open(ml_summary_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        ml_summary_rows.append(r)
            except Exception:
                pass

        # 6. Phase 5 Domain Graduation Sensitivity
        domain_grad_rows = []
        domain_grad_csv = results_dir / "domain_graduation_sensitivity.csv"
        if domain_grad_csv.exists():
            try:
                with open(domain_grad_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        domain_grad_rows.append(r)
            except Exception:
                pass

        # 7. Phase 7B Publication Tables Content
        tables_dir = results_dir / "tables"
        phase7b_tables = {}
        for tbl_file in ["table1_dnsentinel_vs_tunneleye.md", "table2_cold_start.md", "table3_zero_day_campaigns.md", "table4_latency_performance.md"]:
            tbl_path = tables_dir / tbl_file
            if tbl_path.exists():
                try:
                    with open(tbl_path, "r", encoding="utf-8") as f:
                        phase7b_tables[tbl_file] = f.read()
                except Exception:
                    pass

        # 8. Phase 7B Publication Figures Metadata
        phase7b_figures = [
            {
                "id": "fig1",
                "filename": "01_cold_start_baseline_drift.png",
                "title": "Figure 1: Cold-Start Baseline Drift",
                "url": "/figures/01_cold_start_baseline_drift.png",
                "caption": "Sequential rolling average entropy comparison across 115 queries for A1 Fresh Control (+4.5265 bits), A2 Mature Control (+4.5389 bits), and B Mitigated Treatment (0.0000 bits).",
                "key_takeaway": "Unmitigated controls experience severe drift (+4.54 bits); provisional gating provides complete poisoning immunity (0.0000 bits)."
            },
            {
                "id": "fig2a",
                "filename": "02_roc_curve.png",
                "title": "Figure 2A: Zero-Day ROC Curves",
                "url": "/figures/02_roc_curve.png",
                "caption": "Held-out zero-day ROC curves across 1,714 records with validation-calibrated operating points (FPR <= 5%).",
                "key_takeaway": "ROC-AUC: Behavioral 0.9981, ML30 1.0000, ML31 1.0000, Hybrid 1.0000, Cascade 1.0000."
            },
            {
                "id": "fig2b",
                "filename": "03_precision_recall_curve.png",
                "title": "Figure 2B: Zero-Day Precision-Recall Curves",
                "url": "/figures/03_precision_recall_curve.png",
                "caption": "Precision-Recall curves evaluating class imbalance (53.4% attack prevalence) with no-skill baseline.",
                "key_takeaway": "PR-AUC: Behavioral 0.9983, ML30 1.0000, ML31 1.0000, Hybrid 1.0000, Cascade 1.0000."
            },
            {
                "id": "fig3",
                "filename": "04_cascade_latency.png",
                "title": "Figure 3: Tiered Cascade Latency Architecture",
                "url": "/figures/04_cascade_latency.png",
                "caption": "Logarithmic distribution showing Fast-Path (62.49%, P50=0.21 µs, P99=1.38 µs) vs Escalated ML-Path (37.51%, P50=3608 µs, P99=5169 µs) against the 500 µs target.",
                "key_takeaway": "Fast path satisfies sub-microsecond budget; overall cascade median latency is 0.32 µs."
            },
            {
                "id": "fig4",
                "filename": "05_abdg_pareto_frontier.png",
                "title": "Figure 4: ABDG Pareto Frontier",
                "url": "/figures/05_abdg_pareto_frontier.png",
                "caption": "Scatter plot of Benign Recovery Rate vs Malicious Graduation Rate across all 37 sensitivity configurations.",
                "key_takeaway": "Operational setting (Cbase=10, PGER=0.10) achieves 92.0% BRR and 0.0% MGR."
            }
        ]

        # 9. Key Frozen Research Benchmark Metrics
        key_benchmark_metrics = {
            "behavioral": {
                "name": "Behavioral-Only Baseline",
                "recall": 100.0,
                "fpr": 1.75,
                "f1": 99.24,
                "latency_p50_us": 0.24,
                "latency_p99_us": 0.29,
                "notes": "Fast heuristic baseline (P99 < 0.3 µs), 14 false alarms on novel enterprise domains."
            },
            "ml30": {
                "name": "ML30 (30 Causal Features)",
                "recall": 100.0,
                "fpr": 0.00,
                "f1": 100.00,
                "latency_p50_us": 3742.28,
                "latency_p99_us": 4963.04,
                "notes": "Zero false alarms; single-query scikit-learn inference overhead ~3.7 ms."
            },
            "ml31": {
                "name": "ML31 (31 Features + Behavior Score)",
                "recall": 100.0,
                "fpr": 0.13,
                "f1": 99.95,
                "latency_p50_us": 3856.70,
                "latency_p99_us": 6331.24,
                "notes": "Augmented with behavior score; 1 false positive on test set."
            },
            "hybrid": {
                "name": "Hybrid Fusion (Behavioral + ML30)",
                "recall": 100.0,
                "fpr": 0.00,
                "f1": 100.00,
                "latency_p50_us": 4145.93,
                "latency_p99_us": 6928.20,
                "notes": "Validation-selected beta=0.05 score fusion; executes ML on all queries."
            },
            "cascade": {
                "name": "Tiered Cascade (Heuristic Triage + Selective ML)",
                "recall": 100.0,
                "fpr": 0.00,
                "f1": 100.00,
                "latency_p50_us": 0.32,
                "latency_p99_us": 11327.07,
                "fast_path_pct": 62.49,
                "fast_path_p50_us": 0.21,
                "fast_path_p99_us": 1.38,
                "escalated_pct": 37.51,
                "escalated_p50_us": 3608.03,
                "escalated_p99_us": 5169.26,
                "notes": "Bimodal: 62.49% exits fast path at 0.21 µs; eliminates all false alarms."
            }
        }

        # 10. Manifest summary
        manifest_text = ""
        manifest_path = results_dir / "phase7b_artifacts_manifest.md"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_text = f.read()
            except Exception:
                pass

        return {
            # Preserved Phase 4 Keys (Existing test dependencies)
            "tunneleye_baseline": tunneleye_data,
            "cold_start_ab": cold_start_rows,
            "ablation_study": ablation_rows,
            "static_rule_baseline": static_rule_summary,
            "disclaimer": "All values reflect committed Phase 4 research artifacts. DNSentinel streaming behavioral anomaly detection and TunnelEye supervised flow classification are cross-layer complementary systems with distinct granularities.",

            # Extended Phase 5, 6D, 7B Publication Results
            "key_benchmark_metrics": key_benchmark_metrics,
            "phase7b_figures": phase7b_figures,
            "phase7b_tables": phase7b_tables,
            "ml_evaluation_metrics": ml_eval_metrics,
            "ml_summary_rows": ml_summary_rows,
            "domain_graduation_rows": domain_grad_rows,
            "manifest_text": manifest_text,
            "methodological_disclaimer": "Results shown here are from controlled held-out and laboratory evaluations. They do not constitute universal production guarantees.",
            "tunneleye_boundary": "TunnelEye and DNSentinel operate at different network layers and evaluation settings; direct F1 superiority claims are not methodologically valid."
        }

    # ------------------------------------------------------------------
    # Demo Replay Engine (Isolated / Zero Mutation of Live Baselines)
    # ------------------------------------------------------------------

    def replay_dataset(self, dataset_name: str, max_records: int = 150) -> Dict[str, Any]:
        """
        Executes a Demo Replay of an existing dataset trace through the existing DetectionPipeline.
        CRITICAL: Uses an isolated temporary sandbox to guarantee that live data/profiles/ and
        data/organization/ remain 100% bitwise immutable during demonstrations.
        """
        datasets_dir = Config.PROJECT_ROOT / "experiments" / "datasets"
        org_baseline_file = datasets_dir / "enterprise_org_baseline.json"
        copy_org_baseline = False

        if dataset_name == "tunnel":
            target_file = datasets_dir / "lab_trace_tunnel_burst.jsonl"
            display_label = "Historical Tunnel Burst Trace (Pipeline A1)"
            replay_mode = "DEMO REPLAY — NOT LIVE TRAFFIC"
            pipeline_cls = DetectionPipeline
        elif dataset_name in ("tunnel_b", "tunnel_mitigated"):
            target_file = datasets_dir / "lab_trace_tunnel_burst.jsonl"
            display_label = "Historical Tunnel Burst Trace (Pipeline B)"
            replay_mode = "RESEARCH REPLAY — PIPELINE B (ENTERPRISE PRIOR)"
            pipeline_cls = ColdStartMitigatedPipeline
            copy_org_baseline = True
        elif dataset_name in ("tunnel_cascade", "tunnel_ml"):
            target_file = datasets_dir / "lab_trace_tunnel_burst.jsonl"
            display_label = "Historical Tunnel Burst Trace (Tiered ML Cascade)"
            replay_mode = "LIVE TIERED CASCADE — ML30"
            pipeline_cls = CascadeDetectionPipeline
            copy_org_baseline = True
        elif dataset_name == "benign":
            target_file = datasets_dir / "lab_trace_benign.jsonl"
            display_label = "Real Lab Benign Trace (Unmitigated Cold Start)"
            replay_mode = "RESEARCH REPLAY — UNMITIGATED COLD START"
            pipeline_cls = DetectionPipeline
        elif dataset_name in ("benign_mature", "benign_mature_org"):
            target_file = datasets_dir / "lab_trace_benign.jsonl"
            display_label = "Real Lab Benign Trace (Mature Organization)"
            replay_mode = "ADAPTIVE BASELINE DEMO — MATURE ORGANIZATION"
            pipeline_cls = DetectionPipeline
            copy_org_baseline = True
        else:
            target_file = datasets_dir / "synthetic_mixed_stream.jsonl"
            display_label = "Synthetic Mixed Stream"
            replay_mode = "DEMO REPLAY — NOT LIVE TRAFFIC"
            pipeline_cls = DetectionPipeline

        if not target_file.exists():
            return {"error": f"Dataset file not found: {target_file.name}"}

        records_processed = 0
        events_to_process = []
        with open(target_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events_to_process.append(json.loads(line))
                if len(events_to_process) >= max_records:
                    break

        # Execute inside IsolatedEvaluationContext so live profiles are NEVER modified
        with IsolatedEvaluationContext() as ctx:
            if copy_org_baseline and org_baseline_file.exists():
                dst = ctx.sandbox_path / "organization" / "organization.json"
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(org_baseline_file, dst)

            if pipeline_cls is DetectionPipeline:
                pipeline = ctx.create_pipeline()
            else:
                pipeline = pipeline_cls(data_dir=ctx.sandbox_path)

            for ev in events_to_process:
                host = ev.get("host") or ev.get("source_ip", "10.0.0.1")
                domain = ev.get("domain", "")
                features = ev.get("features", {})
                if "timestamp" not in features:
                    features["timestamp"] = ev.get("timestamp") or time.time()

                # Process through selected pipeline
                result = pipeline.process(host=host, domain=domain, features=features)

                # Format packet event for telemetry
                dns_event = {
                    "timestamp": datetime.fromtimestamp(float(features["timestamp"])).isoformat()
                    if isinstance(features["timestamp"], (int, float))
                    else str(features["timestamp"]),
                    "source_ip": host,
                    "destination_ip": "192.168.145.2",
                    "domain": domain,
                    "query_type": features.get("query_type", 1),
                    "packet_size": features.get("packet_size", 64)
                }

                # Ingest into dashboard ring buffer marked explicitly as replay
                self.ingest_processed_event(dns_event, features, result, is_replay=True, replay_mode=replay_mode)
                records_processed += 1

        return {
            "status": "success",
            "dataset": display_label,
            "records_replayed": records_processed,
            "mode": replay_mode,
            "message": f"Successfully replayed {records_processed} queries through {pipeline_cls.__name__} in isolated sandbox."
        }

    validate_domain = staticmethod(validate_domain)

    def process_test_query(self, host: str, domain: str, query_type: int = 1) -> Dict[str, Any]:
        """
        Tests an individual DNS query through the detection pipeline in a sandbox.
        Uses CascadeDetectionPipeline if pipeline_mode == 'cascade', else ColdStartMitigatedPipeline.
        Validates domain syntax before feature extraction or pipeline execution.
        """
        is_valid, error_msg = self.validate_domain(domain)
        if not is_valid:
            return {"error": error_msg or "Invalid domain name"}

        clean_host = host.strip() or "10.0.0.1"
        clean_domain = domain.strip().lower().rstrip(".")

        dummy_event = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": clean_host,
            "destination_ip": "192.168.145.2",
            "domain": clean_domain,
            "query_type": query_type,
            "packet_size": 60 + len(clean_domain)
        }

        features = self.extractor.extract(dummy_event)
        features["timestamp"] = time.time()

        org_baseline_file = Config.PROJECT_ROOT / "experiments" / "datasets" / "enterprise_org_baseline.json"

        # Run inside isolated context to prevent live baseline drift from test queries
        with IsolatedEvaluationContext() as ctx:
            if org_baseline_file.exists():
                dst = ctx.sandbox_path / "organization" / "organization.json"
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(org_baseline_file, dst)

            if self.pipeline_mode == "cascade":
                pipeline = CascadeDetectionPipeline(data_dir=ctx.sandbox_path)
                mode_str = "LIVE TIERED CASCADE — ML30"
            else:
                pipeline = ColdStartMitigatedPipeline(data_dir=ctx.sandbox_path)
                mode_str = "LIVE HEURISTIC — PIPELINE B"
            result = pipeline.process(clean_host, clean_domain, features)

        record = self.ingest_processed_event(dummy_event, features, result, is_replay=True, replay_mode=mode_str)
        return {
            "status": "success",
            "record": record,
            "mode": mode_str
        }

    # ------------------------------------------------------------------
    # Utility Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _query_type_to_name(qtype: int) -> str:
        qtype_map = {
            1: "A",
            28: "AAAA",
            16: "TXT",
            15: "MX",
            5: "CNAME",
            12: "PTR",
            2: "NS",
            6: "SOA",
            255: "ANY"
        }
        return qtype_map.get(qtype, f"TYPE_{qtype}")
