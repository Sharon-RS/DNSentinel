"""
DNSentinel Phase 9A: Runtime ML Cascade Detection Pipeline.

Wraps ColdStartMitigatedPipeline (Pipeline B) to incorporate the frozen ML30
RandomForest classifier in a tiered cascade architecture:
  - S < 20.0: FAST-PATH BENIGN (ML bypassed, <15µs execution)
  - S >= 70.0: FAST-PATH MALICIOUS (ML bypassed, immediate alert)
  - 20.0 <= S < 70.0: ESCALATED ML (constructs 30-dim causal feature vector,
    evaluates P_ML >= 0.2000 -> MALICIOUS, else BENIGN)

Preserves Pipeline B calibration buffer, organization fallback, batch gating,
and baseline update protection. ML classification is strictly read-only.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from src.utils.config import Config
from src.utils.domain import extract_registrable_domain
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_calculator import DeviationCalculator
from src.pipeline.cold_start_pipeline import ColdStartMitigatedPipeline


@dataclass
class TaintRecord:
    registrable_domain: str
    host: str
    first_detected_ts: float
    last_detected_ts: float
    last_query_index: int
    source_query_index: int
    source_domain: str


class CascadeDetectionPipeline(ColdStartMitigatedPipeline):
    """
    Tiered ML Cascade Detection Pipeline integrating frozen ML30 RandomForest
    on top of the cold-start mitigated adaptive baseline engine.
    """

    FEATURE_NAMES: List[str] = [
        # Group A: Lexical Features
        "lex_domain_length",
        "lex_subdomain_length",
        "lex_subdomain_ratio",
        "lex_label_count",
        "lex_entropy",
        "lex_digit_ratio",
        "lex_alphabet_ratio",
        "lex_special_ratio",
        "lex_packet_size",
        "proto_query_type",
        # Group B: Temporal & Dynamic Window Features
        "temp_inter_arrival_time",
        "temp_query_rate",
        "temp_window_duration",
        "temp_entropy_trend",
        "temp_length_trend",
        "temp_unique_ratio",
        # Group C: Host Behavioral Deviation Features (Queries 1..k-1)
        "host_total_queries",
        "host_average_entropy",
        "host_average_domain_length",
        "host_entropy_deviation",
        "host_length_deviation",
        "host_query_rate_deviation",
        "host_novel_domain",
        # Group D: Organizational Behavioral Features (Queries 1..k-1)
        "org_total_queries",
        "org_domain_frequency",
        "org_rarity_score",
        "org_average_entropy",
        "org_average_domain_length",
        "org_entropy_deviation",
        "org_length_deviation",
    ]

    FAST_PATH_LOW: float = 20.0
    FAST_PATH_HIGH: float = 70.0
    CASCADE_THRESHOLD: float = 0.2000

    def __init__(
        self,
        data_dir=None,
        calibration_queries: Optional[int] = None,
        min_org_observations: Optional[int] = None,
        max_entropy: Optional[float] = None,
        max_length: Optional[int] = None,
        model_path: Optional[Path] = None,
        enable_ml: bool = True,
        enable_burst_taint: bool = False,
        taint_ttl_seconds: float = 60.0,
        taint_max_query_gap: int = 20,
    ):
        super().__init__(
            data_dir=data_dir,
            calibration_queries=calibration_queries,
            min_org_observations=min_org_observations,
            max_entropy=max_entropy,
            max_length=max_length,
        )

        self.last_query_timestamps: Dict[str, float] = {}
        self.enable_ml = enable_ml
        self.enable_burst_taint = enable_burst_taint
        self.taint_ttl_seconds = taint_ttl_seconds
        self.taint_max_query_gap = taint_max_query_gap
        # Host-isolated burst-taint tracking: host -> {registrable_parent_domain: TaintRecord}
        self.taint_state: Dict[str, Dict[str, TaintRecord]] = {}

        # Resolve ML30 model path relative to project root (never hardcoded absolute)
        if model_path is None:
            resolved_path = (
                Config.PROJECT_ROOT
                / "experiments"
                / "results"
                / "ml_models"
                / "ml30_random_forest.joblib"
            )
        else:
            resolved_path = Path(model_path)

        if not resolved_path.exists():
            raise FileNotFoundError(f"ML30 model artifact not found at {resolved_path}")

        artifact = joblib.load(resolved_path)
        if isinstance(artifact, dict) and "model" in artifact:
            self.model = artifact["model"]
            self.feature_names = artifact.get("feature_names", self.FEATURE_NAMES[:30])
        else:
            self.model = artifact
            self.feature_names = self.FEATURE_NAMES[:30]

        # Verify model constraints
        self.n_features_in_ = getattr(self.model, "n_features_in_", len(self.feature_names))
        self.n_estimators = getattr(self.model, "n_estimators", 100)
        self.n_jobs = getattr(self.model, "n_jobs", 1)

        if self.n_features_in_ != 30:
            raise ValueError(f"Expected n_features_in_ == 30, got {self.n_features_in_}")
        if self.n_estimators != 100:
            raise ValueError(f"Expected n_estimators == 100, got {self.n_estimators}")
        if self.n_jobs != 1:
            raise ValueError(f"Expected n_jobs == 1, got {self.n_jobs}")

    @staticmethod
    def _extract_timestamp(ts_val: Any) -> float:
        """Safely parses timestamp from float, int, ISO string, or defaults to time.time()."""
        if ts_val is None:
            return time.time()
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                return datetime.fromisoformat(ts_val).timestamp()
            except Exception:
                try:
                    return float(ts_val)
                except Exception:
                    return time.time()
        return time.time()

    def build_feature_vector(
        self,
        host: str,
        domain: str,
        features: Dict[str, Any],
        snapshot: BehaviorSnapshot,
        window_statistics: Dict[str, Any],
        inter_arrival_time: float,
    ) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Constructs the exact 30-dimensional causal feature vector in canonical ordering.
        All values are float64, unnormalized, without any future information.
        """
        # --- Group A: Lexical Features ---
        dlen = int(features.get("domain_length", len(domain)))
        if "subdomain_length" in features:
            sublen = int(features["subdomain_length"])
        else:
            labels = domain.split(".")
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
            sublen = len(subdomain)

        sub_ratio = round(sublen / dlen, 4) if dlen > 0 else 0.0
        label_cnt = int(features.get("label_count", len(domain.split("."))))
        ent = float(features.get("entropy", 0.0))
        digit_rat = float(features.get("digit_ratio", 0.0))
        alpha_rat = float(features.get("alphabet_ratio", 0.0))

        if "special_character_ratio" in features:
            spec_rat = float(features["special_character_ratio"])
        elif "special_ratio" in features:
            spec_rat = float(features["special_ratio"])
        else:
            spec_rat = round(sum(not c.isalnum() for c in domain) / len(domain), 4) if domain else 0.0

        pkt_size = int(features.get("packet_size", 0))
        q_type = int(features.get("query_type", 1))

        # --- Group B: Temporal & Dynamic Window Features ---
        w_size = max(1, window_statistics.get("window_size", 1))
        unique_doms = window_statistics.get("unique_domains", 1)

        t_arr = round(float(inter_arrival_time), 4)
        t_rate = round(float(window_statistics.get("query_rate", 0.0)), 4)
        t_dur = round(float(window_statistics.get("window_duration", 0.0)), 4)
        t_ent_tr = round(float(window_statistics.get("entropy_trend", 0.0)), 4)
        t_len_tr = round(float(window_statistics.get("length_trend", 0.0)), 4)
        t_uniq_rat = round(float(unique_doms / w_size), 4)

        # --- Group C: Host Behavioral Deviation Features (Queries 1..k-1) ---
        h_prof = snapshot.host_profile or {}
        h_tot = float(h_prof.get("total_queries", 0))
        h_avg_ent = float(h_prof.get("average_entropy", 0.0))
        h_avg_len = float(h_prof.get("average_domain_length", 0.0))
        h_ent_dev = float(DeviationCalculator.entropy(snapshot))
        h_len_dev = float(DeviationCalculator.domain_length(snapshot))
        h_rate_dev = float(DeviationCalculator.query_rate(snapshot))
        h_novel = float(DeviationCalculator.novel_domain(snapshot))

        # --- Group D: Organizational Behavioral Features (Queries 1..k-1) ---
        o_prof = snapshot.organization_profile or {}
        o_tot = float(o_prof.get("total_queries", 0))
        o_dom_freq = float(o_prof.get("domain_frequency", {}).get(domain, 0))
        o_rarity = float(DeviationCalculator.organization_rarity(snapshot))
        o_avg_ent = float(o_prof.get("average_entropy", 0.0))
        o_avg_len = float(o_prof.get("average_domain_length", 0.0))
        o_ent_dev = float(DeviationCalculator.entropy_with_fallback(snapshot))
        o_len_dev = float(DeviationCalculator.domain_length_with_fallback(snapshot))

        # Canonical 30-feature vector ordering
        feature_values = [
            float(dlen),
            float(sublen),
            float(sub_ratio),
            float(label_cnt),
            float(ent),
            float(digit_rat),
            float(alpha_rat),
            float(spec_rat),
            float(pkt_size),
            float(q_type),
            float(t_arr),
            float(t_rate),
            float(t_dur),
            float(t_ent_tr),
            float(t_len_tr),
            float(t_uniq_rat),
            float(h_tot),
            float(h_avg_ent),
            float(h_avg_len),
            float(h_ent_dev),
            float(h_len_dev),
            float(h_rate_dev),
            float(h_novel),
            float(o_tot),
            float(o_dom_freq),
            float(o_rarity),
            float(o_avg_ent),
            float(o_avg_len),
            float(o_ent_dev),
            float(o_len_dev),
        ]

        X = np.array(feature_values, dtype=np.float64).reshape(1, 30)
        feature_dict = {name: val for name, val in zip(self.FEATURE_NAMES, feature_values)}
        return X, feature_dict

    def process(self, host: str, domain: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single incoming DNS observation through the Tiered Cascade:
        1. Tracks session query count k and cold-start lifecycle state.
        2. Measures host inter-arrival time causally.
        3. Updates sliding window context and evaluates behavioral deviations.
        4. Calculates heuristic score S.
        5. Executes cascade decision:
           - S < 20.0: FAST-PATH BENIGN (ML bypassed)
           - S >= 70.0: FAST-PATH MALICIOUS (ML bypassed, baseline update blocked)
           - 20.0 <= S < 70.0: ML ESCALATED (P_ML >= 0.2000 -> MALICIOUS, else BENIGN)
        6. Applies Pipeline B provisional buffering and baseline update gating.
        """
        # 1. Track observed query index for this host session
        self.observed_query_counts[host] += 1
        k = self.observed_query_counts[host]

        is_in_calibration = (k <= self.calibration_queries)
        lifecycle_state = "COLD_START_CALIBRATION" if is_in_calibration else "STEADY_STATE"

        # Inter-arrival time tracking (strictly causal)
        current_ts = self._extract_timestamp(features.get("timestamp"))
        last_ts = self.last_query_timestamps.get(host)
        inter_arrival_time = max(0.0, current_ts - last_ts) if last_ts is not None else 0.0
        self.last_query_timestamps[host] = current_ts

        # Check active parent-domain burst taint (host-isolated, registrable domain match)
        parent_domain = extract_registrable_domain(domain)
        is_tainted, taint_record = (
            self._check_taint(host, parent_domain, current_ts, k)
            if self.enable_burst_taint
            else (False, None)
        )

        # 2. Load CURRENT persistent baselines (queries 1..k-1)
        host_profile = self.host_profile.load(host).to_dict()
        organization_profile = self.organization_profile.load()

        # 3. Update sliding window
        self.window.update(host, domain, features)
        window_statistics = self.window.get_statistics(host)

        # 4. Build behavioral snapshot
        snapshot = BehaviorSnapshot(
            host=host,
            domain=domain,
            packet_features=features,
            host_profile=host_profile,
            organization_profile=organization_profile,
            window_statistics=window_statistics,
        )

        # 5. Calculate behavioral deviation (with org fallback on cold host)
        behavior_result = self.deviation_engine.calculate(snapshot)

        # 6. Evaluate heuristic risk
        risk_result = self.risk_engine.evaluate(behavior_result)
        score = float(behavior_result.get("behavior_score", 0.0))

        # 7. Tiered Cascade Evaluation
        if not self.enable_ml:
            cascade_path = None
            cascade_decision = (
                "MALICIOUS"
                if risk_result["risk_level"] in ("SUSPICIOUS", "HIGH_RISK")
                else "BENIGN"
            )
            ml_prob = None
            ml_enabled = False
        elif score < self.FAST_PATH_LOW:
            cascade_path = "FAST_PATH_BENIGN"
            cascade_decision = "BENIGN"
            ml_prob = None
            ml_enabled = True
        elif score >= self.FAST_PATH_HIGH:
            cascade_path = "FAST_PATH_MALICIOUS"
            cascade_decision = "MALICIOUS"
            ml_prob = None
            ml_enabled = True
            risk_result["risk_level"] = "HIGH_RISK"
            risk_result["confidence"] = max(risk_result.get("confidence", 0.95), 0.95)
            risk_result["recommendation"] = (
                "Potential DNS tunneling detected. Immediate investigation recommended."
            )
        else:
            # 20.0 <= S < 70.0: Escalated ML Path
            cascade_path = "ML_ESCALATED"
            ml_enabled = True
            X, _ = self.build_feature_vector(
                host=host,
                domain=domain,
                features=features,
                snapshot=snapshot,
                window_statistics=window_statistics,
                inter_arrival_time=inter_arrival_time,
            )
            probs = np.asarray(self.model.predict_proba(X))
            p_ml = float(probs[0, 1] if probs.shape[1] > 1 else probs[0, 0])
            ml_prob = round(p_ml, 4)

            if p_ml >= self.CASCADE_THRESHOLD:
                cascade_decision = "MALICIOUS"
                risk_result["risk_level"] = "HIGH_RISK"
                risk_result["confidence"] = round(float(p_ml), 4)
                risk_result["recommendation"] = (
                    "Potential DNS tunneling detected by ML cascade. Immediate investigation recommended."
                )
            else:
                cascade_decision = "BENIGN"
                # Observation cleared by ML; preserved risk_level allows Pipeline B baseline gating

        # 7b. Burst-Taint Propagation Evaluation (if enabled)
        detection_source = (
            "DIRECT_FAST_PATH"
            if cascade_path == "FAST_PATH_MALICIOUS"
            else (
                "DIRECT_ML"
                if cascade_decision == "MALICIOUS"
                else (
                    "FAST_PATH_BENIGN"
                    if cascade_path == "FAST_PATH_BENIGN"
                    else "DIRECT_CLEAR"
                )
            )
        )
        taint_propagated = False

        if self.enable_burst_taint:
            if cascade_decision == "MALICIOUS":
                # Confirmed attack establishes or refreshes taint for this host and registrable domain
                self._register_taint(host, parent_domain, current_ts, k, domain)
            elif is_tainted and taint_record is not None:
                # Direct evaluation was non-malicious, but active burst-taint exists for this parent domain
                cascade_decision = "MALICIOUS"
                risk_result["risk_level"] = "HIGH_RISK"
                cascade_path = "TAINT_PROPAGATED"
                detection_source = "TAINT_PROPAGATED"
                taint_propagated = True
                risk_result["confidence"] = max(risk_result.get("confidence", 0.85), 0.90)
                risk_result["recommendation"] = (
                    "Potential DNS tunneling detected via parent-domain burst-taint propagation. Immediate investigation recommended."
                )
                risk_result["taint_parent_domain"] = parent_domain
                risk_result["taint_inherited_from"] = taint_record.source_query_index
                risk_result["taint_source_domain"] = taint_record.source_domain
                self._refresh_taint(host, parent_domain, current_ts, k)

        # Attach cascade and cold-start metadata to result
        risk_result["ml_enabled"] = ml_enabled
        risk_result["ml_probability"] = ml_prob
        risk_result["cascade_path"] = cascade_path
        risk_result["cascade_decision"] = cascade_decision
        risk_result["detection_source"] = detection_source
        risk_result["taint_propagated"] = taint_propagated

        risk_result["query_index"] = k
        risk_result["lifecycle_state"] = lifecycle_state
        risk_result["entropy_deviation"] = behavior_result["entropy_deviation"]
        risk_result["domain_length_deviation"] = behavior_result["domain_length_deviation"]
        risk_result["query_rate_deviation"] = behavior_result["query_rate_deviation"]
        risk_result["novel_domain_score"] = behavior_result["novel_domain_score"]
        risk_result["organization_rarity_score"] = behavior_result["organization_rarity_score"]
        risk_result["behavior_score"] = behavior_result["behavior_score"]

        # 8. Baseline Update & Cold-Start Quarantine Logic
        if is_in_calibration:
            self.provisional_buffers.setdefault(host, []).append({
                "domain": domain,
                "features": features,
                "risk_result": risk_result,
                "k": k,
            })
            risk_result["baseline_updated"] = False
            risk_result["provisional_held"] = True

            if k == self.calibration_queries:
                self._evaluate_calibration_batch(host)
        else:
            if host in self.quarantined_hosts:
                risk_result["baseline_updated"] = False
                risk_result["calibration_quarantined"] = True
            else:
                if cascade_decision == "BENIGN" and risk_result["risk_level"] in ("NORMAL", "LOW_RISK"):
                    self.host_profile.update(host, domain, features)
                    self.organization_profile.update(host, domain, features)
                    risk_result["baseline_updated"] = True
                else:
                    risk_result["baseline_updated"] = False

        return risk_result

    def _evaluate_calibration_batch(self, host: str):
        """
        Evaluates the provisional calibration buffer at query 10.
        All-or-nothing gating:
        - Rejects and quarantines if ANY query was flagged MALICIOUS by ML or Fast-Path.
        - Rejects and quarantines if ANY observation failed Pipeline B criteria.
        - Commits all queries chronologically only if every single observation passed.
        """
        buffer = self.provisional_buffers.get(host, [])
        if not buffer:
            return

        batch_failed = False
        for item in buffer:
            res = item["risk_result"]
            feats = item["features"]

            # Criterion 0: Cascade decision flagged malicious
            if res.get("cascade_decision") == "MALICIOUS":
                batch_failed = True
                break

            # Criterion 1: Elevated risk level
            if res.get("risk_level") in ("SUSPICIOUS", "HIGH_RISK"):
                batch_failed = True
                break

            # Criterion 2: Query-rate burst above baseline
            if res.get("query_rate_deviation", 0.0) > 0.0:
                batch_failed = True
                break

            # Criterion 3: Individual packet entropy exceeds calibration ceiling
            if float(feats.get("entropy", 0.0)) > self.max_entropy:
                batch_failed = True
                break

            # Criterion 4: Domain length exceeds calibration ceiling
            if int(feats.get("domain_length", 0)) > self.max_length:
                batch_failed = True
                break

        if batch_failed:
            self.quarantined_hosts.add(host)
            self.provisional_buffers[host] = []
        else:
            for item in buffer:
                self.host_profile.update(host, item["domain"], item["features"])
                self.organization_profile.update(host, item["domain"], item["features"])
            self.provisional_buffers[host] = []

    def reset_taint(self, host: Optional[str] = None):
        """
        Resets burst-taint state. If host is specified, resets only that host;
        otherwise resets all hosts.
        """
        if host is not None:
            self.taint_state.pop(host, None)
        else:
            self.taint_state.clear()

    def _check_taint(
        self,
        host: str,
        parent_domain: Optional[str],
        current_ts: float,
        current_k: int
    ) -> Tuple[bool, Optional[TaintRecord]]:
        """
        Checks if active, non-expired taint exists for (host, parent_domain).
        Guarantees:
        - Host isolation: cannot access taint from other hosts.
        - Domain isolation: exact match on registrable parent domain.
        - Expiry by time (taint_ttl_seconds) and query gap (taint_max_query_gap).
        """
        if not parent_domain or host not in self.taint_state:
            return False, None

        host_records = self.taint_state[host]
        record = host_records.get(parent_domain)
        if record is None:
            return False, None

        # Expiry check by timestamp
        if (current_ts - record.last_detected_ts) > self.taint_ttl_seconds:
            host_records.pop(parent_domain, None)
            return False, None

        # Expiry check by query index gap
        if (current_k - record.last_query_index) > self.taint_max_query_gap:
            host_records.pop(parent_domain, None)
            return False, None

        return True, record

    def _register_taint(
        self,
        host: str,
        parent_domain: Optional[str],
        current_ts: float,
        current_k: int,
        source_domain: str
    ):
        """
        Registers or updates active taint after a confirmed malicious decision.
        """
        if not parent_domain:
            return

        host_records = self.taint_state.setdefault(host, {})
        if parent_domain in host_records:
            rec = host_records[parent_domain]
            rec.last_detected_ts = current_ts
            rec.last_query_index = current_k
        else:
            host_records[parent_domain] = TaintRecord(
                registrable_domain=parent_domain,
                host=host,
                first_detected_ts=current_ts,
                last_detected_ts=current_ts,
                last_query_index=current_k,
                source_query_index=current_k,
                source_domain=source_domain,
            )

    def _refresh_taint(
        self,
        host: str,
        parent_domain: Optional[str],
        current_ts: float,
        current_k: int
    ):
        """
        Extends active taint timer upon taint propagation.
        """
        if not parent_domain or host not in self.taint_state:
            return
        rec = self.taint_state[host].get(parent_domain)
        if rec:
            rec.last_detected_ts = current_ts
            rec.last_query_index = current_k


class BurstTaintCascadePipeline(CascadeDetectionPipeline):
    """
    Research prototype extending CascadeDetectionPipeline with parent-domain
    burst-taint propagation.
    Propagates suspicion to subsequent queries under the same registrable parent domain
    from the same host following a confirmed attack.
    """

    def __init__(
        self,
        data_dir=None,
        calibration_queries: Optional[int] = None,
        min_org_observations: Optional[int] = None,
        max_entropy: Optional[float] = None,
        max_length: Optional[int] = None,
        model_path: Optional[Path] = None,
        enable_ml: bool = True,
        enable_burst_taint: bool = True,
        taint_ttl_seconds: float = 60.0,
        taint_max_query_gap: int = 20,
    ):
        super().__init__(
            data_dir=data_dir,
            calibration_queries=calibration_queries,
            min_org_observations=min_org_observations,
            max_entropy=max_entropy,
            max_length=max_length,
            model_path=model_path,
            enable_ml=enable_ml,
            enable_burst_taint=enable_burst_taint,
            taint_ttl_seconds=taint_ttl_seconds,
            taint_max_query_gap=taint_max_query_gap,
        )
