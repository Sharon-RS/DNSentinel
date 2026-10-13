"""
Phase 3 Cold-Start Mitigated Detection Pipeline.
Implements Pipeline B:
- Organization baseline fallback for cold-start hosts (when org baseline is mature).
- Strict calibration lifecycle indexing: Queries 1..10 are COLD_START_CALIBRATION, 11+ are STEADY_STATE.
- Provisional observation buffer: no persistent profile updates during calibration.
- All-or-nothing batch gating at query 10: batch commits only if every query passes criteria;
  otherwise permanently quarantines the entire batch.
- Preserves exact production RiskEngine thresholds and scoring formulas.
"""

from collections import Counter
from typing import Dict, Any, List, Optional

from src.utils.config import Config
from src.pipeline.detection_pipeline import DetectionPipeline
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_engine import ColdStartDeviationEngine


class ColdStartMitigatedPipeline(DetectionPipeline):
    """
    Subclasses DetectionPipeline to provide robust cold-start protection
    without modifying the pre-mitigation DetectionPipeline logic.
    """

    def __init__(
        self,
        data_dir=None,
        calibration_queries: Optional[int] = None,
        min_org_observations: Optional[int] = None,
        max_entropy: Optional[float] = None,
        max_length: Optional[int] = None
    ):
        super().__init__(data_dir=data_dir)

        # Configurable experimental parameters
        self.calibration_queries = (
            calibration_queries
            if calibration_queries is not None
            else getattr(Config, "COLD_START_CALIBRATION_QUERIES", 10)
        )
        self.min_org_observations = (
            min_org_observations
            if min_org_observations is not None
            else getattr(Config, "MIN_ORG_CALIBRATION_QUERIES", 20)
        )
        self.max_entropy = (
            max_entropy
            if max_entropy is not None
            else getattr(Config, "CALIBRATION_MAX_ENTROPY", 4.5)
        )
        self.max_length = (
            max_length
            if max_length is not None
            else getattr(Config, "CALIBRATION_MAX_LENGTH", 45)
        )

        # Plug in ColdStartDeviationEngine with org fallback
        self.deviation_engine = ColdStartDeviationEngine(
            min_org_observations=self.min_org_observations
        )

        # Host-level lifecycle and provisional quarantine state
        self.observed_query_counts = Counter()
        self.provisional_buffers: Dict[str, List[Dict[str, Any]]] = {}
        self.quarantined_hosts = set()

    def process(self, host: str, domain: str, features: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Track observed query index for this host session
        self.observed_query_counts[host] += 1
        k = self.observed_query_counts[host]

        # Explicit lifecycle phase definition:
        # Queries 1..10 = COLD_START_CALIBRATION; Query 11+ = STEADY_STATE
        is_in_calibration = (k <= self.calibration_queries)
        lifecycle_state = "COLD_START_CALIBRATION" if is_in_calibration else "STEADY_STATE"

        # 2. Load CURRENT persistent baselines
        host_profile = self.host_profile.load(host).to_dict()
        organization_profile = self.organization_profile.load()

        # 3. Update sliding window (temporal context is always maintained)
        self.window.update(host, domain, features)
        window_statistics = self.window.get_statistics(host)

        # 4. Build behavioral snapshot
        snapshot = BehaviorSnapshot(
            host=host,
            domain=domain,
            packet_features=features,
            host_profile=host_profile,
            organization_profile=organization_profile,
            window_statistics=window_statistics
        )

        # 5. Calculate behavioral deviation (with org fallback on cold host)
        behavior_result = self.deviation_engine.calculate(snapshot)

        # 6. Evaluate risk using standard production RiskEngine
        risk_result = self.risk_engine.evaluate(behavior_result)

        # Attach detailed evaluation metadata
        risk_result["query_index"] = k
        risk_result["lifecycle_state"] = lifecycle_state
        risk_result["entropy_deviation"] = behavior_result["entropy_deviation"]
        risk_result["domain_length_deviation"] = behavior_result["domain_length_deviation"]
        risk_result["query_rate_deviation"] = behavior_result["query_rate_deviation"]
        risk_result["novel_domain_score"] = behavior_result["novel_domain_score"]
        risk_result["organization_rarity_score"] = behavior_result["organization_rarity_score"]
        risk_result["behavior_score"] = behavior_result["behavior_score"]

        # 7. Baseline Update & Quarantine Logic
        if is_in_calibration:
            # RULE: During calibration, provisional observations MUST NOT update
            # either persistent host profile or persistent organization profile.
            self.provisional_buffers.setdefault(host, []).append({
                "domain": domain,
                "features": features,
                "risk_result": risk_result,
                "k": k
            })
            risk_result["baseline_updated"] = False
            risk_result["provisional_held"] = True

            # Check if this is the calibration transition query (e.g. Query #10)
            if k == self.calibration_queries:
                self._evaluate_calibration_batch(host)

        else:
            # STEADY_STATE: Query #11 onward
            if host in self.quarantined_hosts:
                # Host failed calibration batch gating; permanently quarantined from baseline
                risk_result["baseline_updated"] = False
                risk_result["calibration_quarantined"] = True
            else:
                # Host graduated; standard production baseline update rule applies
                if risk_result["risk_level"] in ("NORMAL", "LOW_RISK"):
                    self.host_profile.update(host, domain, features)
                    self.organization_profile.update(host, domain, features)
                    risk_result["baseline_updated"] = True
                else:
                    risk_result["baseline_updated"] = False

        return risk_result

    def _evaluate_calibration_batch(self, host: str):
        """
        At the end of calibration (query 10), evaluates all provisional observations.
        All-or-nothing:
        - If EVERY observation passes gating criteria, batch commit all 10.
        - If ANY observation fails gating criteria, quarantine the entire batch (0 committed).
        """
        buffer = self.provisional_buffers.get(host, [])
        if not buffer:
            return

        batch_failed = False
        for item in buffer:
            res = item["risk_result"]
            feats = item["features"]

            # Criterion 1: Elevated risk level
            if res["risk_level"] in ("SUSPICIOUS", "HIGH_RISK"):
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
            # Quarantine the entire provisional batch (0 committed)
            self.quarantined_hosts.add(host)
            self.provisional_buffers[host] = []
        else:
            # Every observation passed: batch commit in chronological order
            for item in buffer:
                self.host_profile.update(host, item["domain"], item["features"])
                self.organization_profile.update(host, item["domain"], item["features"])
            self.provisional_buffers[host] = []
