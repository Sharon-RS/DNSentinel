from src.behavior.host_profile_manager import HostProfileManager
from src.behavior.organization_profile import OrganizationProfile
from src.behavior.sliding_window import SlidingWindowManager
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_engine import BehaviorDeviationEngine
from src.risk.risk_engine import RiskEngine


class DetectionPipeline:
    """
    Main DNSentinel behavioral detection pipeline.

    Processing order:

        1. Load the existing trusted host baseline.
        2. Load the existing trusted organization baseline.
        3. Update the sliding window with the current observation.
        4. Build a behavioral snapshot.
        5. Calculate behavioral deviation.
        6. Convert deviation into a risk decision.
        7. Learn the observation only when it is trusted.

    This prevents suspicious observations from immediately
    poisoning the behavioral baseline.
    """

    def __init__(self):

        self.host_profile = (
            HostProfileManager()
        )

        self.organization_profile = (
            OrganizationProfile()
        )

        self.window = (
            SlidingWindowManager()
        )

        self.deviation_engine = (
            BehaviorDeviationEngine()
        )

        self.risk_engine = (
            RiskEngine()
        )

    # --------------------------------------------------
    # Process DNS observation
    # --------------------------------------------------

    def process(
        self,
        host,
        domain,
        features
    ):

        # ==================================================
        # STEP 1
        # Load CURRENT trusted baselines
        # ==================================================

        host_profile = (
            self.host_profile.load(host)
            .to_dict()
        )

        organization_profile = (
            self.organization_profile.load()
        )

        # ==================================================
        # STEP 2
        # Update sliding window
        #
        # The sliding window represents recent activity.
        # It is intentionally separate from the persistent
        # trusted baseline.
        # ==================================================

        self.window.update(
            host,
            domain,
            features
        )

        window_statistics = (
            self.window.get_statistics(host)
        )

        # ==================================================
        # STEP 3
        # Build behavioral snapshot
        # ==================================================

        snapshot = BehaviorSnapshot(

            host=host,

            domain=domain,

            packet_features=features,

            host_profile=host_profile,

            organization_profile=organization_profile,

            window_statistics=window_statistics

        )

        # ==================================================
        # STEP 4
        # Calculate behavioral deviation
        # ==================================================

        behavior_result = (
            self.deviation_engine.calculate(
                snapshot
            )
        )

        # ==================================================
        # STEP 5
        # Calculate risk
        # ==================================================

        risk_result = (
            self.risk_engine.evaluate(
                behavior_result
            )
        )

        # ==================================================
        # STEP 6
        # Decide whether to learn
        # ==================================================

        risk_level = risk_result[
            "risk_level"
        ]

        # Only trusted observations are allowed
        # to update the persistent baseline.
        #
        # NORMAL and LOW_RISK observations are
        # currently considered safe enough to learn.
        #
        # SUSPICIOUS and HIGH_RISK observations
        # are NOT learned immediately.

        if risk_level in (
            "NORMAL",
            "LOW_RISK"
        ):

            self.host_profile.update(
                host,
                domain,
                features
            )

            self.organization_profile.update(
                host,
                domain,
                features
            )

            risk_result[
                "baseline_updated"
            ] = True

        else:

            risk_result[
                "baseline_updated"
            ] = False

        return risk_result