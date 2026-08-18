from src.behavior.host_profile_manager import HostProfileManager
from src.behavior.organization_profile import OrganizationProfile
from src.behavior.sliding_window import SlidingWindowManager
from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_engine import BehaviorDeviationEngine
from src.risk.risk_engine import RiskEngine


class DetectionPipeline:

    def __init__(self):

        self.host_profile = HostProfileManager()

        self.organization_profile = OrganizationProfile()

        self.window = SlidingWindowManager()

        self.deviation_engine = (
            BehaviorDeviationEngine()
        )

        self.risk_engine = RiskEngine()

    # --------------------------------------------------
    # Process One DNS Observation
    # --------------------------------------------------

    def process(
        self,
        host,
        domain,
        features
    ):

        # ==================================================
        # 1. READ PREVIOUS HOST PROFILE
        # ==================================================

        previous_host_profile = (
            self.host_profile
            .load(host)
            .to_dict()
        )

        # ==================================================
        # 2. READ PREVIOUS ORGANIZATION PROFILE
        # ==================================================

        previous_organization_profile = (
            self.organization_profile.load()
        )

        # ==================================================
        # 3. READ PREVIOUS SLIDING WINDOW
        # ==================================================

        previous_window = (
            self.window.get_statistics(host)
        )

        # ==================================================
        # 4. BUILD SNAPSHOT USING PREVIOUS STATE
        # ==================================================

        snapshot = BehaviorSnapshot(

            host=host,

            domain=domain,

            packet_features=features,

            host_profile=previous_host_profile,

            organization_profile=(
                previous_organization_profile
            ),

            window_statistics=(
                previous_window
            )
        )

        # ==================================================
        # 5. CALCULATE BEHAVIOR
        # ==================================================

        behavior_result = (
            self.deviation_engine
            .calculate(snapshot)
        )

        # ==================================================
        # 6. CALCULATE RISK
        # ==================================================

        risk_result = (
            self.risk_engine
            .evaluate(behavior_result)
        )

        # ==================================================
        # 7. NOW UPDATE HOST PROFILE
        # ==================================================

        self.host_profile.update(
            host,
            domain,
            features
        )

        # ==================================================
        # 8. NOW UPDATE ORGANIZATION PROFILE
        # ==================================================

        self.organization_profile.update(
            host,
            domain,
            features
        )

        # ==================================================
        # 9. NOW UPDATE SLIDING WINDOW
        # ==================================================

        self.window.update(
            host,
            domain,
            features
        )

        # ==================================================
        # 10. RETURN RESULT
        # ==================================================

        return risk_result