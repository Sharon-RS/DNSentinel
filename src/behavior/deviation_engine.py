from src.behavior.deviation_calculator import DeviationCalculator
from src.utils.config import Config


class BehaviorDeviationEngine:
    """
    Calculates behavioral deviations for the current
    DNS observation against previously learned context.
    """

    def calculate(self, snapshot):

        entropy = DeviationCalculator.entropy(
            snapshot
        )

        length = DeviationCalculator.domain_length(
            snapshot
        )

        rate = DeviationCalculator.query_rate(
            snapshot
        )

        novel = DeviationCalculator.novel_domain(
            snapshot
        )

        rarity = DeviationCalculator.organization_rarity(
            snapshot
        )

        # --------------------------------------------------
        # Weighted behavioral score
        # --------------------------------------------------

        score = (

            entropy *
            Config.ENTROPY_WEIGHT

            +

            length *
            Config.DOMAIN_LENGTH_WEIGHT

            +

            rate *
            Config.QUERY_RATE_WEIGHT

            +

            novel *
            Config.NOVEL_DOMAIN_WEIGHT

            +

            rarity *
            Config.ORGANIZATION_RARITY_WEIGHT

        )

        return {

            "entropy_deviation": round(
                entropy,
                4
            ),

            "domain_length_deviation": round(
                length,
                4
            ),

            "query_rate_deviation": round(
                rate,
                4
            ),

            "novel_domain_score": round(
                novel,
                4
            ),

            "organization_rarity_score": round(
                rarity,
                4
            ),

            "behavior_score": round(
                min(score * 100, 100),
                2
            )
        }


class ColdStartDeviationEngine(BehaviorDeviationEngine):
    """
    Subclasses BehaviorDeviationEngine to apply organization baseline fallback
    for cold-start hosts without altering steady-state calculation.
    """

    def __init__(self, min_org_observations=None):
        super().__init__()
        self.min_org_observations = min_org_observations

    def calculate(self, snapshot):
        entropy = DeviationCalculator.entropy_with_fallback(
            snapshot, self.min_org_observations
        )
        length = DeviationCalculator.domain_length_with_fallback(
            snapshot, self.min_org_observations
        )
        rate = DeviationCalculator.query_rate(snapshot)
        novel = DeviationCalculator.novel_domain(snapshot)
        rarity = DeviationCalculator.organization_rarity(snapshot)

        score = (
            entropy * Config.ENTROPY_WEIGHT
            + length * Config.DOMAIN_LENGTH_WEIGHT
            + rate * Config.QUERY_RATE_WEIGHT
            + novel * Config.NOVEL_DOMAIN_WEIGHT
            + rarity * Config.ORGANIZATION_RARITY_WEIGHT
        )

        return {
            "entropy_deviation": round(entropy, 4),
            "domain_length_deviation": round(length, 4),
            "query_rate_deviation": round(rate, 4),
            "novel_domain_score": round(novel, 4),
            "organization_rarity_score": round(rarity, 4),
            "behavior_score": round(min(score * 100, 100), 2)
        }