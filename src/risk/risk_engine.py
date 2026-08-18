class RiskEngine:
    """
    Converts the behavioral anomaly score into
    an interpretable risk decision.

    The score is in the range 0-100.
    """

    def evaluate(self, behavior_result):

        score = float(
            behavior_result["behavior_score"]
        )

        # --------------------------------------------------
        # NORMAL
        # --------------------------------------------------

        if score < 30:

            level = "NORMAL"

            confidence = 0.90

            recommendation = (
                "No immediate action required."
            )

        # --------------------------------------------------
        # LOW RISK
        # --------------------------------------------------

        elif score < 50:

            level = "LOW_RISK"

            confidence = 0.70

            recommendation = (
                "Monitor this host for changes "
                "in DNS behavior."
            )

        # --------------------------------------------------
        # SUSPICIOUS
        # --------------------------------------------------

        elif score < 70:

            level = "SUSPICIOUS"

            confidence = 0.85

            recommendation = (
                "Investigate the host for "
                "potential anomalous DNS activity."
            )

        # --------------------------------------------------
        # HIGH RISK
        # --------------------------------------------------

        else:

            level = "HIGH_RISK"

            confidence = 0.95

            recommendation = (
                "Potential DNS tunneling detected. "
                "Immediate investigation recommended."
            )

        result = behavior_result.copy()

        result["risk_level"] = level

        result["confidence"] = confidence

        result["recommendation"] = recommendation

        return result