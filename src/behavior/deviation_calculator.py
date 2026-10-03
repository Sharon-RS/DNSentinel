from src.utils.config import Config


class DeviationCalculator:

    # --------------------------------------------------
    # Generic Normalization
    # --------------------------------------------------

    @staticmethod
    def normalize(current, baseline):

        if baseline <= 0:
            return 0.0

        deviation = abs(current - baseline) / baseline

        return round(
            min(deviation, 1.0),
            4
        )

    # --------------------------------------------------
    # Entropy Deviation
    # --------------------------------------------------

    @staticmethod
    def entropy(snapshot):

        current = snapshot.packet_features["entropy"]

        baseline = snapshot.host_profile.get(
            "average_entropy",
            0.0
        )

        if snapshot.host_profile.get(
            "total_queries",
            0
        ) < 2:

            return 0.0

        return DeviationCalculator.normalize(
            current,
            baseline
        )

    @staticmethod
    def entropy_with_fallback(snapshot, min_org_observations=None):
        current = snapshot.packet_features["entropy"]
        total_queries = snapshot.host_profile.get("total_queries", 0)

        if total_queries >= 2:
            baseline = snapshot.host_profile.get("average_entropy", 0.0)
            return DeviationCalculator.normalize(current, baseline)

        threshold = (
            min_org_observations
            if min_org_observations is not None
            else getattr(Config, "MIN_ORG_CALIBRATION_QUERIES", 20)
        )
        org = snapshot.organization_profile or {}
        org_queries = org.get("total_queries", 0)
        org_entropy = org.get("average_entropy", 0.0)
        org_len = org.get("average_domain_length", 0.0)

        if org_queries >= threshold and org_entropy > 0.0 and org_len > 0.0:
            return DeviationCalculator.normalize(current, org_entropy)

        return 0.0

    # --------------------------------------------------
    # Domain Length Deviation
    # --------------------------------------------------

    @staticmethod
    def domain_length(snapshot):

        current = snapshot.packet_features[
            "domain_length"
        ]

        baseline = snapshot.host_profile.get(
            "average_domain_length",
            0.0
        )

        if snapshot.host_profile.get(
            "total_queries",
            0
        ) < 2:

            return 0.0

        return DeviationCalculator.normalize(
            current,
            baseline
        )

    @staticmethod
    def domain_length_with_fallback(snapshot, min_org_observations=None):
        current = snapshot.packet_features["domain_length"]
        total_queries = snapshot.host_profile.get("total_queries", 0)

        if total_queries >= 2:
            baseline = snapshot.host_profile.get("average_domain_length", 0.0)
            return DeviationCalculator.normalize(current, baseline)

        threshold = (
            min_org_observations
            if min_org_observations is not None
            else getattr(Config, "MIN_ORG_CALIBRATION_QUERIES", 20)
        )
        org = snapshot.organization_profile or {}
        org_queries = org.get("total_queries", 0)
        org_entropy = org.get("average_entropy", 0.0)
        org_len = org.get("average_domain_length", 0.0)

        if org_queries >= threshold and org_entropy > 0.0 and org_len > 0.0:
            return DeviationCalculator.normalize(current, org_len)

        return 0.0

    # --------------------------------------------------
    # Query Rate Deviation
    # --------------------------------------------------

    @staticmethod
    def query_rate(snapshot):

        current_rate = float(
            snapshot.window_statistics.get(
                "query_rate",
                0.0
            )
        )

        baseline_rate = getattr(
            Config,
            "BASELINE_QUERY_RATE",
            2.0
        )

        # Cold start: fewer than 2 queries in window, rate cannot be established
        window_size = snapshot.window_statistics.get(
            "window_size",
            2
        )
        if window_size < 2 or current_rate <= 0.0:
            return 0.0

        # Normal steady traffic at or below design threshold receives zero deviation
        if current_rate <= baseline_rate:
            return 0.0

        # Query burst: scales linearly from baseline_rate upward
        deviation = (current_rate - baseline_rate) / baseline_rate

        return round(
            min(deviation, 1.0),
            4
        )

    # --------------------------------------------------
    # Novel Domain
    # --------------------------------------------------

    @staticmethod
    def novel_domain(snapshot):

        profile = snapshot.host_profile

        domain = snapshot.domain

        known_domains = set(
            profile.get(
                "unique_domains",
                []
            )
        )

        total_queries = profile.get(
            "total_queries",
            0
        )

        # During the learning phase we don't penalize
        # every first-time legitimate domain.
        if total_queries < 5:
            return 0.0

        if domain in known_domains:
            return 0.0

        return 1.0

    # --------------------------------------------------
    # Organization Rarity
    # --------------------------------------------------

    @staticmethod
    def organization_rarity(snapshot):

        organization = snapshot.organization_profile

        domain = snapshot.domain

        hosts = organization.get(
            "host_domain_map",
            {}
        ).get(domain, [])

        total_hosts = len(
            organization.get(
                "total_hosts",
                []
            )
        )

        if total_hosts <= 0:
            return 0.0

        # Domain seen by many hosts = common
        # Domain seen by very few hosts = rare
        rarity = 1.0 - (
            len(hosts) / total_hosts
        )

        return round(
            max(0.0, min(rarity, 1.0)),
            4
        )