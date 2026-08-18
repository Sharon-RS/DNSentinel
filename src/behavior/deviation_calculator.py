# from src.utils.config import Config


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

    # --------------------------------------------------
    # Query Rate Deviation
    # --------------------------------------------------

    @staticmethod
    def query_rate(snapshot):

        current = snapshot.window_statistics.get(
            "query_rate",
            0
        )

        previous_window_size = snapshot.window_statistics.get(
            "previous_window_size",
            0
        )

        if previous_window_size <= 0:
            return 0.0

        return DeviationCalculator.normalize(
            current,
            previous_window_size
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