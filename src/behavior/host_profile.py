from collections import Counter


class HostProfile:
    """
    Stores the learned behavioral baseline for a single host.

    The profile contains only observations that the detection
    pipeline considers trusted enough to learn from.
    """

    def __init__(self, host):

        self.host = host

        # Total trusted DNS queries learned
        self.total_queries = 0

        # Cumulative feature values
        self.entropy_sum = 0.0
        self.domain_length_sum = 0

        # Running averages
        self.average_entropy = 0.0
        self.average_domain_length = 0.0

        # Learned domains
        self.unique_domains = set()

        # Frequency information
        self.domain_frequency = Counter()
        self.query_type_frequency = Counter()

    # --------------------------------------------------
    # Update trusted baseline
    # --------------------------------------------------

    def update(self, domain, features):

        self.total_queries += 1

        self.entropy_sum += features["entropy"]

        self.domain_length_sum += features["domain_length"]

        # Running average entropy
        self.average_entropy = round(
            self.entropy_sum / self.total_queries,
            4
        )

        # Running average domain length
        self.average_domain_length = round(
            self.domain_length_sum / self.total_queries,
            4
        )

        # Learn the domain
        self.unique_domains.add(domain)

        # Update domain frequency
        self.domain_frequency[domain] += 1

        # Update query-type frequency
        query_type = str(
            features["query_type"]
        )

        self.query_type_frequency[query_type] += 1

    # --------------------------------------------------
    # Convert profile to dictionary
    # --------------------------------------------------

    def to_dict(self):

        return {

            "host": self.host,

            "total_queries": self.total_queries,

            "entropy_sum": self.entropy_sum,

            "domain_length_sum": self.domain_length_sum,

            "average_entropy": self.average_entropy,

            "average_domain_length": self.average_domain_length,

            "unique_domains": sorted(
                self.unique_domains
            ),

            "domain_frequency": dict(
                self.domain_frequency
            ),

            "query_type_frequency": dict(
                self.query_type_frequency
            )
        }

    # --------------------------------------------------
    # Restore profile from dictionary
    # --------------------------------------------------

    @classmethod
    def from_dict(cls, data):

        profile = cls(
            data["host"]
        )

        profile.total_queries = data.get(
            "total_queries",
            0
        )

        profile.entropy_sum = data.get(
            "entropy_sum",
            0.0
        )

        profile.domain_length_sum = data.get(
            "domain_length_sum",
            0
        )

        profile.average_entropy = data.get(
            "average_entropy",
            0.0
        )

        profile.average_domain_length = data.get(
            "average_domain_length",
            0.0
        )

        profile.unique_domains = set(
            data.get(
                "unique_domains",
                []
            )
        )

        profile.domain_frequency = Counter(
            data.get(
                "domain_frequency",
                {}
            )
        )

        profile.query_type_frequency = Counter(
            data.get(
                "query_type_frequency",
                {}
            )
        )

        return profile