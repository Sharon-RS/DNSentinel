from collections import Counter


class HostProfile:

    def __init__(self, host):

        self.host = host

        self.total_queries = 0

        self.entropy_sum = 0.0

        self.domain_length_sum = 0

        self.average_entropy = 0.0

        self.average_domain_length = 0.0

        self.unique_domains = set()

        self.domain_frequency = Counter()

        self.query_type_frequency = Counter()

    def update(self, domain, features):

        self.total_queries += 1

        self.entropy_sum += features["entropy"]

        self.domain_length_sum += features["domain_length"]

        self.average_entropy = round(
            self.entropy_sum / self.total_queries,
            4
        )

        self.average_domain_length = round(
            self.domain_length_sum / self.total_queries,
            4
        )

        self.unique_domains.add(domain)

        self.domain_frequency[domain] += 1

        self.query_type_frequency[
            str(features["query_type"])
        ] += 1

    def to_dict(self):

        return {

            "host": self.host,

            "total_queries": self.total_queries,

            "entropy_sum": self.entropy_sum,

            "domain_length_sum": self.domain_length_sum,

            "average_entropy": self.average_entropy,

            "average_domain_length": self.average_domain_length,

            "unique_domains": list(self.unique_domains),

            "domain_frequency": dict(self.domain_frequency),

            "query_type_frequency": dict(
                self.query_type_frequency
            )

        }

    @classmethod
    def from_dict(cls, data):

        profile = cls(data["host"])

        profile.total_queries = data["total_queries"]

        profile.entropy_sum = data["entropy_sum"]

        profile.domain_length_sum = data[
            "domain_length_sum"
        ]

        profile.average_entropy = data[
            "average_entropy"
        ]

        profile.average_domain_length = data[
            "average_domain_length"
        ]

        profile.unique_domains = set(
            data["unique_domains"]
        )

        profile.domain_frequency = Counter(
            data["domain_frequency"]
        )

        profile.query_type_frequency = Counter(
            data["query_type_frequency"]
        )

        return profile
