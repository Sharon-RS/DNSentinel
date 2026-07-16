from src.features.entropy import calculate_entropy


class TraditionalFeatureExtractor:

    def extract(self, dns_event):

        domain = dns_event["domain"]

        features = {
            "domain_length": self.domain_length(domain),
            "subdomain_length": self.subdomain_length(domain),
            "label_count": self.label_count(domain),
            "entropy": calculate_entropy(domain),
            "digit_ratio": self.digit_ratio(domain),
            "alphabet_ratio": self.alphabet_ratio(domain),
            "special_character_ratio": self.special_character_ratio(domain),
            "packet_size": dns_event["packet_size"],
            "query_type": dns_event["query_type"],
        }

        return features

    def domain_length(self, domain):

        return len(domain)

    def subdomain_length(self, domain):

        labels = domain.split(".")

        if len(labels) <= 2:
            return 0

        subdomain = ".".join(labels[:-2])

        return len(subdomain)

    def label_count(self, domain):

        return len(domain.split("."))

    def digit_ratio(self, domain):

        if not domain:
            return 0.0

        digit_count = sum(
            character.isdigit()
            for character in domain
        )

        return round(
            digit_count / len(domain),
            4
        )

    def alphabet_ratio(self, domain):

        if not domain:
            return 0.0

        alphabet_count = sum(
            character.isalpha()
            for character in domain
        )

        return round(
            alphabet_count / len(domain),
            4
        )

    def special_character_ratio(self, domain):

        if not domain:
            return 0.0

        special_count = sum(
            not character.isalnum()
            for character in domain
        )

        return round(
            special_count / len(domain),
            4
        )
