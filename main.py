from src.capture.dns_capture import DNSCapture
from src.features.traditional_features import TraditionalFeatureExtractor
from src.behavior.host_profile import HostProfileManager


feature_extractor = TraditionalFeatureExtractor()

host_profile_manager = HostProfileManager()


def handle_dns_event(event):

    features = feature_extractor.extract(event)

    host = event["source_ip"]

    domain = event["domain"]

    profile = host_profile_manager.update_profile(
        host=host,
        domain=domain,
        features=features
    )

    print("=" * 60)
    print("DNS EVENT DETECTED")
    print("=" * 60)

    print(f"Host   : {host}")
    print(f"Domain : {domain}")

    print()

    print("-" * 60)
    print("TRADITIONAL DNS FEATURES")
    print("-" * 60)

    print(
        f"Domain Length   : "
        f"{features['domain_length']}"
    )

    print(
        f"Entropy         : "
        f"{features['entropy']}"
    )

    print(
        f"Digit Ratio     : "
        f"{features['digit_ratio']}"
    )

    print(
        f"Packet Size     : "
        f"{features['packet_size']}"
    )

    print()

    print("-" * 60)
    print("ADAPTIVE HOST PROFILE")
    print("-" * 60)

    print(
        f"Total Queries         : "
        f"{profile['total_queries']}"
    )

    print(
        f"Average Entropy       : "
        f"{profile['average_entropy']}"
    )

    print(
        f"Average Domain Length : "
        f"{profile['average_domain_length']}"
    )

    print(
        f"Unique Domains        : "
        f"{len(profile['unique_domains'])}"
    )

    print()

    print("DOMAIN FREQUENCY")

    for domain_name, count in sorted(
        profile["domain_frequency"].items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]:

        print(
            f"{domain_name:<35} {count}"
        )

    print()


def main():

    print()

    print("=" * 60)
    print("DNSENTINEL v0.1")
    print("Adaptive DNS Behavioral Intelligence")
    print("=" * 60)

    print()

    print(
        "[+] Traditional feature extraction enabled"
    )

    print(
        "[+] Adaptive host profiling enabled"
    )

    print()

    capture = DNSCapture(
        packet_handler=handle_dns_event
    )

    capture.start()


if __name__ == "__main__":

    main()
