import argparse

from src.capture.dns_capture import DNSCapture
from src.features.traditional_features import TraditionalFeatureExtractor
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline


class DNSentinel:

    def __init__(self, pipeline_type: str = "heuristic"):

        self.extractor = TraditionalFeatureExtractor()

        if pipeline_type == "cascade":
            self.pipeline = CascadeDetectionPipeline()
        else:
            self.pipeline = DetectionPipeline()

    def process_dns_event(self, dns_event):

        features = self.extractor.extract(
            dns_event
        )

        features["timestamp"] = dns_event.get(
            "timestamp"
        )

        result = self.pipeline.process(

            host=dns_event["source_ip"],

            domain=dns_event["domain"],

            features=features

        )

        self.display_result(

            dns_event,

            features,

            result

        )

    def display_result(

        self,

        event,

        features,

        result

    ):

        print("=" * 60)

        print(f"Time        : {event['timestamp']}")

        print(f"Host        : {event['source_ip']}")

        print(f"Domain      : {event['domain']}")

        print()

        print("Packet Features")

        print("-----------------------------")

        print(f"Entropy     : {features['entropy']}")

        print(f"Length      : {features['domain_length']}")

        print(f"Digits      : {features['digit_ratio']}")

        print(f"Packet Size : {features['packet_size']}")

        print()

        print("Detection")

        print("-----------------------------")

        print(f"Score       : {result['behavior_score']}")

        print(f"Risk        : {result['risk_level']}")

        print(f"Confidence  : {result['confidence']}")
        print(f"Baseline Updated : "f"{result['baseline_updated']}")

        if result.get("ml_enabled"):
            print(f"Cascade Path     : {result.get('cascade_path')}")
            print(f"Cascade Decision : {result.get('cascade_decision')}")
            if result.get("ml_probability") is not None:
                print(f"ML Probability   : {result.get('ml_probability')}")

        print()

        print(f"Recommendation:")

        print(result["recommendation"])

        print("=" * 60)

        print()

    def start(self, interface: str = "ens33"):

        capture = DNSCapture(

            self.process_dns_event

        )

        capture.start(interface=interface)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="DNSentinel: Adaptive DNS Tunneling Detection")
    parser.add_argument(
        "--pipeline",
        choices=["heuristic", "cascade"],
        default="heuristic",
        help="Detection pipeline engine to use (default: heuristic)"
    )
    args = parser.parse_args()

    detector = DNSentinel(pipeline_type=args.pipeline)

    detector.start()