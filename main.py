from src.capture.dns_capture import DNSCapture
from src.features.traditional_features import TraditionalFeatureExtractor
from src.pipeline.detection_pipeline import DetectionPipeline


class DNSentinel:

    def __init__(self):

        self.extractor = TraditionalFeatureExtractor()

        self.pipeline = DetectionPipeline()

    def process_dns_event(self, dns_event):

        features = self.extractor.extract(
            dns_event
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

        print()

        print(f"Recommendation:")

        print(result["recommendation"])

        print("=" * 60)

        print()

    def start(self):

        capture = DNSCapture(

            self.process_dns_event

        )

        capture.start()


if __name__ == "__main__":

    detector = DNSentinel()

    detector.start()