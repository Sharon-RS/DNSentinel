from src.pipeline.detection_pipeline import DetectionPipeline

pipeline = DetectionPipeline()

samples = [

    ("10.0.0.1", "google.com", 2.6, 10),

    ("10.0.0.1", "github.com", 3.0, 10),

    ("10.0.0.1", "youtube.com", 3.2, 11),

    ("10.0.0.1", "stackoverflow.com", 3.4, 17),

    ("10.0.0.1", "asd82js92j.command.xyz", 5.1, 28)

]

for host, domain, entropy, length in samples:

    features = {

        "entropy": entropy,

        "domain_length": length,

        "query_type": 1

    }

    result = pipeline.process(

        host,

        domain,

        features

    )

    print("\n--------------------------------")

    print(f"Domain       : {domain}")

    print(f"Score        : {result['behavior_score']}")

    print(f"Risk Level   : {result['risk_level']}")

    print(f"Confidence   : {result['confidence']}")

    print(f"Recommendation: {result['recommendation']}")

    # print(domain)

    # print(result)____