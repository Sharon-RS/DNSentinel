from src.pipeline.detection_pipeline import DetectionPipeline


pipeline = DetectionPipeline()


# --------------------------------------------------
# Establish normal baseline
# --------------------------------------------------

normal_samples = [

    ("10.0.0.1", "google.com", 2.6, 10),

    ("10.0.0.1", "github.com", 3.0, 10),

    ("10.0.0.1", "youtube.com", 3.2, 11),

    ("10.0.0.1", "stackoverflow.com", 3.4, 17),

]


for host, domain, entropy, length in normal_samples:

    features = {

        "entropy": entropy,

        "domain_length": length,

        "query_type": 1

    }

    pipeline.process(
        host,
        domain,
        features
    )


print("\nNormal baseline established.")


# --------------------------------------------------
# Suspicious domain
# --------------------------------------------------

malicious_domain = "asd82js92j.command.xyz"


malicious_features = {

    "entropy": 5.1,

    "domain_length": 28,

    "query_type": 1

}


# --------------------------------------------------
# Send suspicious domain repeatedly
# --------------------------------------------------

for i in range(1, 6):

    result = pipeline.process(

        "10.0.0.1",

        malicious_domain,

        malicious_features

    )

    print("\n--------------------------------")

    print(
        f"Suspicious Query #{i}"
    )

    print(
        f"Domain           : {malicious_domain}"
    )

    print(
        f"Score            : "
        f"{result['behavior_score']}"
    )

    print(
        f"Risk             : "
        f"{result['risk_level']}"
    )

    print(
        f"Baseline Updated : "
        f"{result['baseline_updated']}"
    )
