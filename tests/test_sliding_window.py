from src.behavior.sliding_window import SlidingWindowManager


window = SlidingWindowManager(
    window_size=5
)


samples = [

    ("google.com", 2.6, 10),

    ("github.com", 3.3, 10),

    ("youtube.com", 3.1, 11),

    ("stackoverflow.com", 3.5, 17),

    ("ubuntu.com", 3.2, 10)

]


for domain, entropy, length in samples:

    features = {

        "entropy": entropy,

        "domain_length": length,

        "query_type": 1

    }

    window.update(

        "10.0.0.1",

        domain,

        features

    )


print(window.get_statistics("10.0.0.1"))