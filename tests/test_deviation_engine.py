from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_engine import BehaviorDeviationEngine

snapshot = BehaviorSnapshot(

    host="10.0.0.1",

    domain="randomabcxyz123.com",

    packet_features={

        "entropy": 4.8,

        "domain_length": 20

    },

    host_profile={

        "average_entropy": 3.0,

        "average_domain_length": 12,

        "average_query_rate": 5,

        "queried_domains": [

            "google.com",

            "github.com"

        ]

    },

    organization_profile={

        "total_hosts": [

            "10.0.0.1",

            "10.0.0.2"

        ],

        "host_domain_map": {

            "google.com": [

                "10.0.0.1",

                "10.0.0.2"

            ]

        }

    },

    window_statistics={

        "query_rate": 10

    }

)

engine = BehaviorDeviationEngine()

result = engine.calculate(snapshot)

print(result)