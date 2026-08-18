from dataclasses import dataclass


@dataclass
class BehaviorSnapshot:
    """
    Complete behavioral context for one DNS query.
    """

    host: str
    domain: str

    packet_features: dict
    host_profile: dict
    organization_profile: dict
    window_statistics: dict