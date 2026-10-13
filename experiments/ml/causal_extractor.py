"""
DNSentinel Phase 6B: Causal ML Feature Extraction Module.

Extracts leakage-free, causal features from chronologically replayed DNS query streams.
For every query k, features are constructed strictly using:
  1. Lexical and protocol properties of query k itself.
  2. Temporal sliding-window metrics of host activity up to query k.
  3. Persistent behavioral baselines accumulated strictly from queries 1..k-1.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from src.behavior.behavior_snapshot import BehaviorSnapshot
from src.behavior.deviation_calculator import DeviationCalculator
from src.behavior.deviation_engine import BehaviorDeviationEngine


class CausalMLFeatureExtractor:
    """
    Transforms raw streaming DNS queries and prior behavioral context into
    a strictly causal, leakage-audited feature vector.
    """

    FEATURE_NAMES: List[str] = [
        # Group A: Lexical Features
        "lex_domain_length",
        "lex_subdomain_length",
        "lex_subdomain_ratio",
        "lex_label_count",
        "lex_entropy",
        "lex_digit_ratio",
        "lex_alphabet_ratio",
        "lex_special_ratio",
        "lex_packet_size",
        "proto_query_type",
        # Group B: Temporal & Dynamic Window Features
        "temp_inter_arrival_time",
        "temp_query_rate",
        "temp_window_duration",
        "temp_entropy_trend",
        "temp_length_trend",
        "temp_unique_ratio",
        # Group C: Host Behavioral Deviation Features (Queries 1..k-1)
        "host_total_queries",
        "host_average_entropy",
        "host_average_domain_length",
        "host_entropy_deviation",
        "host_length_deviation",
        "host_query_rate_deviation",
        "host_novel_domain",
        # Group D: Organizational Behavioral Features (Queries 1..k-1)
        "org_total_queries",
        "org_domain_frequency",
        "org_rarity_score",
        "org_average_entropy",
        "org_average_domain_length",
        "org_entropy_deviation",
        "org_length_deviation",
        # Group E: Heuristic Composite Behavioral Score
        "behavior_score",
    ]

    FORBIDDEN_FEATURE_SUBSTRINGS: Set[str] = {
        "host", "ip", "domain_name", "raw_domain", "timestamp", "epoch",
        "provenance", "phase", "label"
    }

    @classmethod
    def extract_features(
        cls,
        sample_id: int,
        raw_event: Dict[str, Any],
        host_profile: Dict[str, Any],
        org_profile: Dict[str, Any],
        window_stats: Dict[str, Any],
        inter_arrival_time: float,
        deviation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds the clean feature record for query k.
        """
        domain = raw_event["domain"]
        feats = raw_event["features"]
        dlen = int(feats["domain_length"])
        sublen = int(feats["subdomain_length"])

        # Construct snapshot strictly from state up to query k
        snapshot = BehaviorSnapshot(
            host=raw_event["host"],
            domain=domain,
            packet_features=feats,
            host_profile=host_profile,
            organization_profile=org_profile,
            window_statistics=window_stats,
        )

        w_size = max(1, window_stats.get("window_size", 1))
        unique_doms = window_stats.get("unique_domains", 1)

        feature_dict: Dict[str, Any] = {
            # Group A: Lexical Features
            "lex_domain_length": dlen,
            "lex_subdomain_length": sublen,
            "lex_subdomain_ratio": round(sublen / dlen, 4) if dlen > 0 else 0.0,
            "lex_label_count": int(feats["label_count"]),
            "lex_entropy": float(feats["entropy"]),
            "lex_digit_ratio": float(feats["digit_ratio"]),
            "lex_alphabet_ratio": float(feats["alphabet_ratio"]),
            "lex_special_ratio": float(feats["special_character_ratio"]),
            "lex_packet_size": int(feats["packet_size"]),
            "proto_query_type": int(feats["query_type"]),

            # Group B: Temporal & Dynamic Window Features
            "temp_inter_arrival_time": round(float(inter_arrival_time), 4),
            "temp_query_rate": round(float(window_stats.get("query_rate", 0.0)), 4),
            "temp_window_duration": round(float(window_stats.get("window_duration", 0.0)), 4),
            "temp_entropy_trend": round(float(window_stats.get("entropy_trend", 0.0)), 4),
            "temp_length_trend": round(float(window_stats.get("length_trend", 0.0)), 4),
            "temp_unique_ratio": round(float(unique_doms / w_size), 4),

            # Group C: Host Behavioral Deviation Features (Queries 1..k-1)
            "host_total_queries": int(host_profile.get("total_queries", 0)),
            "host_average_entropy": float(host_profile.get("average_entropy", 0.0)),
            "host_average_domain_length": float(host_profile.get("average_domain_length", 0.0)),
            "host_entropy_deviation": float(DeviationCalculator.entropy(snapshot)),
            "host_length_deviation": float(DeviationCalculator.domain_length(snapshot)),
            "host_query_rate_deviation": float(DeviationCalculator.query_rate(snapshot)),
            "host_novel_domain": float(DeviationCalculator.novel_domain(snapshot)),

            # Group D: Organizational Behavioral Features (Queries 1..k-1)
            "org_total_queries": int(org_profile.get("total_queries", 0)),
            "org_domain_frequency": int(org_profile.get("domain_frequency", {}).get(domain, 0)),
            "org_rarity_score": float(DeviationCalculator.organization_rarity(snapshot)),
            "org_average_entropy": float(org_profile.get("average_entropy", 0.0)),
            "org_average_domain_length": float(org_profile.get("average_domain_length", 0.0)),
            "org_entropy_deviation": float(DeviationCalculator.entropy_with_fallback(snapshot)),
            "org_length_deviation": float(DeviationCalculator.domain_length_with_fallback(snapshot)),

            # Group E: Heuristic Composite Behavioral Score
            "behavior_score": round(float(deviation_result.get("behavior_score", 0.0)), 4),
        }

        return {
            "sample_id": sample_id,
            "label": int(raw_event["label"]),
            "provenance": raw_event.get("provenance", "unknown"),
            "features": feature_dict,
        }
