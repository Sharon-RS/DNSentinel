"""
Dataset builder for DNSentinel Phase 2 experiments.
Extracts real lab traces directly from /var/log/named/query.log
and generates explicitly labeled synthetic test streams.
"""

import json
import re
from datetime import datetime
from pathlib import Path

from src.features.traditional_features import TraditionalFeatureExtractor

DATASETS_DIR = Path(__file__).parent.resolve()
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

extractor = TraditionalFeatureExtractor()


def parse_real_lab_traces():
    log_path = Path("/var/log/named/query.log")
    if not log_path.exists():
        raise FileNotFoundError(f"Real lab log not found at {log_path}")

    benign_events = []
    tunnel_events = []

    pattern = re.compile(
        r"^(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\s+queries:\s+info:\s+client\s+@\S+\s+(\d+\.\d+\.\d+\.\d+)#\d+\s+\([^)]+\):\s+query:\s+(\S+)\s+IN\s+([A-Z]+)"
    )

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue

            raw_time_str, client_ip, raw_domain, qtype_str = m.groups()
            domain = raw_domain.lower().rstrip(".")

            # Convert BIND9 timestamp: e.g. "03-Oct-2026 10:46:28.451" -> epoch float
            try:
                dt = datetime.strptime(raw_time_str, "%d-%b-%Y %H:%M:%S.%f")
                ts_epoch = dt.timestamp()
            except ValueError:
                ts_epoch = 1700000000.0

            qtype = 1 if qtype_str == "A" else 12 if qtype_str == "PTR" else 16

            raw_event = {
                "timestamp": ts_epoch,
                "source_ip": client_ip,
                "domain": domain,
                "query_type": qtype,
                "packet_size": len(domain) + 40
            }

            features = extractor.extract(raw_event)
            features["timestamp"] = ts_epoch

            event_record = {
                "timestamp": ts_epoch,
                "host": client_ip,
                "domain": domain,
                "features": features,
                "provenance": "real_lab_trace_named_query_log"
            }

            # Classify real lab traffic by known experimental lab domains
            is_tunnel = any(
                t in domain for t in ["tunnel.test", "attacker.lab", "office365-update.local"]
            )
            is_reverse_ptr = domain.endswith(".arpa")

            if is_tunnel:
                event_record["label"] = 1
                tunnel_events.append(event_record)
            elif not is_reverse_ptr:
                event_record["label"] = 0
                benign_events.append(event_record)

    # Sort each trace chronologically
    benign_events.sort(key=lambda x: x["timestamp"])
    tunnel_events.sort(key=lambda x: x["timestamp"])

    # Write real lab benign trace
    benign_path = DATASETS_DIR / "lab_trace_benign.jsonl"
    with open(benign_path, "w", encoding="utf-8") as f:
        for ev in benign_events:
            f.write(json.dumps(ev) + "\n")

    # Write real lab tunnel burst trace
    tunnel_path = DATASETS_DIR / "lab_trace_tunnel_burst.jsonl"
    with open(tunnel_path, "w", encoding="utf-8") as f:
        for ev in tunnel_events:
            f.write(json.dumps(ev) + "\n")

    print(f"[+] Extracted real lab benign trace: {len(benign_events)} queries -> {benign_path.name}")
    print(f"[+] Extracted real lab tunnel burst trace: {len(tunnel_events)} queries -> {tunnel_path.name}")


def generate_synthetic_datasets():
    # 1. Synthetic Mixed Stream (200 queries: 160 benign, 40 tunneling)
    mixed_path = DATASETS_DIR / "synthetic_mixed_stream.jsonl"
    benign_domains = [
        "google.com", "github.com", "youtube.com", "ubuntu.com", "stackoverflow.com",
        "wikipedia.org", "python.org", "docs.python.org", "debian.org", "mozilla.org"
    ]
    tunnel_payloads = [
        "a8k3mp91xq7z.tunnel.test", "7hk92lmqx81p.tunnel.test", "9xk82m4ql7pr3s.tunnel.test",
        "q7m2kx91lz83pq6r.attacker.lab", "x92klm7pq81zr4.attacker.lab", "m7qk29xlp83nz61.attacker.lab",
        "p8xk92mlq71zr4.attacker.lab", "q7mk29xlp83nz61.attacker.lab", "z81kq92lm7px4r.attacker.lab",
        "m92xk7qlp81zr4.attacker.lab"
    ]

    base_time = 1770000000.0
    mixed_events = []
    host = "10.0.1.50"

    current_time = base_time
    for i in range(200):
        # 80% benign, 20% malicious (every 5th query is part of intermittent burst)
        if (i % 5 == 0) and i >= 10:
            domain = tunnel_payloads[(i // 5) % len(tunnel_payloads)]
            current_time += 0.04  # Burst timing (25 QPS)
            label = 1
        else:
            domain = benign_domains[i % len(benign_domains)]
            current_time += 1.5   # Normal browsing timing (0.67 QPS)
            label = 0

        raw_event = {
            "timestamp": current_time,
            "source_ip": host,
            "domain": domain,
            "query_type": 1,
            "packet_size": len(domain) + 40
        }
        features = extractor.extract(raw_event)
        features["timestamp"] = current_time

        mixed_events.append({
            "timestamp": round(current_time, 4),
            "host": host,
            "domain": domain,
            "features": features,
            "label": label,
            "provenance": "synthetic_mixed_stream"
        })

    with open(mixed_path, "w", encoding="utf-8") as f:
        for ev in mixed_events:
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Generated synthetic mixed stream: {len(mixed_events)} queries -> {mixed_path.name}")

    # 2. Synthetic Poisoning Attack Stream (20 benign warmup + 40 malicious attack)
    poison_path = DATASETS_DIR / "synthetic_poisoning_attack.jsonl"
    poison_events = []
    poison_host = "10.0.2.100"
    p_time = base_time

    # Warmup phase: 20 benign queries
    for i in range(20):
        p_time += 1.0
        domain = benign_domains[i % len(benign_domains)]
        raw_event = {
            "timestamp": p_time,
            "source_ip": poison_host,
            "domain": domain,
            "query_type": 1,
            "packet_size": len(domain) + 40
        }
        features = extractor.extract(raw_event)
        features["timestamp"] = p_time
        poison_events.append({
            "timestamp": round(p_time, 4),
            "host": poison_host,
            "domain": domain,
            "features": features,
            "label": 0,
            "phase": "warmup",
            "provenance": "synthetic_poisoning_attack"
        })

    # Attack phase: 40 repetitive high-entropy tunneling queries
    malicious_domain = "asd82js92j.command.xyz"
    for i in range(40):
        p_time += 0.05  # Burst rate
        raw_event = {
            "timestamp": p_time,
            "source_ip": poison_host,
            "domain": malicious_domain,
            "query_type": 1,
            "packet_size": len(malicious_domain) + 40
        }
        features = extractor.extract(raw_event)
        features["timestamp"] = p_time
        poison_events.append({
            "timestamp": round(p_time, 4),
            "host": poison_host,
            "domain": malicious_domain,
            "features": features,
            "label": 1,
            "phase": "attack",
            "provenance": "synthetic_poisoning_attack"
        })

    with open(poison_path, "w", encoding="utf-8") as f:
        for ev in poison_events:
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Generated synthetic poisoning attack stream: {len(poison_events)} queries -> {poison_path.name}")


if __name__ == "__main__":
    parse_real_lab_traces()
    generate_synthetic_datasets()
