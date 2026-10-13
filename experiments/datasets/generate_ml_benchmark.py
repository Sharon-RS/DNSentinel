"""
DNSentinel Phase 6A: Machine Learning Benchmark Dataset Generator.

Generates an isolated, multi-host, temporally interleaved benchmark dataset
for evaluating machine learning and hybrid behavioral-ML DNS tunneling detection.

Design Principles:
  1. Realistic Enterprise Diversity: 16 hosts, 85+ legitimate domains across 10 categories.
  2. Multi-Threat Composition: Low-and-slow C2, high-entropy tunneling bursts, and
     varying-subdomain exfiltration across 9 disjoint attack campaigns.
  3. No Class Shortcuts: No host is exclusively malicious; timestamps, packet sizes,
     and suffixes overlap across classes.
  4. Causal & Reconstructible: Chronologically sorted per host and globally, enabling
     causal reconstruction of sliding windows, query rates, and host baselines.
  5. Hard-Negative Preservation: Preserves the authentic lab trace danger.edu observations
     as legitimate label=0 anomalies.
  6. Strict Determinism: Fixed random seed (42) guarantees bitwise reproducibility.
"""

import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.traditional_features import TraditionalFeatureExtractor

DATASETS_DIR = Path(__file__).parent.resolve()
OUTPUT_FILE = DATASETS_DIR / "dnsentinel_ml_benchmark.jsonl"
RANDOM_SEED = 42


# ==============================================================================
# 1. DOMAIN POOLS & ATTACK CAMPAIGNS
# ==============================================================================

BENIGN_DOMAINS_BY_CATEGORY = {
    "search": [
        "google.com", "www.google.com", "bing.com", "duckduckgo.com",
        "search.yahoo.com", "ecosia.org"
    ],
    "developer_repos": [
        "github.com", "api.github.com", "raw.githubusercontent.com",
        "gitlab.com", "bitbucket.org", "pypi.org", "files.pythonhosted.org",
        "registry.npmjs.org", "crates.io", "maven.apache.org", "docker.io",
        "registry-1.docker.io", "hub.docker.com"
    ],
    "developer_docs": [
        "stackoverflow.com", "api.stackexchange.com", "developer.mozilla.org",
        "docs.python.org", "kubernetes.io", "golang.org", "rust-lang.org",
        "readthedocs.io", "w3schools.com", "dev.to"
    ],
    "cloud_infrastructure": [
        "aws.amazon.com", "s3.amazonaws.com", "dynamodb.us-east-1.amazonaws.com",
        "azure.microsoft.com", "management.azure.com", "blob.core.windows.net",
        "cloud.google.com", "storage.googleapis.com", "compute.googleapis.com"
    ],
    "cdns_and_assets": [
        "cloudflare.com", "cdnjs.cloudflare.com", "1.1.1.1.cloudflare-dns.com",
        "fastly.net", "akamaihd.net", "unpkg.com", "cdn.jsdelivr.net",
        "ajax.googleapis.com", "static.cloudflareinsights.com"
    ],
    "enterprise_productivity": [
        "office.com", "login.microsoftonline.com", "outlook.office365.com",
        "slack.com", "app.slack.com", "zoom.us", "us04web.zoom.us",
        "atlassian.net", "jira.corp.internal", "confluence.corp.internal",
        "workday.com", "salesforce.com"
    ],
    "collaboration": [
        "notion.so", "figma.com", "miro.com", "teams.microsoft.com",
        "discord.com", "trello.com", "asana.com"
    ],
    "os_infrastructure": [
        "ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com",
        "1.ntp.ubuntu.com", "debian.org", "ftp.debian.org",
        "dl-cdn.alpinelinux.org", "fedoraproject.org"
    ],
    "common_web": [
        "wikipedia.org", "en.wikipedia.org", "youtube.com", "i.ytimg.com",
        "linkedin.com", "reddit.com", "nytimes.com", "bbc.co.uk", "medium.com"
    ],
    "internal_services": [
        "auth.internal.corp", "mail.corp.lan", "dc01.corp.internal",
        "git.internal.net", "vault.infra.internal", "monitoring.corp.lan"
    ]
}

# Flatten benign domain pool
ALL_BENIGN_DOMAINS = [
    dom for cat in BENIGN_DOMAINS_BY_CATEGORY.values() for dom in cat
]

# Malicious Campaigns (Domain-Disjoint for Phase 6 Train/Test splitting)
MALICIOUS_CAMPAIGNS = {
    # Category 1: Low-and-Slow C2 Beacons (Dictionary/legitimate-looking lexical structure)
    "c2_stealth_alpha": {
        "type": "low_and_slow_c2",
        "domains": [
            "telemetry-sync.cloud-metrics-hub.org",
            "heartbeat.services-diagnostics.net",
            "update-agent.cloud-telemetry.io"
        ],
        "qtype": 1,
        "interval_range": (35.0, 90.0)
    },
    "c2_stealth_beta": {
        "type": "low_and_slow_c2",
        "domains": [
            "beacon.global-connectivity-test.org",
            "auth-validator.network-security-check.net",
            "service-ping.edge-infrastructure.org"
        ],
        "qtype": 1,
        "interval_range": (45.0, 120.0)
    },
    "c2_stealth_gamma": {
        "type": "low_and_slow_c2",
        "domains": [
            "edge-metrics.api-cdn-services.com",
            "sync.device-management-cloud.net",
            "node-health.system-monitoring-infra.org"
        ],
        "qtype": 1,
        "interval_range": (60.0, 180.0)
    },
    # Category 2: High-Entropy DNS Tunneling (Bursts of encoded payload labels)
    "tunnel_hex_delta": {
        "type": "high_entropy_tunnel",
        "slds": ["data-relay-stream.org", "ns-tunnel.net"],
        "encoding": "hex",
        "qtype": 1,
        "burst_qps_range": (8.0, 25.0)
    },
    "tunnel_base32_epsilon": {
        "type": "high_entropy_tunnel",
        "slds": ["c2-dnscat-exfil.xyz", "secure-payload-dns.test"],
        "encoding": "base32",
        "qtype": 16,  # TXT record exfil
        "burst_qps_range": (5.0, 15.0)
    },
    "tunnel_base64_zeta": {
        "type": "high_entropy_tunnel",
        "slds": ["fast-tunnel-transit.info", "dns-uplink-gateway.biz"],
        "encoding": "base64",
        "qtype": 1,
        "burst_qps_range": (10.0, 20.0)
    },
    "tunnel_random_theta": {
        "type": "high_entropy_tunnel",
        "slds": ["stream-egress.cloud-transit.tech"],
        "encoding": "random",
        "qtype": 1,
        "burst_qps_range": (12.0, 25.0)
    },
    # Category 3: Dynamic Subdomain Exfiltration (Staged sequential payloads)
    "exfil_chunk_eta": {
        "type": "subdomain_exfiltration",
        "sld": "corp-backup-transfer.net",
        "pattern": "chunk{:03d}.{}",
        "qtype": 1,
        "interval_range": (0.4, 1.8)
    },
    "exfil_chunk_iota": {
        "type": "subdomain_exfiltration",
        "sld": "staging-cloud-upload.org",
        "pattern": "p{:03d}-{:08x}.{}",
        "qtype": 1,
        "interval_range": (0.5, 2.2)
    }
}


# ==============================================================================
# 2. GENERATOR LOGIC
# ==============================================================================

class DNSentinelMLBenchmarkGenerator:
    """
    Constructs the 6,000-query benchmark dataset with realistic multi-host
    concurrency, authentic hard negatives, and strict temporal causality.
    """

    def __init__(self, seed: int = RANDOM_SEED):
        self.seed = seed
        self.rng = random.Random(seed)
        self.extractor = TraditionalFeatureExtractor()

        # 16 Enterprise Host IP Pool
        self.hosts = [f"10.0.1.{i}" for i in range(10, 26)]

        # Threat assignment to hosts (hosts are compromised but still browse legitimately)
        self.c2_hosts = ["10.0.1.12", "10.0.1.15", "10.0.1.22"]
        self.tunnel_hosts = ["10.0.1.18", "10.0.1.20", "10.0.1.23"]
        self.exfil_hosts = ["10.0.1.21", "10.0.1.24", "10.0.1.25"]
        self.hard_negative_host = "10.0.1.14"

        # Global Simulation Clock: 12 hours (43,200 seconds)
        self.base_timestamp = 1780000000.0
        self.total_duration_s = 43200.0

    def _create_record(
        self,
        host: str,
        domain: str,
        timestamp: float,
        label: int,
        provenance: str,
        query_type: int = 1
    ) -> Dict[str, Any]:
        """Builds a schema-compliant DNSentinel dataset record."""
        packet_size = len(domain) + 40
        raw_event = {
            "timestamp": timestamp,
            "source_ip": host,
            "domain": domain,
            "query_type": query_type,
            "packet_size": packet_size
        }
        features = self.extractor.extract(raw_event)
        features["timestamp"] = round(timestamp, 4)

        return {
            "timestamp": round(timestamp, 4),
            "host": host,
            "domain": domain,
            "features": features,
            "provenance": provenance,
            "label": label
        }

    def _generate_random_payload(self, encoding: str, length: int) -> str:
        """Generates synthetic high-entropy payload strings."""
        if encoding == "hex":
            chars = "0123456789abcdef"
        elif encoding == "base32":
            chars = "abcdefghijklmnopqrstuvwxyz234567"
        elif encoding == "base64":
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        else:
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(self.rng.choice(chars) for _ in range(length))

    def generate_benign_traffic(self, target_count: int = 4000) -> List[Dict[str, Any]]:
        """
        Generates 4,000 legitimate queries across 16 hosts with realistic inter-arrival
        times, category distributions, and authentic hard-negative preservation.
        """
        records: List[Dict[str, Any]] = []

        # 1. Insert the two authentic hard-negative observations from lab_trace_benign.jsonl
        # Preserving m92xk7qlp81zr4.danger.edu with original label 0
        hn_times = [
            self.base_timestamp + 14200.5,
            self.base_timestamp + 14267.3
        ]
        for t in hn_times:
            rec = self._create_record(
                host=self.hard_negative_host,
                domain="m92xk7qlp81zr4.danger.edu",
                timestamp=t,
                label=0,
                provenance="authentic_lab_trace_hard_negative_danger_edu",
                query_type=1
            )
            records.append(rec)

        remaining_count = target_count - len(records)
        base_per_host = remaining_count // len(self.hosts)
        extra = remaining_count % len(self.hosts)

        # Realistic query-type weighting: 88% A, 10% AAAA, 2% TXT
        qtypes = [1] * 88 + [28] * 10 + [16] * 2

        # 5 distinct browsing sessions per host across the 10-hour (35,000s) timeline
        session_starts = [60.0, 7200.0, 14400.0, 21600.0, 28800.0]

        for h_idx, host in enumerate(self.hosts):
            host_queries = base_per_host + (1 if h_idx < extra else 0)
            queries_per_session = host_queries // len(session_starts)
            rem_q = host_queries % len(session_starts)

            for s_idx, s_start in enumerate(session_starts):
                s_count = queries_per_session + (1 if s_idx < rem_q else 0)
                current_time = self.base_timestamp + s_start + self.rng.uniform(10.0, 300.0)

                for _ in range(s_count):
                    if self.rng.random() < 0.12:
                        dt = self.rng.uniform(45.0, 180.0)  # Reading / idle pause
                    else:
                        dt = self.rng.expovariate(1.0 / 7.5)  # Active web browsing
                        dt = max(0.4, min(dt, 35.0))

                    current_time += dt
                    domain = self.rng.choice(ALL_BENIGN_DOMAINS)
                    qtype = self.rng.choice(qtypes)

                    rec = self._create_record(
                        host=host,
                        domain=domain,
                        timestamp=current_time,
                        label=0,
                        provenance="synthetic_enterprise_benign_ambient",
                        query_type=qtype
                    )
                    records.append(rec)

        return records

    def generate_low_and_slow_c2(self, target_count: int = 500) -> List[Dict[str, Any]]:
        """
        Generates 500 stealthy C2 beacon queries with 30s-180s spacing and
        dictionary-mimicry lexical structure across 3 campaigns and 3 hosts.
        """
        records: List[Dict[str, Any]] = []
        campaign_keys = ["c2_stealth_alpha", "c2_stealth_beta", "c2_stealth_gamma"]
        base_per_camp = target_count // len(campaign_keys)
        rem = target_count % len(campaign_keys)

        for i, camp_key in enumerate(campaign_keys):
            camp = MALICIOUS_CAMPAIGNS[camp_key]
            host = self.c2_hosts[i % len(self.c2_hosts)]
            camp_count = base_per_camp + (1 if i < rem else 0)
            # Beacons distributed across the full 10-hour timeline
            current_time = self.base_timestamp + 600.0 + (i * 400.0)
            step_dt = 32000.0 / camp_count

            for _ in range(camp_count):
                dt = step_dt * self.rng.uniform(0.75, 1.25)
                current_time += dt
                domain = self.rng.choice(camp["domains"])

                rec = self._create_record(
                    host=host,
                    domain=domain,
                    timestamp=current_time,
                    label=1,
                    provenance=f"campaign_{camp_key}",
                    query_type=camp["qtype"]
                )
                records.append(rec)

        return records

    def generate_high_entropy_tunneling(self, target_count: int = 1000) -> List[Dict[str, Any]]:
        """
        Generates 1,000 high-entropy tunneling burst queries representing Base32,
        Base64, Hex, and random payload encodings across multiple SLDs.
        """
        records: List[Dict[str, Any]] = []
        tunnel_campaigns = [
            "tunnel_hex_delta", "tunnel_base32_epsilon",
            "tunnel_base64_zeta", "tunnel_random_theta"
        ]
        base_per_camp = target_count // len(tunnel_campaigns)
        rem = target_count % len(tunnel_campaigns)

        # Tunneling occurs in intermittent burst episodes across the full 10 hours
        burst_windows = [2400.0, 9600.0, 16800.0, 24000.0, 31200.0]

        for idx, camp_key in enumerate(tunnel_campaigns):
            camp = MALICIOUS_CAMPAIGNS[camp_key]
            host = self.tunnel_hosts[idx % len(self.tunnel_hosts)]
            queries_remaining = base_per_camp + (1 if idx < rem else 0)
            bursts_count = len(burst_windows)
            queries_per_burst = queries_remaining // bursts_count

            for b_idx, b_start in enumerate(burst_windows):
                b_size = queries_per_burst if b_idx < bursts_count - 1 else queries_remaining
                queries_remaining -= b_size
                current_time = self.base_timestamp + b_start + (idx * 300.0) + self.rng.uniform(10.0, 60.0)

                qps = self.rng.uniform(camp["burst_qps_range"][0], camp["burst_qps_range"][1])
                dt = 1.0 / qps

                for _ in range(b_size):
                    current_time += dt
                    sld = self.rng.choice(camp["slds"])
                    label_len = self.rng.randint(18, 36)
                    payload = self._generate_random_payload(camp["encoding"], label_len)
                    domain = f"{payload}.{sld}"

                    rec = self._create_record(
                        host=host,
                        domain=domain,
                        timestamp=current_time,
                        label=1,
                        provenance=f"campaign_{camp_key}",
                        query_type=camp["qtype"]
                    )
                    records.append(rec)

        return records

    def generate_subdomain_exfiltration(self, target_count: int = 500) -> List[Dict[str, Any]]:
        """
        Generates 500 dynamic subdomain exfiltration queries testing sequential
        payload staging across multiple hosts and domains.
        """
        records: List[Dict[str, Any]] = []
        exfil_campaigns = ["exfil_chunk_eta", "exfil_chunk_iota"]
        base_per_camp = target_count // len(exfil_campaigns)
        rem = target_count % len(exfil_campaigns)

        # Exfiltration sessions distributed across hours 1.5, 4.5, 7.5, 9.2
        exfil_windows = [5400.0, 16200.0, 27000.0, 33000.0]

        for idx, camp_key in enumerate(exfil_campaigns):
            camp = MALICIOUS_CAMPAIGNS[camp_key]
            host = self.exfil_hosts[idx % len(self.exfil_hosts)]
            total_camp_q = base_per_camp + (1 if idx < rem else 0)
            q_per_session = total_camp_q // len(exfil_windows)
            q_rem = total_camp_q % len(exfil_windows)

            global_seq = 0
            for w_idx, w_start in enumerate(exfil_windows):
                session_q = q_per_session + (1 if w_idx < q_rem else 0)
                current_time = self.base_timestamp + w_start + (idx * 600.0) + self.rng.uniform(10.0, 60.0)

                for _ in range(session_q):
                    dt = self.rng.uniform(camp["interval_range"][0], camp["interval_range"][1])
                    current_time += dt

                    if "pattern" in camp:
                        if "{:08x}" in camp["pattern"]:
                            rand_hex = self.rng.getrandbits(32)
                            domain = camp["pattern"].format(global_seq, rand_hex, camp["sld"])
                        else:
                            domain = camp["pattern"].format(global_seq, camp["sld"])
                    else:
                        domain = f"chunk{global_seq:03d}.{camp['sld']}"

                    global_seq += 1

                    rec = self._create_record(
                        host=host,
                        domain=domain,
                        timestamp=current_time,
                        label=1,
                        provenance=f"campaign_{camp_key}",
                        query_type=camp["qtype"]
                    )
                    records.append(rec)

        return records

    def build_dataset(self) -> List[Dict[str, Any]]:
        """
        Assembles all constituent traffic categories, resolves host timestamp
        ordering, and interleaves the stream into a globally causal dataset.
        """
        print(f"[*] Initializing DNSentinel ML Benchmark Generation with Random Seed: {self.seed}")

        benign = self.generate_benign_traffic(target_count=4000)
        c2 = self.generate_low_and_slow_c2(target_count=500)
        tunnel = self.generate_high_entropy_tunneling(target_count=1000)
        exfil = self.generate_subdomain_exfiltration(target_count=500)

        all_records = benign + c2 + tunnel + exfil

        # Group by host and sort each host's stream strictly chronologically
        host_streams = defaultdict(list)
        for r in all_records:
            host_streams[r["host"]].append(r)

        # Ensure no identical timestamps exist for any single host
        unified_stream = []
        for host, stream in host_streams.items():
            stream.sort(key=lambda x: x["timestamp"])
            # Deconflict any microsecond collisions
            last_ts = 0.0
            for r in stream:
                if r["timestamp"] <= last_ts:
                    r["timestamp"] = round(last_ts + 0.005, 4)
                    r["features"]["timestamp"] = r["timestamp"]
                last_ts = r["timestamp"]
                unified_stream.append(r)

        # Final global sort by timestamp for realistic temporal interleaving
        unified_stream.sort(key=lambda x: x["timestamp"])
        return unified_stream


# ==============================================================================
# 3. COMPREHENSIVE DATASET VALIDATOR
# ==============================================================================

class BenchmarkDatasetValidator:
    """
    Validates dataset integrity, schema consistency, absence of shortcut
    leakage, class balance, and campaign separation.
    """

    @staticmethod
    def validate(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        report = {}
        total = len(records)
        report["total_records"] = total

        # 1. Target Volume Check
        if not (5000 <= total <= 7000):
            raise AssertionError(f"Total records {total} outside required range [5000, 7000]")

        # 2. Class Balance
        labels = Counter(r["label"] for r in records)
        report["class_distribution"] = dict(labels)
        report["benign_count"] = labels[0]
        report["malicious_count"] = labels[1]
        report["benign_ratio"] = round(labels[0] / total, 4)
        report["malicious_ratio"] = round(labels[1] / total, 4)

        if labels[0] < 3000 or labels[1] < 1500:
            raise AssertionError(f"Unexpected class distribution: {dict(labels)}")

        # 3. Host Diversity & Shortcut Check
        hosts_all = set(r["host"] for r in records)
        hosts_benign = set(r["host"] for r in records if r["label"] == 0)
        hosts_malicious = set(r["host"] for r in records if r["label"] == 1)

        report["unique_hosts_total"] = len(hosts_all)
        report["unique_hosts_benign"] = len(hosts_benign)
        report["unique_hosts_malicious"] = len(hosts_malicious)

        if len(hosts_all) < 10:
            raise AssertionError(f"Insufficient host diversity: {len(hosts_all)} hosts < 10 required")

        # Verify NO host is exclusively malicious (prevents IP shortcut)
        malicious_only_hosts = hosts_malicious - hosts_benign
        if malicious_only_hosts:
            raise AssertionError(f"Found exclusively malicious hosts: {malicious_only_hosts}")

        # 4. Domain Diversity & Cross-Class Overlap Check
        domains_all = set(r["domain"] for r in records)
        domains_benign = set(r["domain"] for r in records if r["label"] == 0)
        domains_malicious = set(r["domain"] for r in records if r["label"] == 1)

        report["unique_domains_total"] = len(domains_all)
        report["unique_domains_benign"] = len(domains_benign)
        report["unique_domains_malicious"] = len(domains_malicious)

        overlap = domains_benign.intersection(domains_malicious)
        report["cross_class_domain_overlap"] = len(overlap)
        if overlap:
            raise AssertionError(f"Cross-class domain overlap detected: {overlap}")

        # 5. Schema & Missing Values Check
        required_top_keys = {"timestamp", "host", "domain", "features", "provenance", "label"}
        required_feat_keys = {
            "domain_length", "subdomain_length", "label_count", "entropy",
            "digit_ratio", "alphabet_ratio", "special_character_ratio",
            "packet_size", "query_type", "timestamp"
        }

        for i, r in enumerate(records):
            missing_top = required_top_keys - set(r.keys())
            if missing_top:
                raise AssertionError(f"Row {i} missing top keys: {missing_top}")
            missing_feat = required_feat_keys - set(r["features"].keys())
            if missing_feat:
                raise AssertionError(f"Row {i} missing feature keys: {missing_feat}")

        # 6. Chronological Order per Host Check
        host_last_ts = {}
        for r in records:
            h = r["host"]
            ts = r["timestamp"]
            if h in host_last_ts and ts <= host_last_ts[h]:
                raise AssertionError(f"Non-monotonic timestamp on host {h}: {ts} <= {host_last_ts[h]}")
            host_last_ts[h] = ts

        # 7. Global Timestamp Ordering Check
        ts_list = [r["timestamp"] for r in records]
        if ts_list != sorted(ts_list):
            raise AssertionError("Global dataset stream is not sorted chronologically")

        report["time_span_seconds"] = round(max(ts_list) - min(ts_list), 2)
        report["time_span_hours"] = round(report["time_span_seconds"] / 3600.0, 2)

        # 8. Hard-Negative Danger.edu Check
        danger_records = [
            r for r in records
            if "m92xk7qlp81zr4.danger.edu" in r["domain"]
        ]
        report["danger_edu_records_count"] = len(danger_records)
        if len(danger_records) != 2:
            raise AssertionError(f"Expected 2 danger.edu records, found {len(danger_records)}")
        for dr in danger_records:
            if dr["label"] != 0:
                raise AssertionError("danger.edu record must be labeled 0 (benign)")

        # 9. Campaign Diversity
        campaigns = Counter(
            r["provenance"] for r in records if r["label"] == 1
        )
        report["malicious_campaigns"] = dict(campaigns)
        if len(campaigns) < 5:
            raise AssertionError(f"Insufficient campaign diversity: only {len(campaigns)} campaigns")

        # 10. Shortcut Check: Timestamp range overlap
        benign_ts = [r["timestamp"] for r in records if r["label"] == 0]
        mal_ts = [r["timestamp"] for r in records if r["label"] == 1]
        report["benign_time_range"] = (min(benign_ts), max(benign_ts))
        report["malicious_time_range"] = (min(mal_ts), max(mal_ts))

        # Both classes must span at least 80% of the timeline
        total_span = max(ts_list) - min(ts_list)
        mal_span = max(mal_ts) - min(mal_ts)
        ben_span = max(benign_ts) - min(benign_ts)
        if mal_span < 0.7 * total_span or ben_span < 0.7 * total_span:
            raise AssertionError("One class is confined to a temporal sub-block")

        report["status"] = "PASSED"
        return report


# ==============================================================================
# 4. MAIN EXECUTION PIPELINE
# ==============================================================================

def main():
    generator = DNSentinelMLBenchmarkGenerator(seed=RANDOM_SEED)
    records = generator.build_dataset()

    # Write output to JSONL
    print(f"[*] Writing {len(records)} records to {OUTPUT_FILE.name}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # Compute SHA-256
    with open(OUTPUT_FILE, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"[+] Output File: {OUTPUT_FILE.name}")
    print(f"[+] SHA-256 Digest: {file_hash}")

    # Validate generated dataset
    print("[*] Running rigorous benchmark validation...")
    validation_report = BenchmarkDatasetValidator.validate(records)
    print("\n================ BENCHMARK VALIDATION REPORT ================")
    print(json.dumps(validation_report, indent=2))
    print("=============================================================")


if __name__ == "__main__":
    main()
