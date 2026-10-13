import argparse
import fcntl
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from src.capture.dns_capture import DNSCapture
from src.features.traditional_features import TraditionalFeatureExtractor
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.cascade_pipeline import CascadeDetectionPipeline


class DNSentinel:

    DEFAULT_DASHBOARD_URL = "http://127.0.0.1:8080/api/ingest"
    DEFAULT_FORWARD_TIMEOUT = 1.0  # seconds
    DEFAULT_LOCK_FILE = "/tmp/dnsentinel_detector.lock"

    def __init__(
        self,
        pipeline_type: str = "heuristic",
        enable_dashboard: bool = True,
        dashboard_url: str = DEFAULT_DASHBOARD_URL,
        forward_timeout: float = DEFAULT_FORWARD_TIMEOUT,
        lock_file: Optional[str] = DEFAULT_LOCK_FILE,
    ):
        self.extractor = TraditionalFeatureExtractor()

        if pipeline_type == "cascade":
            self.pipeline = CascadeDetectionPipeline()
        else:
            self.pipeline = DetectionPipeline()

        self.enable_dashboard = enable_dashboard
        self.dashboard_url = dashboard_url
        self.forward_timeout = forward_timeout
        self.lock_file = lock_file
        self._lock_fd: Optional[Any] = None

    def forward_to_dashboard(
        self,
        event: Dict[str, Any],
        features: Dict[str, Any],
        result: Dict[str, Any],
    ) -> bool:
        """
        Sends processed live telemetry to the dashboard ingestion endpoint via HTTP POST.
        Catches connection, HTTP, and timeout errors so packet capture is never interrupted.
        """
        if not self.enable_dashboard or not self.dashboard_url:
            return False

        payload = {
            "event": {
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip", "0.0.0.0"),
                "domain": event.get("domain"),
                "query_type": event.get("query_type", 1),
                "packet_size": event.get("packet_size", 0),
                "transaction_id": event.get("transaction_id"),
            },
            "features": features,
            "result": result,
        }

        try:
            req_data = json.dumps(
                payload,
                default=lambda o: o.item() if hasattr(o, "item") else str(o),
            ).encode("utf-8")
            req = urllib.request.Request(
                self.dashboard_url,
                data=req_data,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.forward_timeout) as resp:
                return resp.status in (200, 201)
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except Exception:
                pass
            return False
        except Exception:
            # Defensive non-blocking telemetry forwarding: never crash live capture
            return False

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

        if self.enable_dashboard:
            self.forward_to_dashboard(dns_event, features, result)

        return result

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

    def acquire_lock(self) -> None:
        """
        Acquires an exclusive, non-blocking advisory file lock via fcntl.flock
        to guarantee only a single detector instance captures on the host.
        """
        if not self.lock_file:
            return

        fd = None
        try:
            fd = open(self.lock_file, "a+")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd.seek(0)
            fd.truncate()
            fd.write(f"{os.getpid()}\n")
            fd.flush()
            self._lock_fd = fd
        except (IOError, OSError) as exc:
            if fd is not None:
                try:
                    fd.close()
                except Exception:
                    pass
            self._lock_fd = None
            raise RuntimeError(
                f"Another DNSentinel detector process is already running (locked '{self.lock_file}'). "
                "Only one detector instance may capture packets and forward telemetry at a time."
            ) from exc

    def release_lock(self) -> None:
        """
        Safely releases the detector instance file lock on shutdown.
        """
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self._lock_fd.close()
            except Exception:
                pass
            self._lock_fd = None

    def start(self, interface: str = "ens33"):

        self.acquire_lock()
        try:
            capture = DNSCapture(
                self.process_dns_event
            )
            capture.start(interface=interface)
        finally:
            self.release_lock()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="DNSentinel: Adaptive DNS Tunneling Detection")
    parser.add_argument(
        "--pipeline",
        choices=["heuristic", "cascade"],
        default="heuristic",
        help="Detection pipeline engine to use (default: heuristic)"
    )
    parser.add_argument(
        "--dashboard-url",
        default=DNSentinel.DEFAULT_DASHBOARD_URL,
        help=f"Dashboard ingestion API endpoint (default: {DNSentinel.DEFAULT_DASHBOARD_URL})"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable telemetry forwarding to the dashboard"
    )
    parser.add_argument(
        "--dashboard-timeout",
        type=float,
        default=DNSentinel.DEFAULT_FORWARD_TIMEOUT,
        help=f"Timeout in seconds for dashboard forwarding requests (default: {DNSentinel.DEFAULT_FORWARD_TIMEOUT})"
    )
    parser.add_argument(
        "--lock-file",
        default=DNSentinel.DEFAULT_LOCK_FILE,
        help=f"Path to single-instance detector lock file (default: {DNSentinel.DEFAULT_LOCK_FILE})"
    )
    parser.add_argument(
        "--interface",
        default="ens33",
        help="Network interface to monitor (default: ens33)"
    )
    args = parser.parse_args()

    detector = DNSentinel(
        pipeline_type=args.pipeline,
        enable_dashboard=not args.no_dashboard,
        dashboard_url=args.dashboard_url,
        forward_timeout=args.dashboard_timeout,
        lock_file=args.lock_file,
    )

    try:
        detector.start(interface=args.interface)
    except KeyboardInterrupt:
        print("\n[+] Detector stopped by user.")
    except RuntimeError as err:
        print(f"[!] Error: {err}", file=sys.stderr)
        sys.exit(1)
