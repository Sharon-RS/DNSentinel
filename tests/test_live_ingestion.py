"""
Automated unit and integration tests for DNSentinel live telemetry ingestion.

Validates:
1. Valid POST /api/ingest requests store live events with is_replay=False.
2. Ingested live events preserve actual timestamp, host, destination IP, domain, query type, and packet size.
3. Dashboard metrics (total_queries, risk counters, alerts buffer) update correctly.
4. Malformed/invalid JSON returns HTTP 400 Bad Request.
5. Missing required fields (event, features, result, source_ip, domain) return HTTP 400 Bad Request.
6. Oversized request payloads exceeding the limit return HTTP 400 Bad Request.
7. End-to-end telemetry forwarding from DNSentinel.process_dns_event() to dashboard.
8. Non-blocking error handling: detector never crashes when dashboard is unreachable, slow, or fails.
9. Forwarding can be disabled via constructor and CLI options.
"""

import argparse
import io
import json
import socket
import sys
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from dashboard.adapter import DashboardAdapter
from dashboard.app import DashboardHTTPRequestHandler, ADAPTER
from main import DNSentinel
from experiments.context import IsolatedEvaluationContext


class DelayedOrErrorHandler(BaseHTTPRequestHandler):
    """Mock handler simulating server errors and timeouts for resilience testing."""

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path == "/timeout":
            time.sleep(0.5)
            self.send_response(HTTPStatus.OK)
            self.end_headers()
        elif self.path == "/error":
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Internal server crash"}')
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()


class TestLiveTelemetryIngestion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start in-process dashboard server on an ephemeral loopback port
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHTTPRequestHandler)
        cls.server_port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.server_port}"
        cls.ingest_url = f"{cls.base_url}/api/ingest"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        ADAPTER.clear_session()

    def test_valid_live_ingestion_endpoint(self):
        """Verifies successful ingestion of a live event and accurate dashboard telemetry."""
        payload = {
            "event": {
                "timestamp": "2026-10-13T12:00:00.000000",
                "source_ip": "192.168.1.50",
                "destination_ip": "1.1.1.1",
                "domain": "test.example.com",
                "query_type": 1,
                "packet_size": 75,
                "transaction_id": 4321
            },
            "features": {
                "entropy": 2.5,
                "domain_length": 16,
                "digit_ratio": 0.0,
                "query_rate": 0.5
            },
            "result": {
                "behavior_score": 15.0,
                "risk_level": "NORMAL",
                "confidence": 0.90,
                "recommendation": "No immediate action required.",
                "baseline_updated": True
            }
        }

        req = urllib.request.Request(
            self.ingest_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "success")
            self.assertIn("id", data)
            self.assertIsInstance(data["id"], int)
            ingested_id = data["id"]

        # 1. Summary checks: live traffic, not demo replay
        summary = ADAPTER.get_summary()
        self.assertEqual(summary["total_queries"], 1)
        self.assertEqual(summary["normal_count"], 1)
        self.assertEqual(summary["suspicious_count"], 0)
        self.assertFalse(summary["is_demo_replay"])

        # 2. Live events buffer checks
        events = ADAPTER.get_live_events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["id"], ingested_id)
        self.assertFalse(ev["is_replay"])
        self.assertEqual(ev["timestamp"], "2026-10-13T12:00:00.000000")
        self.assertEqual(ev["host"], "192.168.1.50")
        self.assertEqual(ev["destination_ip"], "1.1.1.1")
        self.assertEqual(ev["domain"], "test.example.com")
        self.assertEqual(ev["query_type"], 1)
        self.assertEqual(ev["query_type_name"], "A")
        self.assertEqual(ev["packet_size"], 75)
        self.assertEqual(ev["entropy"], 2.5)
        self.assertEqual(ev["domain_length"], 16)
        self.assertEqual(ev["behavior_score"], 15.0)
        self.assertEqual(ev["risk_level"], "NORMAL")
        self.assertEqual(ev["baseline_status"], "Learned")

        # 3. Alerts buffer should be empty for NORMAL risk
        self.assertEqual(len(ADAPTER.get_alerts()), 0)

    def test_live_ingestion_suspicious_creates_alert(self):
        """Verifies that high-risk or suspicious live events populate the alerts buffer with is_replay=False."""
        payload = {
            "event": {
                "timestamp": "2026-10-13T12:01:00.000000",
                "source_ip": "10.0.0.5",
                "destination_ip": "8.8.8.8",
                "domain": "tunnel.attacker.lab",
                "query_type": 16,
                "packet_size": 250
            },
            "features": {
                "entropy": 4.85,
                "domain_length": 35,
                "digit_ratio": 0.25,
                "query_rate": 12.0
            },
            "result": {
                "behavior_score": 85.0,
                "risk_level": "HIGH_RISK",
                "confidence": 0.95,
                "recommendation": "Potential DNS tunneling detected.",
                "baseline_updated": False,
                "ml_enabled": True,
                "cascade_path": "FAST_PATH_MALICIOUS",
                "cascade_decision": "MALICIOUS",
                "detection_source": "DIRECT_FAST_PATH"
            }
        }

        req = urllib.request.Request(
            self.ingest_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

        summary = ADAPTER.get_summary()
        self.assertEqual(summary["total_queries"], 1)
        self.assertEqual(summary["high_risk_count"], 1)
        self.assertFalse(summary["is_demo_replay"])

        alerts = ADAPTER.get_alerts()
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertFalse(alert["is_replay"])
        self.assertEqual(alert["host"], "10.0.0.5")
        self.assertEqual(alert["domain"], "tunnel.attacker.lab")
        self.assertEqual(alert["risk_level"], "HIGH_RISK")
        self.assertEqual(alert["query_type_name"], "TXT")
        self.assertEqual(alert["detection_source"], "DIRECT_FAST_PATH")

    def test_invalid_json_returns_bad_request(self):
        """Verifies that malformed JSON payloads return HTTP 400."""
        req = urllib.request.Request(
            self.ingest_url,
            data=b"{\"event\": {broken json missing close",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        err = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err)
        ctx.exception.close()

    def test_missing_fields_returns_bad_request(self):
        """Verifies that omitted required objects or event fields return HTTP 400."""
        test_cases = [
            # Missing top-level 'event'
            {"features": {}, "result": {}},
            # Missing top-level 'features'
            {"event": {"source_ip": "1.1.1.1", "domain": "a.com"}, "result": {}},
            # Missing top-level 'result'
            {"event": {"source_ip": "1.1.1.1", "domain": "a.com"}, "features": {}},
            # Missing 'source_ip' in event
            {"event": {"domain": "a.com"}, "features": {}, "result": {}},
            # Empty 'source_ip'
            {"event": {"source_ip": "   ", "domain": "a.com"}, "features": {}, "result": {}},
            # Missing 'domain' in event
            {"event": {"source_ip": "1.1.1.1"}, "features": {}, "result": {}},
            # Empty 'domain'
            {"event": {"source_ip": "1.1.1.1", "domain": ""}, "features": {}, "result": {}},
            # Non-dict event
            {"event": "not-a-dict", "features": {}, "result": {}},
            # Non-dict features
            {"event": {"source_ip": "1.1.1.1", "domain": "a.com"}, "features": "not-a-dict", "result": {}},
            # Non-dict result
            {"event": {"source_ip": "1.1.1.1", "domain": "a.com"}, "features": {}, "result": "not-a-dict"},
            # Non-dict payload (JSON array)
            [{"event": {}, "features": {}, "result": {}}],
        ]

        for idx, payload in enumerate(test_cases):
            with self.subTest(case=idx):
                req = urllib.request.Request(
                    self.ingest_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 400, f"Case {idx} did not return HTTP 400")
                err = json.loads(ctx.exception.read().decode("utf-8"))
                self.assertIn("error", err)
                ctx.exception.close()

    def test_oversized_payload_returns_bad_request(self):
        """Verifies that request bodies exceeding the 64 KB limit are rejected with HTTP 400."""
        # Create ~70 KB payload
        oversized_data = json.dumps({
            "event": {"source_ip": "10.0.0.1", "domain": "test.com"},
            "features": {},
            "result": {},
            "padding": "A" * 70000
        }).encode("utf-8")

        self.assertGreater(len(oversized_data), 65536)

        req = urllib.request.Request(
            self.ingest_url,
            data=oversized_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        err = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err)
        ctx.exception.close()

    def test_detector_forwarding_end_to_end_heuristic(self):
        """Verifies that DNSentinel with heuristic pipeline successfully forwards live telemetry."""
        with IsolatedEvaluationContext(), unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
            detector = DNSentinel(
                pipeline_type="heuristic",
                enable_dashboard=True,
                dashboard_url=self.ingest_url,
                forward_timeout=2.0
            )

            raw_event = {
                "timestamp": "2026-10-13T12:05:00.000000",
                "source_ip": "10.0.0.1",
                "destination_ip": "192.168.1.1",
                "domain": "live.test.example.com",
                "query_type": 1,
                "packet_size": 68,
                "transaction_id": 9999
            }

            res = detector.process_dns_event(raw_event)
            self.assertIsNotNone(res)
            self.assertIn("risk_level", res)

            # Check that dashboard received the event
            events = ADAPTER.get_live_events()
            self.assertEqual(len(events), 1)
            ev = events[0]
            self.assertFalse(ev["is_replay"])
            self.assertEqual(ev["host"], "10.0.0.1")
            self.assertEqual(ev["domain"], "live.test.example.com")
            self.assertEqual(ev["packet_size"], 68)

    def test_detector_forwarding_end_to_end_cascade(self):
        """Verifies that DNSentinel with cascade pipeline forwards ML telemetry correctly."""
        with IsolatedEvaluationContext(), unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
            detector = DNSentinel(
                pipeline_type="cascade",
                enable_dashboard=True,
                dashboard_url=self.ingest_url,
                forward_timeout=2.0
            )

            raw_event = {
                "timestamp": "2026-10-13T12:06:00.000000",
                "source_ip": "10.0.0.2",
                "destination_ip": "192.168.1.1",
                "domain": "live.cascade.attacker.lab",
                "query_type": 1,
                "packet_size": 120,
                "transaction_id": 8888
            }

            res = detector.process_dns_event(raw_event)
            self.assertIsNotNone(res)

            events = ADAPTER.get_live_events()
            self.assertEqual(len(events), 1)
            ev = events[0]
            self.assertFalse(ev["is_replay"])
            self.assertEqual(ev["host"], "10.0.0.2")
            self.assertEqual(ev["domain"], "live.cascade.attacker.lab")
            self.assertTrue(ev["ml_enabled"])

    def test_detector_disabled_forwarding(self):
        """Verifies that setting enable_dashboard=False disables HTTP forwarding completely."""
        with IsolatedEvaluationContext(), unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
            # Point to a nonexistent host/port; if it attempted HTTP, it would fail
            detector = DNSentinel(
                pipeline_type="heuristic",
                enable_dashboard=False,
                dashboard_url="http://127.0.0.1:59999/api/ingest"
            )

            raw_event = {
                "timestamp": "2026-10-13T12:07:00.000000",
                "source_ip": "10.0.0.3",
                "destination_ip": "192.168.1.1",
                "domain": "disabled.forwarding.test",
                "query_type": 1,
                "packet_size": 60,
            }

            res = detector.process_dns_event(raw_event)
            self.assertIsNotNone(res)

            # Adapter should have received nothing
            self.assertEqual(len(ADAPTER.get_live_events()), 0)

            # Direct forward call returns False
            success = detector.forward_to_dashboard(raw_event, {}, res)
            self.assertFalse(success)

    def test_detector_forwarding_resilience_when_dashboard_unreachable(self):
        """Verifies that detector never crashes when the dashboard is unreachable (connection refused)."""
        with IsolatedEvaluationContext(), unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
            # Port with no listening process
            unused_port = 59981
            detector = DNSentinel(
                pipeline_type="heuristic",
                enable_dashboard=True,
                dashboard_url=f"http://127.0.0.1:{unused_port}/api/ingest",
                forward_timeout=0.2
            )

            raw_event = {
                "timestamp": "2026-10-13T12:08:00.000000",
                "source_ip": "10.0.0.4",
                "destination_ip": "192.168.1.1",
                "domain": "resilience.test.domain",
                "query_type": 1,
                "packet_size": 64,
            }

            # Must not raise any exceptions
            res = detector.process_dns_event(raw_event)
            self.assertIsNotNone(res)

            # Direct call returns False cleanly
            self.assertFalse(detector.forward_to_dashboard(raw_event, {}, res))

    def test_detector_forwarding_resilience_on_mock_errors_and_timeouts(self):
        """Verifies non-crashing behavior on HTTP 500 server errors and connection timeouts."""
        mock_server = ThreadingHTTPServer(("127.0.0.1", 0), DelayedOrErrorHandler)
        mock_port = mock_server.server_address[1]
        mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
        mock_thread.start()

        try:
            with IsolatedEvaluationContext(), unittest.mock.patch("sys.stdout", new_callable=io.StringIO):
                raw_event = {
                    "timestamp": "2026-10-13T12:09:00.000000",
                    "source_ip": "10.0.0.5",
                    "destination_ip": "192.168.1.1",
                    "domain": "error.test.domain",
                    "query_type": 1,
                    "packet_size": 64,
                }

                # 1. Test 500 error resilience
                detector_err = DNSentinel(
                    pipeline_type="heuristic",
                    enable_dashboard=True,
                    dashboard_url=f"http://127.0.0.1:{mock_port}/error",
                    forward_timeout=0.5
                )
                res1 = detector_err.process_dns_event(raw_event)
                self.assertIsNotNone(res1)
                self.assertFalse(detector_err.forward_to_dashboard(raw_event, {}, res1))

                # 2. Test timeout resilience (short timeout: 0.05s against 0.5s delay)
                detector_timeout = DNSentinel(
                    pipeline_type="heuristic",
                    enable_dashboard=True,
                    dashboard_url=f"http://127.0.0.1:{mock_port}/timeout",
                    forward_timeout=0.05
                )
                res2 = detector_timeout.process_dns_event(raw_event)
                self.assertIsNotNone(res2)
                self.assertFalse(detector_timeout.forward_to_dashboard(raw_event, {}, res2))
        finally:
            mock_server.shutdown()
            mock_server.server_close()

    def test_cli_argument_parsing(self):
        """Verifies CLI argument parsing for dashboard options and pipelines."""
        parser = argparse.ArgumentParser(description="DNSentinel: Adaptive DNS Tunneling Detection")
        parser.add_argument("--pipeline", choices=["heuristic", "cascade"], default="heuristic")
        parser.add_argument("--dashboard-url", default=DNSentinel.DEFAULT_DASHBOARD_URL)
        parser.add_argument("--no-dashboard", action="store_true")
        parser.add_argument("--dashboard-timeout", type=float, default=DNSentinel.DEFAULT_FORWARD_TIMEOUT)
        parser.add_argument("--interface", default="ens33")

        # 1. Default arguments
        args_default = parser.parse_args([])
        self.assertEqual(args_default.pipeline, "heuristic")
        self.assertEqual(args_default.dashboard_url, "http://127.0.0.1:8080/api/ingest")
        self.assertFalse(args_default.no_dashboard)
        self.assertEqual(args_default.dashboard_timeout, 1.0)
        self.assertEqual(args_default.interface, "ens33")

        # 2. Explicit custom arguments
        args_custom = parser.parse_args([
            "--pipeline", "cascade",
            "--dashboard-url", "http://10.0.0.5:9000/api/ingest",
            "--no-dashboard",
            "--dashboard-timeout", "2.5",
            "--interface", "eth0"
        ])
        self.assertEqual(args_custom.pipeline, "cascade")
        self.assertEqual(args_custom.dashboard_url, "http://10.0.0.5:9000/api/ingest")
        self.assertTrue(args_custom.no_dashboard)
        self.assertEqual(args_custom.dashboard_timeout, 2.5)
        self.assertEqual(args_custom.interface, "eth0")


if __name__ == "__main__":
    unittest.main()
