"""
DNSentinel SOC Dashboard Application Server
Lightweight, zero-dependency HTTP server delivering real-time telemetry,
SOC monitoring, host baselines, and Phase 4 research evaluation insights.
"""

import argparse
import json
import mimetypes
import os
import sys
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.config import Config
from dashboard.adapter import DashboardAdapter

STATIC_DIR = Path(__file__).resolve().parent / "static"
ADAPTER = DashboardAdapter()


class DashboardHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving JSON REST APIs and static dashboard assets.
    """

    def log_message(self, format, *args):
        # Suppress verbose access logs during high-frequency polling
        if args and isinstance(args[0], str):
            first_arg = args[0]
            if "/api/live" in first_arg or "/api/summary" in first_arg or "/api/status" in first_arg:
                return
        try:
            formatted = format % args
        except Exception:
            formatted = f"{format} {args}"
        sys.stderr.write(f"[{self.log_date_time_string()}] {formatted}\n")

    def send_json_response(self, data: Any, status_code: int = HTTPStatus.OK):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def send_file_response(self, file_path: Path):
        if not file_path.exists() or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File Not Found")
            return

        content_type, _ = mimetypes.guess_type(str(file_path))
        if not content_type:
            content_type = "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading file: {str(e)}")

    # ------------------------------------------------------------------
    # GET Endpoints
    # ------------------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query_params = parse_qs(parsed.query)

        # 1. API Endpoints
        if path == "/api/status":
            self.send_json_response(ADAPTER.get_system_status())
            return

        if path == "/api/pipeline_mode":
            self.send_json_response({"pipeline_mode": ADAPTER.get_pipeline_mode()})
            return

        if path == "/api/summary":
            self.send_json_response(ADAPTER.get_summary())
            return

        if path == "/api/live":
            limit = int(query_params.get("limit", [50])[0])
            since_id = int(query_params.get("since_id", [0])[0])
            self.send_json_response(ADAPTER.get_live_events(limit=limit, since_id=since_id))
            return

        if path == "/api/alerts":
            raw_limit = query_params.get("limit", [50])[0]
            try:
                limit = int(raw_limit)
                if limit <= 0:
                    limit = 50
                elif limit > 200:
                    limit = 200
            except (ValueError, TypeError):
                limit = 50
            self.send_json_response(ADAPTER.get_alerts(limit=limit))
            return

        if path == "/api/hosts":
            self.send_json_response(ADAPTER.get_all_host_summaries())
            return

        if path.startswith("/api/host/"):
            host_ip = path.replace("/api/host/", "").strip()
            details = ADAPTER.get_host_profile_details(host_ip)
            if details is None:
                self.send_json_response({"error": "Host profile not found"}, status_code=HTTPStatus.NOT_FOUND)
            else:
                self.send_json_response(details)
            return

        if path == "/api/organization":
            self.send_json_response(ADAPTER.get_organization_profile_details())
            return

        if path == "/api/research":
            self.send_json_response(ADAPTER.get_research_results())
            return

        # 2. Phase 7B Publication Figures (Safe Read-Only Route)
        if path.startswith("/figures/"):
            filename = path.replace("/figures/", "", 1).strip()
            figures_dir = (Config.PROJECT_ROOT / "experiments" / "results" / "figures").resolve()
            candidate = (figures_dir / filename).resolve()
            if candidate.is_relative_to(figures_dir) and candidate.is_file() and candidate.suffix.lower() == ".png":
                self.send_file_response(candidate)
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Figure Not Found")
            return

        # 3. Static Assets
        if path in ("/", "/index.html"):
            self.send_file_response(STATIC_DIR / "index.html")
            return

        if path in ("/style.css", "/static/style.css"):
            self.send_file_response(STATIC_DIR / "style.css")
            return

        if path in ("/app.js", "/static/app.js"):
            self.send_file_response(STATIC_DIR / "app.js")
            return

        # Fallback check static directory
        safe_rel_path = path.lstrip("/")
        candidate = (STATIC_DIR / safe_rel_path).resolve()
        if candidate.is_relative_to(STATIC_DIR) and candidate.is_file():
            self.send_file_response(candidate)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Resource not found")

    # ------------------------------------------------------------------
    # POST Endpoints
    # ------------------------------------------------------------------

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(post_data.decode("utf-8")) if post_data else {}
        except json.JSONDecodeError:
            self.send_json_response({"error": "Invalid JSON"}, status_code=HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/replay":
            dataset_name = payload.get("trace", "tunnel")
            max_records = int(payload.get("max_records", 150))
            result = ADAPTER.replay_dataset(dataset_name, max_records=max_records)
            self.send_json_response(result)
            return

        if path == "/api/test_query":
            host = payload.get("host", "10.0.0.1")
            domain = payload.get("domain", "")
            query_type = int(payload.get("query_type", 1))
            result = ADAPTER.process_test_query(host=host, domain=domain, query_type=query_type)
            status_code = HTTPStatus.BAD_REQUEST if "error" in result else HTTPStatus.OK
            self.send_json_response(result, status_code=status_code)
            return

        if path == "/api/clear":
            ADAPTER.clear_session()
            self.send_json_response({"status": "cleared", "message": "In-memory telemetry buffer reset"})
            return

        if path == "/api/pipeline_mode":
            mode = payload.get("mode", "heuristic")
            updated = ADAPTER.set_pipeline_mode(mode)
            self.send_json_response({"status": "success", "pipeline_mode": updated})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Action not found")


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Starts the ThreadingHTTPServer for the dashboard."""
    server_address = (host, port)
    try:
        httpd = ThreadingHTTPServer(server_address, DashboardHTTPRequestHandler)
    except OSError as e:
        if port != 8081:
            print(f"[!] Port {port} busy, attempting fallback to port 8081...")
            server_address = (host, 8081)
            httpd = ThreadingHTTPServer(server_address, DashboardHTTPRequestHandler)
            port = 8081
        else:
            raise e

    print("=" * 80)
    print(" DNSENTINEL REAL-TIME SOC DASHBOARD & RESEARCH MONITOR")
    print("=" * 80)
    print(f"[*] Server listening on : http://{host}:{port}")
    print(f"[*] Local Web Access   : http://127.0.0.1:{port}")
    print("[*] HTTP Polling Engine: Ready (0.0000ms latency overhead on detection core)")
    print("[*] Static Files Path  : " + str(STATIC_DIR))
    print("[*] Monitored Baselines : " + str(Config.DATA_DIR))
    print("=" * 80)
    print("[*] Press Ctrl+C to terminate dashboard server cleanly.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping DNSentinel dashboard server...")
        httpd.server_close()
        print("[+] Dashboard stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNSentinel SOC Dashboard Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host IP (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port number (default: 8080)")
    args = parser.parse_args()

    run_dashboard(host=args.host, port=args.port)
