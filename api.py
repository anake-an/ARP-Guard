# =============================================================================
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# Author      : Aniq Najmuddin bin Sharifuddin
# File        : api.py
# Description : Flask REST API and Flask-SocketIO WebSocket server.
#               Exposes live ARP table state, alert history, and system stats
#               via HTTP endpoints, and pushes real-time alerts to the
#               browser dashboard via WebSocket events.
# =============================================================================

import threading
import logging
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO
from colorama import Fore, Style

# Suppress Werkzeug's per-request access log lines (127.0.0.1 - - GET ...)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


# ---------------------------------------------------------------------------
# Flask application and SocketIO setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = "arp_guard_secret_2024"  # Required by Flask-SocketIO

# threading mode is used as the async backend for SocketIO.
# This avoids eventlet's monkey-patching which conflicts with Scapy's
# raw socket operations running in parallel threads.
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ---------------------------------------------------------------------------
# Module-level references (injected by main.py after all modules are created)
# ---------------------------------------------------------------------------

_detector = None   # ARPDetector instance
_logger   = None   # ARPLogger instance


def init_api(detector, logger):
    """
    Inject module dependencies into the API layer.
    Called once from main.py before the server starts.

    Args:
        detector: ARPDetector instance (provides ARP table & stats).
        logger:   ARPLogger instance (provides event history).
    """
    global _detector, _logger
    _detector = detector
    _logger   = logger
    print(f"{Fore.CYAN}[API]{Style.RESET_ALL} Flask API initialised.")


def push_alert(alert: dict):
    """
    Called by the logger/detector when a new spoofing alert is raised.
    Emits a WebSocket event so the dashboard updates instantly without polling.

    Args:
        alert (dict): Alert payload from detector.py.
    """
    socketio.emit("new_alert", alert)


# ---------------------------------------------------------------------------
# REST API routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the live dashboard HTML page."""
    return render_template("dashboard.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    """
    GET /api/status
    Returns the current operational status of ARP Guard.

    Response JSON:
        {
            "status": "running",
            "stats": { packets_processed, known_hosts, total_alerts }
        }
    """
    stats = _detector.get_stats() if _detector else {}
    return jsonify({"status": "running", "stats": stats})


@app.route("/api/arp-table", methods=["GET"])
def api_arp_table():
    """
    GET /api/arp-table
    Returns the current trusted IP-to-MAC mapping table.

    Response JSON:
        {
            "count": <int>,
            "table": [ { "ip": "...", "mac": "..." }, ... ]
        }
    """
    if not _detector:
        return jsonify({"error": "Detector not initialised"}), 503

    raw_table = _detector.get_arp_table()

    # Convert the flat dict to a list of objects for easier dashboard rendering
    table_list = [{"ip": ip, "mac": mac} for ip, mac in raw_table.items()]
    table_list.sort(key=lambda x: x["ip"])  # Sort by IP for consistent display

    return jsonify({"count": len(table_list), "table": table_list})


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    GET /api/alerts?limit=<n>
    Returns the most recent ARP spoofing alerts.

    Query params:
        limit (int, optional): Max number of alerts to return. Default: 50.

    Response JSON:
        {
            "count": <int>,
            "alerts": [ { alert dict }, ... ]
        }
    """
    if not _detector:
        return jsonify({"error": "Detector not initialised"}), 503

    limit  = request.args.get("limit", 50, type=int)
    alerts = _detector.get_alerts()[-limit:]
    alerts.reverse()  # Newest first

    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/events", methods=["GET"])
def api_events():
    """
    GET /api/events?limit=<n>
    Returns the most recent system events from the logger.

    Response JSON:
        {
            "count": <int>,
            "events": [ { event dict }, ... ]
        }
    """
    if not _logger:
        return jsonify({"error": "Logger not initialised"}), 503

    limit  = request.args.get("limit", 100, type=int)
    events = _logger.get_recent_events(limit)

    return jsonify({"count": len(events), "events": events})


@app.route("/api/trust", methods=["POST"])
def api_add_trust():
    """
    POST /api/trust
    Manually add a trusted IP-to-MAC entry to the detector's trust table.
    Useful for pre-seeding known-good gateway / server MACs.

    Request JSON:
        { "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff" }

    Response JSON:
        { "message": "Trust entry added", "ip": "...", "mac": "..." }
    """
    if not _detector:
        return jsonify({"error": "Detector not initialised"}), 503

    data = request.get_json()
    ip   = data.get("ip")
    mac  = data.get("mac")

    if not ip or not mac:
        return jsonify({"error": "Both 'ip' and 'mac' fields are required"}), 400

    _detector.load_trusted_table({ip: mac})
    return jsonify({"message": "Trust entry added", "ip": ip, "mac": mac}), 201


# ---------------------------------------------------------------------------
# WebSocket events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    """Client connected — send current stats immediately as a welcome payload."""
    if _detector:
        socketio.emit("stats_update", _detector.get_stats())
    print(f"{Fore.CYAN}[API]{Style.RESET_ALL} Dashboard client connected.")


@socketio.on("disconnect")
def on_disconnect():
    """Log when a dashboard browser client drops its Socket.IO connection."""
    print(f"{Fore.CYAN}[API]{Style.RESET_ALL} Dashboard client disconnected.")


@socketio.on("request_stats")
def on_request_stats():
    """Client requests a fresh stats snapshot (e.g., on page focus)."""
    if _detector:
        socketio.emit("stats_update", _detector.get_stats())


# ---------------------------------------------------------------------------
# Server startup helper
# ---------------------------------------------------------------------------

def run_server(host: str = "0.0.0.0", port: int = 5000):
    """
    Start the Flask-SocketIO server.
    Called from main.py in a background thread.

    Args:
        host (str): Bind address. 0.0.0.0 listens on all interfaces.
        port (int): TCP port for the web server.
    """
    print(
        f"{Fore.CYAN}[API]{Style.RESET_ALL} "
        f"Dashboard available at http://127.0.0.1:{port}"
    )
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)
