# =============================================================================
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# Author      : Aniq Najmuddin bin Sharifuddin
# File        : main.py
# Description : Entry point and orchestrator for the ARP Guard system.
#               Initialises all modules, wires their callbacks together,
#               and starts the sniffer, defender, and web server threads.
#
# Usage:
#   sudo python main.py                        # Auto-detect interface
#   sudo python main.py --iface eth0           # Specify interface
#   sudo python main.py --iface eth0 --port 8080  # Custom dashboard port
#   sudo python main.py --trust 192.168.1.1=aa:bb:cc:dd:ee:ff  # Pre-trust
#
# Note: Root/Administrator privileges are required for raw packet capture.
# =============================================================================

import argparse
import sys
import signal
import threading
import time

from colorama import Fore, Style, init as colorama_init

from sniffer  import ARPSniffer
from detector import ARPDetector
from defender import ARPDefender
from logger   import ARPLogger
import api as api_module

# Initialise colorama for cross-platform coloured terminal output
colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""
{Fore.CYAN}
  █████╗ ██████╗ ██████╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ███████║██████╔╝██████╔╝    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██╔══██║██╔══██╗██╔═══╝     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║  ██║██║  ██║██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{Style.RESET_ALL}
  {Fore.WHITE}ARP Spoofing Detector & Active Defender{Style.RESET_ALL}
  {Fore.YELLOW}Developed by Aniq Najmuddin bin Sharifuddin{Style.RESET_ALL}
"""


# ---------------------------------------------------------------------------
# Interface helper
# ---------------------------------------------------------------------------

def get_default_interface() -> str:
    """
    Attempt to auto-detect the primary active network interface.
    Falls back to 'eth0' if detection fails.

    Returns:
        str: Interface name (e.g. 'eth0', 'wlan0', 'ens33').
    """
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_gw = gateways.get("default", {})
        if netifaces.AF_INET in default_gw:
            return default_gw[netifaces.AF_INET][1]
    except Exception:
        pass
    return "eth0"


def parse_trust_entries(trust_args: list) -> dict:
    """
    Parse CLI --trust arguments into a dict of {ip: mac}.

    Expected format: "192.168.1.1=aa:bb:cc:dd:ee:ff"

    Args:
        trust_args (list): List of strings from --trust CLI flag.

    Returns:
        dict: Parsed IP→MAC mappings.
    """
    table = {}
    for entry in (trust_args or []):
        try:
            ip, mac = entry.split("=", 1)
            table[ip.strip()] = mac.strip()
        except ValueError:
            print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Ignoring invalid --trust entry: {entry}")
    return table


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """
    Entry point for ARP Guard.
    Parses CLI arguments, initialises all modules in the correct order,
    wires callback functions between them, starts the Flask API thread and
    the ARP sniffer thread, then keeps the main thread alive as the
    orchestrator — pushing periodic stats updates to the dashboard.
    """
    print(BANNER)

    # -----------------------------------------------------------------------
    # Argument parsing
    # -----------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="ARP Guard — ARP Spoofing Detector & Active Defender"
    )
    parser.add_argument(
        "--iface", "-i",
        type=str,
        default=None,
        help="Network interface to monitor (default: auto-detect)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=5000,
        help="Web dashboard port (default: 5000)"
    )
    parser.add_argument(
        "--trust", "-t",
        action="append",
        metavar="IP=MAC",
        help="Pre-trusted IP→MAC entry (can be repeated). E.g. --trust 192.168.1.1=aa:bb:cc:dd:ee:ff"
    )
    parser.add_argument(
        "--no-defend",
        action="store_true",
        help="Run in detection-only mode (disable active ARP defense)"
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory for log files (default: ./logs)"
    )

    args = parser.parse_args()

    # Resolve interface
    interface = args.iface or get_default_interface()
    print(f"{Fore.CYAN}[MAIN]{Style.RESET_ALL} Using interface: {Fore.WHITE}{interface}{Style.RESET_ALL}")

    # -----------------------------------------------------------------------
    # Initialise modules
    # -----------------------------------------------------------------------

    # 1. Logger — set up first so all other modules can log immediately
    logger = ARPLogger(log_dir=args.log_dir)
    logger.log_event(f"ARP Guard starting on interface {interface}")

    # 2. Defender — only if active mode is enabled
    if args.no_defend:
        defender = None
        print(f"{Fore.YELLOW}[MAIN]{Style.RESET_ALL} Active defense disabled (detection-only mode).")
        logger.log_event("Active defense disabled — running in detection-only mode", level="WARNING")
    else:
        defender = ARPDefender(interface=interface)

    # 3. Detector — wires to logger and defender callbacks
    def on_alert(alert: dict):
        """Callback: called by detector when spoofing is detected."""
        logger.log_alert(alert)
        api_module.push_alert(alert)  # Push to WebSocket dashboard

    def on_defend(alert: dict):
        """Callback: called by detector to trigger active defense."""
        if defender:
            defender.defend(alert)

    detector = ARPDetector(
        alert_callback=on_alert,
        defender_callback=on_defend if not args.no_defend else None
    )

    # Load any pre-trusted entries from CLI
    trusted_entries = parse_trust_entries(args.trust)
    if trusted_entries:
        detector.load_trusted_table(trusted_entries)

    # 4. Sniffer — feeds every ARP packet into the detector
    sniffer = ARPSniffer(
        interface=interface,
        packet_callback=detector.process_packet
    )

    # 5. API — inject detector and logger dependencies
    api_module.init_api(detector=detector, logger=logger)

    # -----------------------------------------------------------------------
    # Start threads — Flask first so dashboard is ready immediately
    # -----------------------------------------------------------------------

    # Flask-SocketIO server starts FIRST so the dashboard is reachable
    # while Scapy/sniffer finishes initialising in the background
    api_thread = threading.Thread(
        target=api_module.run_server,
        kwargs={"host": "0.0.0.0", "port": args.port},
        daemon=True,
        name="FlaskAPI"
    )
    api_thread.start()
    logger.log_event(f"Web dashboard started on port {args.port}")

    # Give Flask a moment to bind to the port before starting Scapy
    time.sleep(2)

    # Sniffer runs in its own daemon thread (started inside the class)
    sniffer.start()
    logger.log_event(f"ARP sniffer started on {interface}")

    # -----------------------------------------------------------------------
    # Graceful shutdown on Ctrl+C / SIGTERM
    # -----------------------------------------------------------------------
    def handle_shutdown(sig, frame):
        """
        Signal handler for SIGINT (Ctrl+C) and SIGTERM.
        Logs the shutdown event, stops the sniffer cleanly, and exits.
        """
        print(f"\n{Fore.YELLOW}[MAIN]{Style.RESET_ALL} Shutdown signal received — stopping ARP Guard…")
        logger.log_event("ARP Guard shutting down.")
        sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # -----------------------------------------------------------------------
    # Keep main thread alive — periodically push stats to dashboard
    # -----------------------------------------------------------------------
    print(
        f"\n{Fore.GREEN}[MAIN]{Style.RESET_ALL} ARP Guard is running.\n"
        f"       Dashboard → http://127.0.0.1:{args.port}\n"
        f"       Press Ctrl+C to stop.\n"
    )

    while True:
        time.sleep(5)
        # Push updated stats to all connected WebSocket clients
        stats = detector.get_stats()
        api_module.socketio.emit("stats_update", stats)


if __name__ == "__main__":
    main()
