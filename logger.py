# =============================================================================
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# Author      : Aniq Najmuddin bin Sharifuddin
# File        : logger.py
# Description : Alert and event logging system. Writes all ARP spoofing alerts
#               and system events to a timestamped log file on disk while also
#               maintaining an in-memory ring buffer for the live dashboard.
# =============================================================================

import os
import time
import threading
from colorama import Fore, Style


class ARPLogger:
    """
    Centralised logging system for ARP Guard.

    Responsibilities:
        1. Write structured alert records to a rotating daily log file.
        2. Maintain a bounded in-memory list (ring buffer) of recent events
           so the Flask API can serve them to the dashboard without hitting disk.
        3. Provide a thread-safe interface since both the sniffer thread and
           the Flask request threads may write/read concurrently.

    Log file location: logs/arp_guard_YYYY-MM-DD.log
    """

    # Maximum number of events kept in the in-memory buffer
    MAX_BUFFER_SIZE = 500

    def __init__(self, log_dir: str = "logs"):
        """
        Initialise the logger.

        Args:
            log_dir (str): Directory where log files are stored.
                           Created automatically if it does not exist.
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # In-memory ring buffer of recent events (newest at the end)
        self._buffer: list[dict] = []
        self._lock = threading.Lock()

        print(
            f"{Fore.CYAN}[LOGGER]{Style.RESET_ALL} "
            f"Logging to directory: {os.path.abspath(log_dir)}"
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def log_alert(self, alert: dict):
        """
        Record an ARP spoofing alert — the primary logging method.
        Writes to both the in-memory buffer and the daily log file.

        Args:
            alert (dict): Alert payload from detector.py.
        """
        entry = {
            "level":     "ALERT",
            "timestamp": alert.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
            "type":      alert.get("type", "UNKNOWN"),
            "severity":  alert.get("severity", "HIGH"),
            "ip":        alert.get("ip", "N/A"),
            "real_mac":  alert.get("real_mac", "N/A"),
            "spoofed_mac": alert.get("spoofed_mac", "N/A"),
            "message":   alert.get("message", ""),
        }

        self._append_to_buffer(entry)
        self._write_to_file(entry)

    def log_event(self, message: str, level: str = "INFO"):
        """
        Record a general system event (startup, shutdown, interface change, etc.).

        Args:
            message (str): Human-readable event description.
            level   (str): Severity level — INFO, WARNING, ERROR.
        """
        entry = {
            "level":     level,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":      "SYSTEM_EVENT",
            "message":   message,
        }

        self._append_to_buffer(entry)
        self._write_to_file(entry)

        # Mirror to console with colour coding
        colour = {
            "INFO":    Fore.WHITE,
            "WARNING": Fore.YELLOW,
            "ERROR":   Fore.RED,
        }.get(level, Fore.WHITE)

        print(f"{colour}[LOGGER][{level}]{Style.RESET_ALL} {message}")

    def get_recent_events(self, limit: int = 100) -> list:
        """
        Return the most recent events from the in-memory buffer.
        Used by the Flask API to populate the dashboard.

        Args:
            limit (int): Maximum number of events to return (newest first).

        Returns:
            list: Slice of the buffer, reversed so newest events come first.
        """
        with self._lock:
            recent = list(self._buffer[-limit:])
            recent.reverse()
            return recent

    def get_alert_count(self) -> int:
        """Return the total number of ALERT-level entries in the buffer."""
        with self._lock:
            return sum(1 for e in self._buffer if e.get("level") == "ALERT")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _append_to_buffer(self, entry: dict):
        """
        Append an entry to the in-memory ring buffer.
        If the buffer exceeds MAX_BUFFER_SIZE, the oldest entry is dropped.
        """
        with self._lock:
            self._buffer.append(entry)
            if len(self._buffer) > self.MAX_BUFFER_SIZE:
                self._buffer.pop(0)  # Evict oldest entry

    def _write_to_file(self, entry: dict):
        """
        Append a formatted log line to today's daily log file.
        Each run of the program appends to the same daily file.

        Log line format:
            [YYYY-MM-DD HH:MM:SS] [LEVEL] [TYPE] message | extra_fields
        """
        today    = time.strftime("%Y-%m-%d")
        filename = os.path.join(self.log_dir, f"arp_guard_{today}.log")

        # Build the log line
        level   = entry.get("level", "INFO")
        ts      = entry.get("timestamp", "")
        etype   = entry.get("type", "")
        message = entry.get("message", "")

        # Append optional alert-specific fields
        extra = ""
        if level == "ALERT":
            extra = (
                f" | IP: {entry.get('ip')} "
                f"| Real MAC: {entry.get('real_mac')} "
                f"| Spoofed MAC: {entry.get('spoofed_mac')}"
            )

        line = f"[{ts}] [{level}] [{etype}] {message}{extra}\n"

        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(line)
        except IOError as e:
            # Non-fatal — print to stderr but do not crash the application
            print(f"{Fore.RED}[LOGGER] Failed to write log file: {e}{Style.RESET_ALL}")
