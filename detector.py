# =============================================================================
# Name        : ANIQ NAJMUDDIN BIN SHARIFUDDIN
# Matric No   : BI23110059
# Course      : KP35203 - Network Programming
# Assignment  : Individual Project Assignment (20%)
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# File        : detector.py
# Description : ARP spoofing detection engine. Maintains a trusted IP-to-MAC
#               mapping table and raises alerts when a new ARP Reply attempts
#               to remap an already-known IP address to a different MAC —
#               the hallmark of an ARP poisoning / spoofing attack.
# =============================================================================

import threading
import time
from colorama import Fore, Style


class ARPDetector:
    """
    Detection engine that tracks the ARP table state of the local network.

    How ARP Spoofing Works:
    -----------------------
    A malicious host sends unsolicited (gratuitous) ARP Replies claiming that
    a legitimate IP (e.g., the default gateway 192.168.1.1) maps to the
    attacker's MAC address. Victims update their ARP cache with this false
    mapping, causing traffic to be redirected through the attacker (MITM).

    Detection Strategy:
    -------------------
    1. Build a TRUSTED table of IP → MAC mappings from observed ARP traffic.
    2. On every subsequent ARP Reply, compare the claimed MAC against the
       trusted table.
    3. If the IP is known but the MAC has changed → ARP spoofing alert.
    4. New IPs are added to the trust table automatically on first seen.
    """

    def __init__(self, alert_callback, defender_callback=None):
        """
        Initialise the detector.

        Args:
            alert_callback   (func): Called with an alert dict when spoofing is detected.
                                     Signature: alert_callback(alert: dict)
            defender_callback(func): Optional. Called with the alert dict so the
                                     defender can issue a corrective ARP.
                                     Signature: defender_callback(alert: dict)
        """
        self.alert_callback    = alert_callback
        self.defender_callback = defender_callback

        # Thread-safe lock to protect the ARP table from race conditions
        # between the sniffer thread and the API thread.
        self._lock = threading.Lock()

        # Trust table: { "192.168.1.1": "aa:bb:cc:dd:ee:ff", ... }
        self._arp_table: dict[str, str] = {}

        # History of all detected spoofing events (kept in memory for the dashboard)
        self._alerts: list[dict] = []

        # Count of total packets processed (for stats)
        self._packet_count: int = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process_packet(self, arp_info: dict):
        """
        Main entry point called by the sniffer for every captured ARP Reply.
        Thread-safe: acquires the lock before reading/writing the ARP table.

        Args:
            arp_info (dict): Parsed ARP packet fields from sniffer.py.
                             Keys: sender_ip, sender_mac, target_ip, target_mac
        """
        sender_ip  = arp_info.get("sender_ip")
        sender_mac = arp_info.get("sender_mac")

        # Ignore malformed or incomplete packets
        if not sender_ip or not sender_mac:
            return

        with self._lock:
            self._packet_count += 1

            if sender_ip in self._arp_table:
                known_mac = self._arp_table[sender_ip]

                if known_mac.lower() != sender_mac.lower():
                    # -------------------------------------------------------
                    # SPOOFING DETECTED: The IP is known but the MAC changed.
                    # -------------------------------------------------------
                    alert = self._build_alert(sender_ip, sender_mac, known_mac)
                    self._alerts.append(alert)

                    # Notify the logger / API
                    self.alert_callback(alert)

                    # Notify the defender to issue a corrective ARP
                    if self.defender_callback:
                        self.defender_callback(alert)
                # else: MAC matches — packet is legitimate, no action needed

            else:
                # First time we see this IP → add to trust table
                self._arp_table[sender_ip] = sender_mac
                print(
                    f"{Fore.GREEN}[DETECTOR]{Style.RESET_ALL} "
                    f"Learned: {sender_ip} → {sender_mac}"
                )

    def get_arp_table(self) -> dict:
        """Return a snapshot of the current trusted ARP table (thread-safe)."""
        with self._lock:
            return dict(self._arp_table)

    def get_alerts(self) -> list:
        """Return a copy of all recorded alerts (thread-safe)."""
        with self._lock:
            return list(self._alerts)

    def get_stats(self) -> dict:
        """Return runtime statistics for the dashboard."""
        with self._lock:
            return {
                "packets_processed": self._packet_count,
                "known_hosts":       len(self._arp_table),
                "total_alerts":      len(self._alerts),
            }

    def load_trusted_table(self, table: dict):
        """
        Optionally pre-seed the trust table with known-good IP→MAC mappings.
        Useful when the operator knows the legitimate MAC of the gateway.

        Args:
            table (dict): { "ip": "mac", ... }
        """
        with self._lock:
            self._arp_table.update(table)
            print(
                f"{Fore.CYAN}[DETECTOR]{Style.RESET_ALL} "
                f"Loaded {len(table)} pre-trusted ARP entries."
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_alert(self, ip: str, spoofed_mac: str, real_mac: str) -> dict:
        """
        Construct a structured alert dictionary for a detected spoofing event.

        Args:
            ip          (str): The IP address being spoofed.
            spoofed_mac (str): The forged MAC address sent by the attacker.
            real_mac    (str): The legitimate MAC address from the trust table.

        Returns:
            dict: Alert payload with all relevant fields.
        """
        alert = {
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "ARP_SPOOFING",
            "severity":    "HIGH",
            "ip":          ip,
            "real_mac":    real_mac,
            "spoofed_mac": spoofed_mac,
            "message": (
                f"ARP Spoofing detected! IP {ip} was mapped to {real_mac} "
                f"but an ARP Reply claims it is {spoofed_mac}."
            ),
        }

        print(
            f"\n{Fore.RED}[!!!] ARP SPOOFING DETECTED{Style.RESET_ALL}\n"
            f"  IP          : {ip}\n"
            f"  Legit MAC   : {real_mac}\n"
            f"  Spoofed MAC : {spoofed_mac}\n"
            f"  Time        : {alert['timestamp']}\n"
        )

        return alert
