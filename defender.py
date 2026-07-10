# =============================================================================
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# Author      : Aniq Najmuddin bin Sharifuddin
# File        : defender.py
# Description : Active ARP defense module. When a spoofing event is detected,
#               this module crafts and broadcasts corrective gratuitous ARP
#               Replies to restore the legitimate IP-to-MAC mapping across
#               all hosts on the LAN segment.
# =============================================================================

import time
import threading
from scapy.all import ARP, Ether, sendp
from colorama import Fore, Style


class ARPDefender:
    """
    Active defense module that responds to ARP spoofing events.

    Defense Mechanism — Gratuitous ARP:
    ------------------------------------
    A gratuitous ARP is an unsolicited ARP Reply where the sender IP and
    target IP are the same. It is used here to broadcast the CORRECT
    IP → MAC mapping to all hosts on the network, overwriting any poisoned
    ARP cache entries that the attacker may have installed.

    The corrective ARP packet is sent multiple times (burst) to ensure it
    reaches all devices before the attacker can re-poison them.

    Rate Limiting:
    --------------
    To avoid flooding the network, a cooldown period is enforced per IP.
    If the same IP is spoofed repeatedly, the defender only fires once
    per cooldown window.
    """

    # Number of corrective ARP packets to send per spoofing event
    BURST_COUNT   = 5

    # Seconds between each packet in the burst
    BURST_DELAY   = 0.2

    # Cooldown in seconds before the same IP can trigger another defense burst
    COOLDOWN_SECS = 10

    def __init__(self, interface: str):
        """
        Initialise the defender.

        Args:
            interface (str): Network interface to send corrective ARPs on (e.g. 'eth0').
        """
        self.interface = interface

        # Track last defense time per IP to enforce rate limiting
        # Format: { "192.168.1.1": <timestamp float> }
        self._last_defense: dict[str, float] = {}
        self._lock = threading.Lock()

    def defend(self, alert: dict):
        """
        Entry point called by the detector when ARP spoofing is confirmed.
        Checks the rate limit, then dispatches a background thread to send
        the corrective ARP burst without blocking the detection pipeline.

        Args:
            alert (dict): Alert payload from detector.py containing:
                          ip, real_mac, spoofed_mac, timestamp.
        """
        ip       = alert.get("ip")
        real_mac = alert.get("real_mac")

        if not ip or not real_mac:
            return  # Incomplete alert — skip

        with self._lock:
            now        = time.time()
            last_time  = self._last_defense.get(ip, 0)

            if now - last_time < self.COOLDOWN_SECS:
                # Still within cooldown window — do not re-flood
                print(
                    f"{Fore.YELLOW}[DEFENDER]{Style.RESET_ALL} "
                    f"Cooldown active for {ip} — skipping re-defense."
                )
                return

            # Record this defense attempt
            self._last_defense[ip] = now

        # Dispatch corrective burst in a separate thread to stay non-blocking
        t = threading.Thread(
            target=self._send_corrective_arp,
            args=(ip, real_mac),
            daemon=True,
            name=f"Defender-{ip}"
        )
        t.start()

    def _send_corrective_arp(self, ip: str, real_mac: str):
        """
        Constructs and broadcasts corrective gratuitous ARP Reply packets.

        Packet structure:
            Ethernet frame  → dst=ff:ff:ff:ff:ff:ff (broadcast to entire LAN)
            ARP payload     → op=2 (Reply), psrc=ip, hwsrc=real_mac
                              pdst=ip, hwdst=ff:ff:ff:ff:ff:ff

        Sending to the broadcast MAC ensures every device on the LAN segment
        receives and processes the corrective mapping.

        Args:
            ip       (str): The IP address whose mapping must be corrected.
            real_mac (str): The legitimate MAC address for that IP.
        """
        print(
            f"{Fore.MAGENTA}[DEFENDER]{Style.RESET_ALL} "
            f"Sending corrective ARP for {ip} → {real_mac} "
            f"({self.BURST_COUNT} packets)"
        )

        # Build the corrective gratuitous ARP packet
        ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac)
        arp_layer   = ARP(
            op=2,                        # ARP Reply (is-at)
            hwsrc=real_mac,              # Legitimate MAC
            psrc=ip,                     # IP being restored
            hwdst="ff:ff:ff:ff:ff:ff",  # Broadcast destination
            pdst=ip                      # Target is itself (gratuitous)
        )

        corrective_packet = ether_layer / arp_layer

        for i in range(self.BURST_COUNT):
            sendp(
                corrective_packet,
                iface=self.interface,
                verbose=False   # Suppress Scapy's per-packet output
            )
            time.sleep(self.BURST_DELAY)

        print(
            f"{Fore.GREEN}[DEFENDER]{Style.RESET_ALL} "
            f"Corrective ARP burst complete for {ip}."
        )
