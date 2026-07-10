# =============================================================================
# Name        : ANIQ NAJMUDDIN BIN SHARIFUDDIN
# Matric No   : BI23110059
# Course      : KP35203 - Network Programming
# Assignment  : Individual Project Assignment (20%)
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# File        : sniffer.py
# Description : ARP packet capture module using Scapy. Sniffs all ARP traffic
#               on the specified network interface and forwards each packet
#               to the detection engine via a shared callback.
# =============================================================================

import threading
from scapy.all import sniff, ARP, Ether
from colorama import Fore, Style


class ARPSniffer:
    """
    Passive ARP sniffer that captures ARP packets on a given network interface.
    Runs in a dedicated daemon thread so it does not block the main program.

    ARP (Address Resolution Protocol) operates at Layer 2/3 boundary.
    It maps IP addresses to MAC addresses. By sniffing ARP traffic, we can
    observe every IP-to-MAC association being broadcast on the LAN.
    """

    def __init__(self, interface: str, packet_callback):
        """
        Initialise the sniffer.

        Args:
            interface (str):        Network interface to listen on (e.g. 'eth0').
            packet_callback (func): Function called for every captured ARP packet.
                                    Signature: callback(packet)
        """
        self.interface = interface
        self.packet_callback = packet_callback
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ARPSniffer")

    def start(self):
        """Start sniffing in background thread."""
        print(f"{Fore.CYAN}[SNIFFER]{Style.RESET_ALL} Starting ARP capture on interface: {self.interface}")
        self._thread.start()

    def stop(self):
        """Signal the sniffer to stop gracefully."""
        print(f"{Fore.CYAN}[SNIFFER]{Style.RESET_ALL} Stopping ARP capture...")
        self._stop_event.set()

    def is_running(self) -> bool:
        """Return True if the sniffer thread is alive."""
        return self._thread.is_alive()

    def _run(self):
        """
        Internal method executed in the sniffer thread.
        Uses Scapy's sniff() with a BPF filter for ARP-only traffic.
        The stop_filter lambda checks the stop event each packet so the
        thread can exit cleanly when stop() is called.
        """
        sniff(
            iface=self.interface,
            filter="arp",                           # BPF filter: capture ARP frames only
            prn=self._process_packet,               # Callback for every captured packet
            store=False,                            # Do not buffer packets in memory
            stop_filter=lambda _: self._stop_event.is_set()  # Exit condition
        )

    def _process_packet(self, packet):
        """
        Called by Scapy for every captured ARP packet.
        Validates the packet structure, then forwards it to the detection callback.

        ARP packet fields of interest:
            op    -> 1 = ARP Request, 2 = ARP Reply
            psrc  -> Sender IP address
            hwsrc -> Sender MAC address
            pdst  -> Target IP address
            hwdst -> Target MAC address
        """
        # We are only interested in ARP Reply packets (op=2).
        # ARP Replies are what attackers forge during spoofing attacks.
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            arp_layer = packet[ARP]

            # Build a clean dictionary with the relevant ARP fields
            arp_info = {
                "sender_ip":  arp_layer.psrc,    # IP claiming to own the MAC
                "sender_mac": arp_layer.hwsrc,   # MAC address of the sender
                "target_ip":  arp_layer.pdst,    # IP of the intended recipient
                "target_mac": arp_layer.hwdst,   # MAC of the intended recipient
            }

            # Also include raw Ethernet frame source if available (extra verification)
            if packet.haslayer(Ether):
                arp_info["frame_src_mac"] = packet[Ether].src

            # Hand off to the detection engine
            self.packet_callback(arp_info)
