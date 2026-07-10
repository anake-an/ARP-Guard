# ARP Guard — ARP Spoofing Detector & Active Defender

**Student  :** ANIQ NAJMUDDIN BIN SHARIFUDDIN  
**Matric   :** BI23110059  
**Course   :** KP35203 - Network Programming  
**Assignment:** Individual Project Assignment (20%)  
**Lecturer :** Dr. Gohar Rahman  

---

## Overview

ARP Guard is a Python-based network security tool that detects and actively counters ARP
spoofing attacks in real time. The system passively monitors ARP traffic on a chosen
network interface, builds a trusted IP-to-MAC mapping table, and immediately raises an
alert the moment a packet contradicts a known-good mapping. When spoofing is confirmed,
it does not just log the event — it fires a corrective gratuitous ARP burst to restore the
legitimate mapping across the LAN. A live web dashboard provides the operator full
visibility over all detected events.

---

## Project Structure

```
arp_guard/
├── main.py              # Entry point — wires all modules and starts threads
├── sniffer.py           # Raw ARP packet capture via Scapy (Layer 2, BPF filter)
├── detector.py          # Detection engine — trust table + MAC mismatch logic
├── defender.py          # Active defense — corrective gratuitous ARP burst
├── logger.py            # Structured logging to daily log files + memory buffer
├── api.py               # Flask REST API + Flask-SocketIO WebSocket server
├── simulate_attack.py   # Attack simulator for testing and verification
├── requirements.txt     # Python dependencies
└── templates/
    └── dashboard.html   # Live browser dashboard (Socket.IO + REST polling)
```

---

## Network Programming Concepts Demonstrated

| Concept | Where Used |
|---|---|
| Raw Packet Capture (Layer 2) | `sniffer.py` — Scapy `sniff()` with BPF filter `"arp"` |
| Client-Server Model | `api.py` — Flask HTTP server; browser as client |
| RESTful API | `api.py` — 5 JSON endpoints (GET ×4, POST ×1) |
| WebSocket Communication | `api.py` — Flask-SocketIO real-time push events |
| Multi-Threading | `main.py` — 3 concurrent threads with `threading.Lock` |
| Gratuitous ARP / Layer 2 Frames | `defender.py` — Scapy `sendp()` Ethernet frame injection |

---

## Installation

> Requires Python 3.10+ and administrator / root privileges for raw packet capture.  
> On Windows, install [Npcap](https://npcap.com) first.

```bash
cd arp_guard
pip install -r requirements.txt
```

---

## Usage

### Start ARP Guard (detection + active defense)

```bash
# Auto-detect interface
python main.py

# Specify interface
python main.py --iface "Ethernet"

# Pre-seed a trusted gateway entry
python main.py --iface "Ethernet" --trust "192.168.1.1=aa:bb:cc:dd:ee:ff"

# Detection-only mode (no corrective ARP broadcast)
python main.py --iface "Ethernet" --no-defend
```

Open the live dashboard at: **http://127.0.0.1:5000**

### Run the Attack Simulator (in a second terminal)

```bash
python simulate_attack.py --iface "Ethernet" --target-ip 10.10.10.10 --fake-mac bb:bb:bb:bb:bb:bb
```

The simulator sends forged ARP Reply packets to trigger the detection engine, allowing
the full pipeline (detection → alert → defense → dashboard update) to be verified.

---

## REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | System running state and aggregate statistics |
| GET | `/api/arp-table` | Full trusted IP-to-MAC mapping table |
| GET | `/api/alerts` | Recent spoofing alerts, newest first |
| GET | `/api/events` | Recent system events from the logger |
| POST | `/api/trust` | Inject a trusted IP-MAC entry at runtime |

---

## Libraries Used

| Library | Version | Purpose |
|---|---|---|
| Scapy | 2.5.0 | Raw packet capture and crafting |
| Flask | 3.0.3 | HTTP web server and REST API |
| Flask-SocketIO | 5.3.6 | WebSocket server for real-time dashboard push |
| colorama | 0.4.6 | Cross-platform ANSI colour terminal output |
| netifaces2 | latest | Network interface enumeration |

All libraries are open-source and properly cited in the project report.

---

## How Detection Works

1. The sniffer captures all ARP Reply packets (op=2) on the chosen interface.
2. On first sight of an IP, the detector records it as trusted.
3. Every subsequent ARP Reply for that IP is compared against the trusted MAC.
4. A MAC mismatch triggers an alert immediately — no waiting, no thresholds.
5. The defender sends 5 corrective gratuitous ARP packets to the broadcast address.
6. A 10-second per-IP cooldown prevents the defender from flooding the network.
7. All events are pushed to the browser dashboard via WebSocket within one second.

---

## Warning

This tool and its attack simulator are for **educational and testing purposes only**.  
Only run on networks you own or have explicit written permission to test.
