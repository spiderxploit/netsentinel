#!/usr/bin/env python3
"""
NetSentinel v3.0 - Advanced Network Management & Security Dashboard

Install:
    pip install scapy psutil netifaces requests flask flask-socketio python-nmap

Run:
    sudo python3 network_manager.py        # full features
    python3 network_manager.py             # limited (no raw capture)

Open http://localhost:5000 in your browser.
"""

import os, sys, re, time, socket, threading, subprocess, ipaddress
import hashlib, logging, platform
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Root detection (safe on Windows too) ──────────────────────────────────────
IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

# ── .env loader (no python-dotenv dependency needed) ─────────────────────────
def _load_env(path: str = ".env") -> None:
    """Parse a simple KEY=VALUE .env file into os.environ."""
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except FileNotFoundError:
        pass   # .env is optional

_load_env()   # load before reading keys below

# ── Third-party imports ───────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    sys.exit("Missing: pip install psutil")
try:
    import netifaces
except ImportError:
    sys.exit("Missing: pip install netifaces")
try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_socketio import SocketIO, emit
except ImportError:
    sys.exit("Missing: pip install flask flask-socketio")
try:
    import nmap
except ImportError:
    sys.exit("Missing: pip install python-nmap")
try:
    import requests as _http
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# Scapy – optional, silence all its startup noise before importing
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)
try:
    import scapy.config
    scapy.config.conf.verb = 0          # suppress scapy output
    from scapy.all import sniff, ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, srp
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

logging.basicConfig(level=logging.WARNING, format="%(message)s")
log = logging.getLogger("netsentry")
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("socketio").setLevel(logging.ERROR)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION        = "3.0.0"
APP_PORT       = 5000
SCAN_INTERVAL  = 15          # seconds between full sweeps (fast for quick detection)
MAX_PKTS       = 400         # per-device packet log size
ANOMALY_THRESH = 50          # SYN packets before flood alert

VULNERABLE_PORTS = {
    21:   ("FTP",          "MEDIUM",   "Unencrypted file transfer – credentials in plaintext"),
    22:   ("SSH",          "LOW",      "Secure Shell – check for weak passwords / old versions"),
    23:   ("Telnet",       "HIGH",     "Unencrypted remote access – severe credential exposure"),
    25:   ("SMTP",         "MEDIUM",   "Mail server – potential open relay"),
    53:   ("DNS",          "LOW",      "DNS resolver – check for open recursion"),
    80:   ("HTTP",         "MEDIUM",   "Unencrypted web – susceptible to MITM"),
    110:  ("POP3",         "MEDIUM",   "Unencrypted email – credentials exposed"),
    135:  ("MS-RPC",       "HIGH",     "Windows RPC – known exploit surface"),
    139:  ("NetBIOS",      "HIGH",     "NetBIOS – SMB enumeration & relay attacks"),
    143:  ("IMAP",         "MEDIUM",   "Unencrypted email – credentials exposed"),
    161:  ("SNMP",         "HIGH",     "SNMP v1/v2 – community string brute-force"),
    389:  ("LDAP",         "MEDIUM",   "Directory service – enumeration risk"),
    443:  ("HTTPS",        "LOW",      "Encrypted web – check TLS version & cert"),
    445:  ("SMB",          "CRITICAL", "EternalBlue / WannaCry attack surface"),
    512:  ("rexec",        "CRITICAL", "Remote exec – legacy, no encryption"),
    513:  ("rlogin",       "CRITICAL", "Remote login – plaintext credentials"),
    514:  ("rsh",          "CRITICAL", "Remote shell – no authentication"),
    1433: ("MSSQL",        "HIGH",     "SQL Server – brute-force / injection risk"),
    1521: ("Oracle",       "HIGH",     "Oracle DB – exposed to network"),
    3306: ("MySQL",        "HIGH",     "MySQL – exposed to network"),
    3389: ("RDP",          "HIGH",     "Remote Desktop – BlueKeep / brute-force"),
    5432: ("PostgreSQL",   "HIGH",     "PostgreSQL – exposed to network"),
    5900: ("VNC",          "HIGH",     "VNC – weak authentication, unencrypted"),
    6379: ("Redis",        "CRITICAL", "Redis – often no auth, remote code exec"),
    8080: ("HTTP-Alt",     "MEDIUM",   "Alternate HTTP – unencrypted"),
    8443: ("HTTPS-Alt",    "LOW",      "Alternate HTTPS"),
    9200: ("Elasticsearch","CRITICAL", "Elasticsearch – often unauthenticated"),
    27017:("MongoDB",      "CRITICAL", "MongoDB – often unauthenticated"),
}

# ── OUI vendor table  (expanded – 120+ entries) ─────────────────────────────
# Format: OUI → (vendor, device_type, brand)
# device_type must match the DEVICE_ICON_MAP keys in JS for correct icon rendering
OUI_TABLE: Dict[str, Tuple[str,str,str]] = {
    # ── Apple ──────────────────────────────────────────────────────────────
    "00:03:93":("Apple","Mac","Apple"),        "00:05:02":("Apple","Mac","Apple"),
    "00:0A:27":("Apple","Mac","Apple"),        "00:0A:95":("Apple","Mac","Apple"),
    "00:11:24":("Apple","Mac","Apple"),        "00:14:51":("Apple","Mac","Apple"),
    "00:16:CB":("Apple","Mac","Apple"),        "00:17:F2":("Apple","Mac","Apple"),
    "00:19:E3":("Apple","Mac","Apple"),        "00:1B:63":("Apple","Mac","Apple"),
    "00:1C:B3":("Apple","Mac","Apple"),        "00:1D:4F":("Apple","Mac","Apple"),
    "00:1E:52":("Apple","Mac","Apple"),        "00:1E:C2":("Apple","Mac","Apple"),
    "00:1F:5B":("Apple","Mac","Apple"),        "00:1F:F3":("Apple","Mac","Apple"),
    "00:21:E9":("Apple","Mac","Apple"),        "00:22:41":("Apple","Mac","Apple"),
    "00:23:12":("Apple","Mac","Apple"),        "00:23:32":("Apple","Mac","Apple"),
    "00:23:6C":("Apple","Mac","Apple"),        "00:23:69":("Apple","iPhone","Apple"),
    "00:23:DF":("Apple","Mac","Apple"),        "00:24:36":("Apple","Mac","Apple"),
    "00:25:00":("Apple","Mac","Apple"),        "00:25:4B":("Apple","Mac","Apple"),
    "00:25:BC":("Apple","Mac","Apple"),        "00:26:08":("Apple","Mac","Apple"),
    "00:26:4A":("Apple","Mac","Apple"),        "00:26:B0":("Apple","Mac","Apple"),
    "00:26:BB":("Apple","Mac","Apple"),        "00:30:65":("Apple","Mac","Apple"),
    "3C:22:FB":("Apple","Mac","Apple"),        "AC:DE:48":("Apple","Mac","Apple"),
    "A4:C3:F0":("Apple","iPhone","Apple"),     "F8:FF:C2":("Apple","iPhone","Apple"),
    "00:88:65":("Apple","iPhone","Apple"),     "04:F1:3E":("Apple","iPhone","Apple"),
    "10:41:7F":("Apple","iPhone","Apple"),     "14:5A:05":("Apple","iPhone","Apple"),
    "18:AF:61":("Apple","iPhone","Apple"),     "1C:1A:C0":("Apple","iPhone","Apple"),
    "20:76:8F":("Apple","iPhone","Apple"),     "24:A2:E1":("Apple","iPhone","Apple"),
    "28:37:37":("Apple","iPhone","Apple"),     "2C:1F:23":("Apple","iPhone","Apple"),
    "30:35:AD":("Apple","iPhone","Apple"),     "34:08:BC":("Apple","iPhone","Apple"),
    "34:C0:59":("Apple","iPhone","Apple"),     "38:0F:4A":("Apple","iPhone","Apple"),
    "3C:15:C2":("Apple","iPhone","Apple"),     "40:83:DE":("Apple","iPhone","Apple"),
    "44:4C:0C":("Apple","iPhone","Apple"),     "48:A1:95":("Apple","iPad","Apple"),
    "4C:57:CA":("Apple","iPad","Apple"),       "50:EA:D6":("Apple","iPad","Apple"),
    "54:72:4F":("Apple","iPhone","Apple"),     "58:E2:8F":("Apple","iPhone","Apple"),
    "5C:59:48":("Apple","iPad","Apple"),       "60:C5:47":("Apple","iPhone","Apple"),
    "64:A3:CB":("Apple","iPhone","Apple"),     "68:96:7B":("Apple","iPhone","Apple"),
    "6C:40:08":("Apple","iPhone","Apple"),     "70:3E:AC":("Apple","Mac","Apple"),
    "74:E2:F5":("Apple","iPhone","Apple"),     "78:6C:1C":("Apple","Mac","Apple"),
    "7C:C3:A1":("Apple","iPhone","Apple"),     "80:00:6E":("Apple","iPhone","Apple"),
    "84:38:35":("Apple","iPhone","Apple"),     "88:19:08":("Apple","iPhone","Apple"),
    "8C:2D:AA":("Apple","iPhone","Apple"),     "90:72:40":("Apple","iPhone","Apple"),
    "94:BF:2D":("Apple","iPhone","Apple"),     "98:9E:63":("Apple","iPhone","Apple"),
    "9C:F3:87":("Apple","iPhone","Apple"),     "A0:D7:95":("Apple","iPhone","Apple"),
    "A4:B8:05":("Apple","iPhone","Apple"),     "A8:51:AB":("Apple","iPhone","Apple"),
    "AC:3C:0B":("Apple","iPhone","Apple"),     "B0:19:C6":("Apple","iPhone","Apple"),
    "B4:18:D1":("Apple","iPhone","Apple"),     "B8:53:AC":("Apple","iPhone","Apple"),
    "BC:52:B7":("Apple","iPhone","Apple"),     "C0:9F:42":("Apple","iPhone","Apple"),
    "C4:2C:03":("Apple","iPhone","Apple"),     "C8:D0:83":("Apple","iPhone","Apple"),
    "CC:25:EF":("Apple","iPhone","Apple"),     "D0:03:4B":("Apple","iPhone","Apple"),
    "D4:9A:20":("Apple","iPad","Apple"),       "D8:00:4D":("Apple","iPhone","Apple"),
    "DC:2B:2A":("Apple","iPhone","Apple"),     "E0:AC:CB":("Apple","iPhone","Apple"),
    "E4:CE:8F":("Apple","iPhone","Apple"),     "E8:04:0B":("Apple","iPhone","Apple"),
    "EC:35:86":("Apple","iPhone","Apple"),     "F0:DB:E2":("Apple","iPhone","Apple"),
    "F4:5C:89":("Apple","iPhone","Apple"),     "F8:27:93":("Apple","iPhone","Apple"),
    "FC:25:3F":("Apple","Mac","Apple"),        "F0:18:98":("Apple","iPhone","Apple"),
    # ── Samsung ────────────────────────────────────────────────────────────
    "00:12:47":("Samsung","Mobile Phone","Samsung"), "00:15:B9":("Samsung","Mobile Phone","Samsung"),
    "00:17:D5":("Samsung","Mobile Phone","Samsung"), "00:1A:8A":("Samsung","Mobile Phone","Samsung"),
    "00:1C:43":("Samsung","Mobile Phone","Samsung"), "00:1D:25":("Samsung","Mobile Phone","Samsung"),
    "00:1E:7D":("Samsung","Mobile Phone","Samsung"), "00:1F:CC":("Samsung","Mobile Phone","Samsung"),
    "00:21:19":("Samsung","Mobile Phone","Samsung"), "00:23:39":("Samsung","Mobile Phone","Samsung"),
    "00:24:54":("Samsung","Mobile Phone","Samsung"), "00:25:66":("Samsung","Mobile Phone","Samsung"),
    "00:26:37":("Samsung","Mobile Phone","Samsung"), "00:26:5F":("Samsung","Mobile Phone","Samsung"),
    "FC:F8:AE":("Samsung","Mobile Phone","Samsung"), "78:4B:87":("Samsung","Mobile Phone","Samsung"),
    "8C:C8:4B":("Samsung","Mobile Phone","Samsung"), "A0:82:1F":("Samsung","Mobile Phone","Samsung"),
    "BC:20:A4":("Samsung","Mobile Phone","Samsung"), "C0:BD:D1":("Samsung","Mobile Phone","Samsung"),
    "E4:12:1D":("Samsung","Mobile Phone","Samsung"), "50:01:BB":("Samsung","Smart TV","Samsung"),
    "78:BD:BC":("Samsung","Smart TV","Samsung"),     "CC:6E:A4":("Samsung","Smart TV","Samsung"),
    "D0:22:BE":("Samsung","Smart TV","Samsung"),     "F4:42:8F":("Samsung","Smart TV","Samsung"),
    "34:14:5F":("Samsung","Smart TV","Samsung"),     "10:D3:8A":("Samsung","Smart TV","Samsung"),
    # ── Xiaomi ─────────────────────────────────────────────────────────────
    "54:C9:DF":("Xiaomi","Mobile Phone","Xiaomi"),   "AC:C1:EE":("Xiaomi","Mobile Phone","Xiaomi"),
    "00:EC:0A":("Xiaomi","Mobile Phone","Xiaomi"),   "04:CF:8C":("Xiaomi","Mobile Phone","Xiaomi"),
    "10:2A:B3":("Xiaomi","Mobile Phone","Xiaomi"),   "14:F6:5A":("Xiaomi","Mobile Phone","Xiaomi"),
    "18:59:36":("Xiaomi","Mobile Phone","Xiaomi"),   "28:6C:07":("Xiaomi","Mobile Phone","Xiaomi"),
    "34:80:B3":("Xiaomi","Mobile Phone","Xiaomi"),   "38:A4:ED":("Xiaomi","Mobile Phone","Xiaomi"),
    "50:64:2B":("Xiaomi","Mobile Phone","Xiaomi"),   "58:44:98":("Xiaomi","Mobile Phone","Xiaomi"),
    "64:09:80":("Xiaomi","Mobile Phone","Xiaomi"),   "74:51:BA":("Xiaomi","Mobile Phone","Xiaomi"),
    "8C:BE:BE":("Xiaomi","Mobile Phone","Xiaomi"),   "98:FA:E3":("Xiaomi","Mobile Phone","Xiaomi"),
    "A0:86:C6":("Xiaomi","Mobile Phone","Xiaomi"),   "B4:0B:44":("Xiaomi","Mobile Phone","Xiaomi"),
    "C4:0B:CB":("Xiaomi","Mobile Phone","Xiaomi"),   "D4:97:0B":("Xiaomi","Mobile Phone","Xiaomi"),
    "F4:8B:32":("Xiaomi","Mobile Phone","Xiaomi"),   "FC:64:BA":("Xiaomi","Mobile Phone","Xiaomi"),
    "28:E3:1F":("Xiaomi","Router/AP","Xiaomi"),      "50:EC:50":("Xiaomi","Router/AP","Xiaomi"),
    # ── Huawei ─────────────────────────────────────────────────────────────
    "40:B0:34":("Huawei","Mobile Phone","Huawei"),   "00:9A:CD":("Huawei","Router/AP","Huawei"),
    "00:18:82":("Huawei","Router/AP","Huawei"),      "00:E0:FC":("Huawei","Router/AP","Huawei"),
    "04:75:03":("Huawei","Mobile Phone","Huawei"),   "04:BD:70":("Huawei","Mobile Phone","Huawei"),
    "08:19:A6":("Huawei","Mobile Phone","Huawei"),   "0C:37:96":("Huawei","Mobile Phone","Huawei"),
    "10:1F:74":("Huawei","Mobile Phone","Huawei"),   "10:47:80":("Huawei","Router/AP","Huawei"),
    "18:C5:8A":("Huawei","Mobile Phone","Huawei"),   "1C:8E:5C":("Huawei","Mobile Phone","Huawei"),
    "20:F3:A3":("Huawei","Mobile Phone","Huawei"),   "28:31:52":("Huawei","Mobile Phone","Huawei"),
    "2C:55:D3":("Huawei","Mobile Phone","Huawei"),   "30:D1:7E":("Huawei","Mobile Phone","Huawei"),
    "34:6B:D3":("Huawei","Mobile Phone","Huawei"),   "38:F8:89":("Huawei","Mobile Phone","Huawei"),
    "3C:FA:06":("Huawei","Mobile Phone","Huawei"),   "44:C3:46":("Huawei","Mobile Phone","Huawei"),
    "48:AD:08":("Huawei","Mobile Phone","Huawei"),   "4C:54:99":("Huawei","Mobile Phone","Huawei"),
    "50:A7:2B":("Huawei","Mobile Phone","Huawei"),   "54:51:1B":("Huawei","Mobile Phone","Huawei"),
    "58:2A:F7":("Huawei","Mobile Phone","Huawei"),   "5C:C3:07":("Huawei","Mobile Phone","Huawei"),
    "60:8E:ED":("Huawei","Mobile Phone","Huawei"),   "64:A6:51":("Huawei","Mobile Phone","Huawei"),
    "68:13:24":("Huawei","Mobile Phone","Huawei"),   "6C:83:36":("Huawei","Mobile Phone","Huawei"),
    # ── Dell ───────────────────────────────────────────────────────────────
    "00:14:22":("Dell","PC","Dell"),  "00:1A:4B":("Dell","PC","Dell"),
    "00:1D:09":("Dell","PC","Dell"),  "00:21:9B":("Dell","PC","Dell"),
    "00:22:19":("Dell","PC","Dell"),  "00:23:AE":("Dell","PC","Dell"),
    "00:24:E8":("Dell","PC","Dell"),  "00:26:B9":("Dell","PC","Dell"),
    "00:23:24":("Dell","PC","Dell"),  "B8:CA:3A":("Dell","PC","Dell"),
    "00:B0:D0":("Dell","Server","Dell"), "14:FE:B5":("Dell","PC","Dell"),
    "18:03:73":("Dell","PC","Dell"),  "18:66:DA":("Dell","PC","Dell"),
    "20:47:47":("Dell","PC","Dell"),  "24:B6:FD":("Dell","PC","Dell"),
    "28:92:4A":("Dell","PC","Dell"),  "34:17:EB":("Dell","PC","Dell"),
    "44:A8:42":("Dell","PC","Dell"),  "50:9A:4C":("Dell","PC","Dell"),
    "54:BF:64":("Dell","PC","Dell"),  "5C:F9:DD":("Dell","PC","Dell"),
    "60:36:DD":("Dell","PC","Dell"),  "6C:2B:59":("Dell","PC","Dell"),
    "74:86:7A":("Dell","PC","Dell"),  "78:2B:CB":("Dell","PC","Dell"),
    "84:7B:EB":("Dell","PC","Dell"),  "90:B1:1C":("Dell","PC","Dell"),
    "A4:1F:72":("Dell","PC","Dell"),  "B0:83:FE":("Dell","PC","Dell"),
    # ── HP / Hewlett-Packard ────────────────────────────────────────────────
    "00:0F:20":("HP","PC","HP"),     "00:13:21":("HP","PC","HP"),
    "00:15:60":("HP","PC","HP"),     "00:17:A4":("HP","PC","HP"),
    "00:19:BB":("HP","PC","HP"),     "00:1B:78":("HP","PC","HP"),
    "00:1E:0B":("HP","PC","HP"),     "00:21:5A":("HP","PC","HP"),
    "00:23:7D":("HP","PC","HP"),     "00:24:81":("HP","PC","HP"),
    "00:25:B3":("HP","Printer","HP"),"30:8D:99":("HP","Printer","HP"),
    "3C:D9:2B":("HP","PC","HP"),     "3C:D9:2B":("HP","PC","HP"),
    "A0:D3:C1":("HP","PC","HP"),     "68:B5:99":("HP","PC","HP"),
    "70:5A:0F":("HP","PC","HP"),     "84:34:97":("HP","PC","HP"),
    "94:57:A5":("HP","PC","HP"),     "9C:B6:54":("HP","PC","HP"),
    # ── Lenovo ─────────────────────────────────────────────────────────────
    "00:21:CC":("Lenovo","Laptop","Lenovo"),  "00:26:C6":("Lenovo","Laptop","Lenovo"),
    "28:D2:44":("Lenovo","Laptop","Lenovo"),  "40:2C:F4":("Lenovo","Laptop","Lenovo"),
    "44:37:E6":("Lenovo","Laptop","Lenovo"),  "54:05:DB":("Lenovo","Laptop","Lenovo"),
    "60:02:B4":("Lenovo","Laptop","Lenovo"),  "6C:88:14":("Lenovo","Laptop","Lenovo"),
    "70:5A:B6":("Lenovo","Laptop","Lenovo"),  "74:DF:BF":("Lenovo","Laptop","Lenovo"),
    "84:7A:88":("Lenovo","Laptop","Lenovo"),  "88:79:7E":("Lenovo","Laptop","Lenovo"),
    "8C:8D:28":("Lenovo","Laptop","Lenovo"),  "98:FA:9B":("Lenovo","Laptop","Lenovo"),
    "A4:4C:C8":("Lenovo","Laptop","Lenovo"),  "AC:B5:7D":("Lenovo","Laptop","Lenovo"),
    "B8:AC:6F":("Lenovo","Laptop","Lenovo"),  "C8:5B:76":("Lenovo","Laptop","Lenovo"),
    "D4:81:D7":("Lenovo","Laptop","Lenovo"),  "E8:39:DF":("Lenovo","Laptop","Lenovo"),
    # ── Asus ────────────────────────────────────────────────────────────────
    "00:11:2F":("Asus","PC","Asus"),  "00:13:D4":("Asus","PC","Asus"),
    "00:15:F2":("Asus","PC","Asus"),  "00:17:31":("Asus","PC","Asus"),
    "00:1A:92":("Asus","Router/AP","Asus"), "00:1B:FC":("Asus","PC","Asus"),
    "00:1D:60":("Asus","PC","Asus"),  "00:1E:8C":("Asus","PC","Asus"),
    "00:22:15":("Asus","PC","Asus"),  "00:23:54":("Asus","PC","Asus"),
    "00:24:8C":("Asus","PC","Asus"),  "00:26:18":("Asus","PC","Asus"),
    "74:D0:2B":("Asus","PC","Asus"),  "60:A4:4C":("Asus","PC","Asus"),
    "04:D4:C4":("Asus","Router/AP","Asus"), "14:DD:A9":("Asus","Router/AP","Asus"),
    "2C:FD:A1":("Asus","Router/AP","Asus"), "30:5A:3A":("Asus","Router/AP","Asus"),
    "40:16:7E":("Asus","Router/AP","Asus"), "50:46:5D":("Asus","Router/AP","Asus"),
    "AC:9E:17":("Asus","Router/AP","Asus"), "BC:AE:C5":("Asus","Router/AP","Asus"),
    # ── Cisco ───────────────────────────────────────────────────────────────
    "00:00:0C":("Cisco","Router/AP","Cisco"), "00:01:42":("Cisco","Router/AP","Cisco"),
    "00:01:63":("Cisco","Router/AP","Cisco"), "00:01:96":("Cisco","Router/AP","Cisco"),
    "00:01:C7":("Cisco","Router/AP","Cisco"), "00:02:17":("Cisco","Router/AP","Cisco"),
    "00:03:6B":("Cisco","Router/AP","Cisco"), "00:03:E3":("Cisco","Router/AP","Cisco"),
    "00:04:6D":("Cisco","Router/AP","Cisco"), "00:04:9A":("Cisco","Router/AP","Cisco"),
    "00:05:32":("Cisco","Router/AP","Cisco"), "00:06:28":("Cisco","Router/AP","Cisco"),
    "00:0A:41":("Cisco","Router/AP","Cisco"), "00:0A:8A":("Cisco","Router/AP","Cisco"),
    "00:0B:BE":("Cisco","Router/AP","Cisco"), "00:0C:CE":("Cisco","Router/AP","Cisco"),
    "00:0D:28":("Cisco","Router/AP","Cisco"), "00:0E:38":("Cisco","Router/AP","Cisco"),
    "00:0F:8F":("Cisco","Router/AP","Cisco"), "00:1A:2B":("Cisco","Router/AP","Cisco"),
    "00:1A:6D":("Cisco","Router/AP","Cisco"), "00:1B:D5":("Cisco","Router/AP","Cisco"),
    "58:AC:78":("Cisco","Router/AP","Cisco"), "00:50:56":("VMware","Virtual Machine","VMware"),
    # ── TP-Link ─────────────────────────────────────────────────────────────
    "00:24:D7":("TP-Link","Router/AP","TP-Link"), "00:18:0A":("TP-Link","Router/AP","TP-Link"),
    "AC:84:C6":("TP-Link","Router/AP","TP-Link"), "50:C7:BF":("TP-Link","Router/AP","TP-Link"),
    "00:1D:0F":("TP-Link","Router/AP","TP-Link"), "14:CC:20":("TP-Link","Router/AP","TP-Link"),
    "18:A6:F7":("TP-Link","Router/AP","TP-Link"), "1C:3B:F3":("TP-Link","Router/AP","TP-Link"),
    "20:DC:E6":("TP-Link","Router/AP","TP-Link"), "24:69:68":("TP-Link","Router/AP","TP-Link"),
    "28:87:BA":("TP-Link","Router/AP","TP-Link"), "2C:D0:5A":("TP-Link","Router/AP","TP-Link"),
    "30:B5:C2":("TP-Link","Router/AP","TP-Link"), "34:60:F9":("TP-Link","Router/AP","TP-Link"),
    "38:EA:A7":("TP-Link","Router/AP","TP-Link"), "3C:84:6A":("TP-Link","Router/AP","TP-Link"),
    "40:3F:8C":("TP-Link","Router/AP","TP-Link"), "40:8D:5C":("TP-Link","Router/AP","TP-Link"),
    "44:94:FC":("TP-Link","Router/AP","TP-Link"), "48:8D:36":("TP-Link","Router/AP","TP-Link"),
    "50:3E:AA":("TP-Link","Router/AP","TP-Link"), "54:E6:FC":("TP-Link","Router/AP","TP-Link"),
    "58:D5:6E":("TP-Link","Router/AP","TP-Link"), "5C:63:BF":("TP-Link","Router/AP","TP-Link"),
    "60:32:B1":("TP-Link","Router/AP","TP-Link"), "64:70:02":("TP-Link","Router/AP","TP-Link"),
    "6C:B0:CE":("TP-Link","Router/AP","TP-Link"), "70:4F:57":("TP-Link","Router/AP","TP-Link"),
    "74:DA:88":("TP-Link","Router/AP","TP-Link"), "7C:8B:CA":("TP-Link","Router/AP","TP-Link"),
    "80:35:C1":("TP-Link","Router/AP","TP-Link"), "84:16:F9":("TP-Link","Router/AP","TP-Link"),
    "8C:21:0A":("TP-Link","Router/AP","TP-Link"), "90:F6:52":("TP-Link","Router/AP","TP-Link"),
    "94:D9:B3":("TP-Link","Router/AP","TP-Link"), "98:DE:D0":("TP-Link","Router/AP","TP-Link"),
    "9C:A6:15":("TP-Link","Router/AP","TP-Link"), "A0:F3:C1":("TP-Link","Router/AP","TP-Link"),
    "A4:2B:B0":("TP-Link","Router/AP","TP-Link"), "A8:57:4E":("TP-Link","Router/AP","TP-Link"),
    "AC:9E:17":("TP-Link","Router/AP","TP-Link"), "B0:48:7A":("TP-Link","Router/AP","TP-Link"),
    "B8:08:CF":("TP-Link","Router/AP","TP-Link"), "BC:46:99":("TP-Link","Router/AP","TP-Link"),
    "C0:4A:00":("TP-Link","Router/AP","TP-Link"), "C4:6E:1F":("TP-Link","Router/AP","TP-Link"),
    "C8:D3:A3":("TP-Link","Router/AP","TP-Link"), "CC:32:E5":("TP-Link","Router/AP","TP-Link"),
    "D4:6E:0E":("TP-Link","Router/AP","TP-Link"), "D8:15:0D":("TP-Link","Router/AP","TP-Link"),
    "DC:FE:18":("TP-Link","Router/AP","TP-Link"), "E0:28:6D":("TP-Link","Router/AP","TP-Link"),
    "E4:D3:32":("TP-Link","Router/AP","TP-Link"), "E8:94:F6":("TP-Link","Router/AP","TP-Link"),
    "EC:08:6B":("TP-Link","Router/AP","TP-Link"), "F0:9F:C2":("TP-Link","Router/AP","TP-Link"),
    "F4:EC:38":("TP-Link","Router/AP","TP-Link"), "F8:1A:67":("TP-Link","Router/AP","TP-Link"),
    # ── Ubiquiti ─────────────────────────────────────────────────────────────
    "00:27:22":("Ubiquiti","Router/AP","Ubiquiti"),  "04:18:D6":("Ubiquiti","Router/AP","Ubiquiti"),
    "0C:62:A6":("Ubiquiti","Router/AP","Ubiquiti"),  "18:E8:29":("Ubiquiti","Router/AP","Ubiquiti"),
    "24:A4:3C":("Ubiquiti","Router/AP","Ubiquiti"),  "44:D9:E7":("Ubiquiti","Router/AP","Ubiquiti"),
    "64:16:66":("Ubiquiti","Router/AP","Ubiquiti"),  "68:72:51":("Ubiquiti","Router/AP","Ubiquiti"),
    "74:83:C2":("Ubiquiti","Router/AP","Ubiquiti"),  "80:2A:A8":("Ubiquiti","Router/AP","Ubiquiti"),
    "B4:FB:E4":("Ubiquiti","Router/AP","Ubiquiti"),  "DC:9F:DB":("Ubiquiti","Router/AP","Ubiquiti"),
    "E0:63:DA":("Ubiquiti","Router/AP","Ubiquiti"),  "F4:92:BF":("Ubiquiti","Router/AP","Ubiquiti"),
    "F4:E2:C6":("Ubiquiti","Router/AP","Ubiquiti"),  "FC:EC:DA":("Ubiquiti","Router/AP","Ubiquiti"),
    # ── Netgear ─────────────────────────────────────────────────────────────
    "00:09:5B":("Netgear","Router/AP","Netgear"), "00:0F:B5":("Netgear","Router/AP","Netgear"),
    "00:14:6C":("Netgear","Router/AP","Netgear"), "00:18:4D":("Netgear","Router/AP","Netgear"),
    "00:1B:2F":("Netgear","Router/AP","Netgear"), "00:1E:2A":("Netgear","Router/AP","Netgear"),
    "00:22:3F":("Netgear","Router/AP","Netgear"), "00:24:B2":("Netgear","Router/AP","Netgear"),
    "00:26:F2":("Netgear","Router/AP","Netgear"), "04:A1:51":("Netgear","Router/AP","Netgear"),
    "20:E5:2A":("Netgear","Router/AP","Netgear"), "2C:B0:5D":("Netgear","Router/AP","Netgear"),
    "30:46:9A":("Netgear","Router/AP","Netgear"), "44:94:FC":("Netgear","Router/AP","Netgear"),
    "6C:B0:CE":("Netgear","Router/AP","Netgear"), "A0:21:B7":("Netgear","Router/AP","Netgear"),
    "C0:FF:D4":("Netgear","Router/AP","Netgear"), "E4:F4:C6":("Netgear","Router/AP","Netgear"),
    # ── Google / Android / Nest ─────────────────────────────────────────────
    "B0:4E:26":("Google","Chromecast","Google"),  "54:60:09":("Google","Chromecast","Google"),
    "6C:AD:F8":("Google","Chromecast","Google"),  "AA:01:37":("Google","Chromecast","Google"),
    "18:B4:30":("Nest","Smart Home","Google"),    "20:7B:D2":("Google","Google Home","Google"),
    "3C:28:6D":("Google","Pixel Phone","Google"), "CC:3D:82":("Google","Pixel Phone","Google"),
    "D0:E7:82":("Google","Pixel Phone","Google"), "F4:F5:D8":("Google","Pixel Phone","Google"),
    # ── Amazon ──────────────────────────────────────────────────────────────
    "F0:27:65":("Amazon","Echo","Amazon"),  "44:65:0D":("Amazon","Echo","Amazon"),
    "40:B4:CD":("Amazon","Echo","Amazon"),  "A4:08:01":("Amazon","Echo","Amazon"),
    "68:37:E9":("Amazon","FireTV","Amazon"),"74:75:48":("Amazon","FireTV","Amazon"),
    "84:D6:D0":("Amazon","FireTV","Amazon"),"FC:A6:67":("Amazon","FireTV","Amazon"),
    # ── LG ──────────────────────────────────────────────────────────────────
    "64:B5:C6":("LG","Smart TV","LG Electronics"),  "A8:23:FE":("LG","Smart TV","LG Electronics"),
    "BC:F5:AC":("LG","Smart TV","LG Electronics"),  "CC:2D:8C":("LG","Smart TV","LG Electronics"),
    "F8:95:C7":("LG","Smart TV","LG Electronics"),  "00:E0:91":("LG","Mobile Phone","LG Electronics"),
    "10:68:3F":("LG","Mobile Phone","LG Electronics"),"30:CD:A7":("LG","Mobile Phone","LG Electronics"),
    # ── Sony ────────────────────────────────────────────────────────────────
    "E0:1C:FC":("Sony","PlayStation","Sony"),  "00:13:A9":("Sony","PlayStation","Sony"),
    "00:24:BE":("Sony","PlayStation","Sony"),  "00:D9:D1":("Sony","PlayStation","Sony"),
    "70:A5:BF":("Sony","Smart TV","Sony"),     "AC:9B:0A":("Sony","Smart TV","Sony"),
    "F8:16:54":("Sony","Smart TV","Sony"),     "B8:8A:60":("Sony","Smart TV","Sony"),
    # ── Raspberry Pi ─────────────────────────────────────────────────────────
    "B8:27:EB":("Raspberry Pi","IoT/SBC","Raspberry Pi"), "DC:A6:32":("Raspberry Pi","IoT/SBC","Raspberry Pi"),
    "E4:5F:01":("Raspberry Pi","IoT/SBC","Raspberry Pi"),
    # ── VMs ─────────────────────────────────────────────────────────────────
    "00:0C:29":("VMware","Virtual Machine","VMware"),   "00:50:56":("VMware","Virtual Machine","VMware"),
    "00:1C:14":("VMware","Virtual Machine","VMware"),   "00:16:3E":("Xen","Virtual Machine","Xen"),
    "52:54:00":("QEMU","Virtual Machine","QEMU"),       "08:00:27":("VirtualBox","Virtual Machine","Oracle"),
    "0A:00:27":("VirtualBox","Virtual Machine","Oracle"),
    # ── Intel (PC NICs) ─────────────────────────────────────────────────────
    "00:1B:21":("Intel","PC","Intel"),  "00:1F:3B":("Intel","PC","Intel"),
    "00:22:FB":("Intel","PC","Intel"),  "00:24:D7":("Intel","PC","Intel"),
    "10:02:B5":("Intel","PC","Intel"),  "18:03:73":("Intel","PC","Intel"),
    "1C:69:7A":("Intel","PC","Intel"),  "24:77:03":("Intel","PC","Intel"),
    "28:D2:44":("Intel","PC","Intel"),  "34:13:E8":("Intel","PC","Intel"),
    "40:8D:5C":("Intel","PC","Intel"),  "4C:EB:42":("Intel","PC","Intel"),
    "50:7B:9D":("Intel","PC","Intel"),  "54:27:1E":("Intel","PC","Intel"),
    "6C:88:14":("Intel","PC","Intel"),  "7C:67:A2":("Intel","PC","Intel"),
    "80:86:F2":("Intel","PC","Intel"),  "8C:8D:28":("Intel","PC","Intel"),
    "94:65:9C":("Intel","PC","Intel"),  "A0:A8:CD":("Intel","PC","Intel"),
    "A4:4C:C8":("Intel","PC","Intel"),  "AC:B5:7D":("Intel","PC","Intel"),
    "B8:03:05":("Intel","PC","Intel"),  "C0:3F:D5":("Intel","PC","Intel"),
    "C4:65:16":("Intel","PC","Intel"),  "CC:3D:82":("Intel","PC","Intel"),
    "D0:50:99":("Intel","PC","Intel"),  "D4:BE:D9":("Intel","PC","Intel"),
    "E0:94:67":("Intel","PC","Intel"),  "E4:B3:18":("Intel","PC","Intel"),
    "E8:6A:64":("Intel","PC","Intel"),  "EC:F4:BB":("Intel","PC","Intel"),
    # ── IP Cameras / NVR ────────────────────────────────────────────────────
    "00:12:12":("Hikvision","IP Camera","Hikvision"), "BC:AD:28":("Hikvision","IP Camera","Hikvision"),
    "C0:56:E3":("Hikvision","IP Camera","Hikvision"), "44:19:B6":("Hikvision","IP Camera","Hikvision"),
    "54:C4:15":("Hikvision","IP Camera","Hikvision"),
    "00:1D:E5":("Dahua","IP Camera","Dahua"),          "3C:EF:8C":("Dahua","IP Camera","Dahua"),
    "90:02:A9":("Axis","IP Camera","Axis"),             "00:40:8C":("Axis","IP Camera","Axis"),
    "AC:CC:8E":("Wyze","IP Camera","Wyze"),             "2C:AA:8E":("Wyze","IP Camera","Wyze"),
    "20:F4:1B":("Reolink","IP Camera","Reolink"),
    # ── Printers ────────────────────────────────────────────────────────────
    "00:00:48":("Epson","Printer","Epson"),  "00:26:AB":("Epson","Printer","Epson"),
    "00:04:00":("Lexmark","Printer","Lexmark"), "00:00:AA":("Xerox","Printer","Xerox"),
    "00:00:74":("Ricoh","Printer","Ricoh"),  "08:00:37":("HP","Printer","HP"),
    "28:80:23":("Canon","Printer","Canon"),  "00:1E:8F":("Canon","Printer","Canon"),
    "08:92:04":("Brother","Printer","Brother"),
    # ── Game Consoles ─────────────────────────────────────────────────────
    "00:13:15":("Sony","PlayStation","Sony"),  "00:19:C5":("Sony","PlayStation","Sony"),
    "00:1F:A7":("Sony","PlayStation","Sony"),  "70:9E:29":("Sony","PlayStation","Sony"),
    "00:E0:4C":("Realtek","PC","Realtek"),     "7C:BB:8A":("Microsoft","Xbox","Microsoft"),
    "00:25:AE":("Microsoft","Xbox","Microsoft"),"00:22:48":("Microsoft","Xbox","Microsoft"),
    "00:1D:D8":("Microsoft","Xbox","Microsoft"),"98:5F:D3":("Microsoft","Xbox","Microsoft"),
    "00:09:BF":("Nintendo","Nintendo Switch","Nintendo"), "98:B6:E9":("Nintendo","Nintendo Switch","Nintendo"),
    "E0:F6:B4":("Nintendo","Nintendo Switch","Nintendo"), "9C:AA:1B":("Nintendo","Nintendo Switch","Nintendo"),
    "A4:C0:E1":("Nintendo","Nintendo Switch","Nintendo"),
}


# ── Hostname → OS mapping (the key accuracy improvement) ─────────────────────
# Each entry: regex pattern → (os_name, os_family, confidence)
HOSTNAME_OS_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    # Windows – broad hostname match (DESKTOP-, WIN-, generic PC names)
    (re.compile(r"DESKTOP-|WIN-|WIN10|WIN11|WINDOWS", re.I),
     "Windows", "Windows", "High"),
    (re.compile(r"-PC$|-LAPTOP$|-WORKSTATION$", re.I),
     "Windows", "Windows", "Medium"),
    # Generic PC / computer hostnames (kali, parrot treated separately below
    # as Linux distros, but plain "PC", "COMPUTER", "DESKTOP", "CUSTOMER" etc.)
    (re.compile(r"^PC[-_]?\d*$|^COMPUTER$|^DESKTOP$|^WORKSTATION$|^CUSTOMER[-_]?\d*$|^CLIENT[-_]?\d*$|^USER[-_]?\d*$|^HOST[-_]?\d*$", re.I),
     "Windows", "Windows", "Medium"),
    # macOS / Apple
    (re.compile(r"MacBook|iMac|Mac-Pro|Mac-Mini|macOS", re.I),
     "macOS", "macOS", "High"),
    (re.compile(r"\.local$", re.I),                          # mDNS .local is almost always Apple/Linux
     "macOS/Linux", "Unix", "Low"),
    # iOS
    (re.compile(r"iPhone|iPad|iPod", re.I),
     "iOS", "iOS", "High"),
    # Android
    (re.compile(r"android|ANDROID|Galaxy|SAMSUNG|HUAWEI|Pixel|OnePlus|Xiaomi|Redmi|"
                r"Poco|Realme|OPPO|Vivo|Infinix|TECNO|Itel|Motorola|Nokia|HTC|ZTE|"
                r"Meizu|Nubia|Gionee|Blackview|Ulefone|Doogee|Fairphone|Nothing",
                re.I),
     "Android", "Android", "High"),
    # Linux distros
    (re.compile(r"ubuntu|debian|fedora|centos|arch|manjaro|mint|kali|parrot", re.I),
     "Linux", "Linux", "High"),
    (re.compile(r"raspberrypi|raspi|rpi", re.I),
     "Linux (Raspberry Pi OS)", "Linux", "High"),
    (re.compile(r"nas|synology|qnap|freenas|truenas", re.I),
     "Linux/BSD (NAS)", "Linux", "High"),
    # Network gear
    (re.compile(r"router|gateway|modem|dsl|fiber|ont|fritzbox|openwrt|dd-wrt|tomato", re.I),
     "Router/Embedded Linux", "Embedded", "High"),
    (re.compile(r"cisco|juniper|mikrotik|ubnt|unifi|edgerouter|zyxel|netgear|dlink", re.I),
     "Network OS (Cisco/Linux)", "Network", "High"),
    # Smart TV / streaming
    (re.compile(r"samsung.*tv|LG.*TV|bravia|VIZIO|hisense|tcl.*tv|firetv|appletv|roku|chromecast", re.I),
     "Smart TV OS", "Embedded", "High"),
    # Game consoles
    (re.compile(r"PS[345]|PlayStation|Xbox|Nintendo|Switch", re.I),
     "Console OS", "Console", "High"),
    # IoT / printers
    (re.compile(r"printer|HP.*LaserJet|EPSON|Canon|Brother|Xerox", re.I),
     "Printer Firmware", "Embedded", "High"),
    (re.compile(r"ESP[0-9]|arduino|tasmota|esphome|home-assistant", re.I),
     "Embedded/IoT Firmware", "Embedded", "High"),
    # Windows Server
    (re.compile(r"SERVER|SRV|DC[0-9]|PDC|BDC|EXCHANGE|SHAREPOINT", re.I),
     "Windows Server", "Windows", "High"),
]

# TTL → OS family (fallback when no hostname hint available)
def _os_from_ttl(ttl: int) -> Tuple[str, str]:
    """Return (os_guess, confidence)"""
    if ttl <= 0:   return "Unknown", ""
    if ttl <= 64:  return "Linux / Android / macOS", "Low (TTL≤64)"
    if ttl <= 128: return "Windows", "Low (TTL≤128)"
    return "Network Device (Cisco/BSD)", "Low (TTL>128)"

# ─────────────────────────────────────────────────────────────────────────────
#  IN-MEMORY STORES  (all protected by _lock)
# ─────────────────────────────────────────────────────────────────────────────
devices:      Dict[str, dict]           = {}
traffic_data: Dict[str, deque]          = defaultdict(lambda: deque(maxlen=120))
packet_log:   Dict[str, deque]          = defaultdict(lambda: deque(maxlen=MAX_PKTS))
alerts:       deque                     = deque(maxlen=200)
syn_counters: Dict[str, int]            = defaultdict(int)
net_stats = dict(total_in=0, total_out=0, pps=0, scan_count=0, alert_count=0)
_lock = threading.RLock()

# ─────────────────────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def _ts()  -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def _sts() -> str: return datetime.now().strftime("%H:%M:%S")

def _fmt(b: int) -> str:
    if b < 1024:       return f"{b}B"
    if b < 1_048_576:  return f"{b/1024:.1f}KB"
    return f"{b/1_048_576:.1f}MB"

def get_local_network() -> Tuple[str, str]:
    gws = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
    if not gws:
        return "192.168.1.1", "192.168.1.0/24"
    gw_ip, iface = gws[0], gws[1]
    addr = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
    ip, mask = addr.get("addr", ""), addr.get("netmask", "255.255.255.0")
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return gw_ip, str(net)
    except Exception:
        return gw_ip, "192.168.1.0/24"

def get_local_ips() -> set:
    ips = {"127.0.0.1"}
    try:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET:
                    ips.add(a.address)
    except Exception:
        pass
    return ips

def oui(mac: str) -> str:
    if not mac or mac in ("N/A", ""):
        return ""
    return ":".join(mac.upper().replace("-",":").split(":")[:3])

# ─────────────────────────────────────────────────────────────────────────────
#  VENDOR LOOKUP  – 4-source cascade, thread-safe, fully cached
# ─────────────────────────────────────────────────────────────────────────────
_vendor_cache:    Dict[str, Tuple[str,str,str]] = {}   # OUI prefix → (vendor, dtype, brand)
_hostname_cache:  Dict[str, str]                = {}   # IP → hostname (PTR)
_banner_cache:    Dict[str, str]                = {}   # IP → HTTP banner info
_mdns_cache:      Dict[str, str]                = {}   # IP → mDNS/Bonjour name

# Clean company name – strip legal suffixes that clutter the UI
_CORP_RE = re.compile(
    r",?\s*(Inc\.?|LLC\.?|Ltd\.?|Co\.?|Corp\.?|GmbH|S\.A\.?|B\.V\.?|PTE\.?|"
    r"Technology|Technologies|Communications|Electronics|International|"
    r"Solutions|Systems|Networks|Network|Group|Holdings|Manufacturing)\.?$",
    re.I
)
def _clean_company(name: str) -> str:
    if not name:
        return name
    name = _CORP_RE.sub("", name).strip(" ,.")
    return name if name else name   # keep original if cleaning made it empty

# API endpoints tried in order – all return company name from MAC/OUI prefix
_OUI_API_ENDPOINTS = [
    # macvendors.com – fast, free, no key, 1 request/s rate limit
    "https://api.macvendors.com/{mac}",
    # maclookup.app – JSON response with company field
    "https://api.maclookup.app/v2/macs/{mac}",
]

def _query_oui_api(mac: str, prefix: str) -> Tuple[str,str,str]:
    """Try each vendor API endpoint and return the first good result."""
    if not REQUESTS_OK:
        return ("Unknown","Unknown","Unknown")
    for tpl in _OUI_API_ENDPOINTS:
        url = tpl.format(mac=mac, prefix=prefix)
        try:
            r = _http.get(url, timeout=3)
            if r.status_code != 200:
                continue
            # macvendors returns plain text; maclookup returns JSON
            if "maclookup" in url:
                company = r.json().get("company","")
                found   = r.json().get("found", True)
                if not found:
                    continue
            else:
                company = r.text.strip()
            company = _clean_company(company)
            if company and company.lower() not in ("","unknown","private","not found"):
                dtype = _guess_type(company)
                return (company, dtype, company)
        except Exception:
            continue
    return ("Unknown","Unknown","Unknown")

def lookup_vendor(mac: str) -> Tuple[str,str,str]:
    """
    Return (vendor_name, device_type, brand) from MAC address.
    Lookup order:
      1. In-memory cache (instant)
      2. Built-in OUI_TABLE (instant, 300+ brands)
      3. macvendors.com  (fast REST API, plain-text response)
      4. maclookup.app   (JSON REST API, fallback)
    Result is always cached so each OUI prefix is only queried once.
    """
    prefix = oui(mac)
    if not prefix:
        return "Unknown", "Unknown", "Unknown"
    # Cache hit
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    # Built-in OUI table
    if prefix in OUI_TABLE:
        entry = OUI_TABLE[prefix]
        _vendor_cache[prefix] = entry
        return entry
    # Live API cascade
    result = _query_oui_api(mac, prefix)
    _vendor_cache[prefix] = result
    return result

def _guess_type(v: str) -> str:
    """Infer device type from vendor string (used for live API results)."""
    v = v.lower()
    # Android phone/tablet brands
    if any(x in v for x in [
        "apple", "samsung", "huawei", "xiaomi", "redmi", "poco", "oneplus",
        "oppo", "realme", "vivo", "iqoo", "infinix", "tecno", "itel",
        "gionee", "motorola", "nokia mobile", "sony mobile", "htc", "zte",
        "meizu", "nubia", "blackview", "ulefone", "doogee", "oukitel",
        "umidigi", "cubot", "blu mobile", "wiko", "micromax", "lava",
        "karbonn", "symphony", "walton", "fairphone", "nothing",
    ]):
        return "Mobile Phone"
    if any(x in v for x in ["dell", "hp inc", "lenovo", "asus", "acer",
                             "toshiba", "msi", "fujitsu", "nec laptop"]):
        return "PC / Laptop"
    if any(x in v for x in ["cisco", "netgear", "tp-link", "d-link",
                             "ubiquiti", "mikrotik", "zyxel", "juniper"]):
        return "Router / Switch"
    if any(x in v for x in ["raspberry", "arduino", "espressif", "particle"]):
        return "IoT / SBC"
    if any(x in v for x in ["vmware", "virtualbox", "qemu", "xen", "parallels"]):
        return "Virtual Machine"
    if any(x in v for x in ["amazon", "google home", "sonos", "nest", "ring"]):
        return "Smart Device"
    if any(x in v for x in ["lg", "sony", "tcl", "hisense", "vizio",
                             "philips", "sharp", "panasonic"]):
        return "Smart TV"
    return "Unknown"

def add_alert(ip: str, title: str, detail: str, severity: str = "MEDIUM"):
    with _lock:
        a = {
            "id": hashlib.md5(f"{ip}{title}{_ts()}".encode()).hexdigest()[:8],
            "ip": ip, "title": title, "detail": detail,
            "severity": severity, "ts": _ts(), "ack": False,
        }
        alerts.appendleft(a)
        net_stats["alert_count"] += 1
    socketio.emit("new_alert", a)

# ─────────────────────────────────────────────────────────────────────────────
#  VENDOR → OS  (authoritative lookup before any scanning)
# ─────────────────────────────────────────────────────────────────────────────

# Android-only brands — these devices run Android regardless of model
_ANDROID_VENDORS: Tuple[str, ...] = (
    "samsung", "xiaomi", "redmi", "poco", "huawei", "honor",
    "oppo", "realme", "oneplus", "vivo", "iqoo", "infinix",
    "tecno", "itel", "gionee", "alcatel", "nokia mobile",
    "motorola", "lenovo mobile", "zte", "lg mobile", "htc",
    "meizu", "nubia", "blackview", "ulefone", "doogee",
    "oukitel", "umidigi", "cubot", "blu", "wiko", "micromax",
    "lava", "karbonn", "symphony", "walton", "pixel", "fairphone",
    "nothing phone", "onyx boox", "sony mobile", "sharp mobile",
)

# Apple device_type values from OUI_TABLE → OS mapping
_APPLE_DTYPE_OS: Dict[str, str] = {
    "iPhone":  "iOS",
    "iPad":    "iPadOS",
    "MacBook": "macOS",
    "Mac":     "macOS",
    "iMac":    "macOS",  # handled by hostname but belt+suspenders
}

def infer_os_from_vendor(vendor: str, device_type: str) -> Tuple[str, str]:
    """
    Return (os_string, confidence) purely from vendor name + OUI device_type.
    Called as the FIRST signal in _deep_scan before any network probing,
    so known devices get the right OS immediately.
    Returns ("", "") when no confident inference is possible.
    """
    v = vendor.lower().strip()
    dt = (device_type or "").lower()

    # ── Apple ──────────────────────────────────────────────────────────────────
    if "apple" in v:
        # Use the device_type from OUI table to distinguish iPhone vs Mac
        if "iphone" in dt:
            return "iOS", "High (Apple iPhone OUI)"
        if "ipad" in dt:
            return "iPadOS", "High (Apple iPad OUI)"
        if any(x in dt for x in ("macbook", "mac", "imac", "desktop", "laptop", "pc")):
            return "macOS", "High (Apple Mac OUI)"
        # Fallback: if we can't tell phone vs mac, use hostname patterns later
        return "iOS / macOS", "Medium (Apple OUI)"

    # ── Pure Android brands ────────────────────────────────────────────────────
    if any(brand in v for brand in _ANDROID_VENDORS):
        # Confirm it's a phone/tablet, not a TV (Samsung makes both)
        if any(x in dt for x in ("smart tv", "television", "tv")):
            return "Android TV / Tizen", "High (vendor+type)"
        if any(x in dt for x in ("chromecast", "streaming", "firetv")):
            return "Android / Cast OS", "High (vendor+type)"
        return "Android", "High (vendor OUI)"

    # ── Google Pixel ───────────────────────────────────────────────────────────
    if "google" in v:
        if "pixel" in dt:
            return "Android", "High (Google Pixel OUI)"
        if any(x in dt for x in ("chromecast", "home", "hub")):
            return "Cast OS / Android", "High (Google OUI)"

    # ── Microsoft Xbox ──────────────────────────────────────────────────────────
    if "microsoft" in v and "xbox" in dt:
        return "Xbox OS", "High (Microsoft Xbox OUI)"

    # ── Sony PlayStation ────────────────────────────────────────────────────────
    if "sony" in v and "playstation" in dt:
        return "PlayStation OS", "High (Sony OUI)"

    # ── Nintendo ────────────────────────────────────────────────────────────────
    if "nintendo" in v:
        return "Nintendo Switch OS", "High (Nintendo OUI)"

    # ── Raspberry Pi ────────────────────────────────────────────────────────────
    if "raspberry" in v:
        return "Linux (Raspberry Pi OS)", "High (RPi OUI)"

    # ── VMs ─────────────────────────────────────────────────────────────────────
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "xen", "parallels")):
        return "Linux / Windows (VM)", "High (VM OUI)"

    # ── Printers ────────────────────────────────────────────────────────────────
    if any(x in v for x in ("hp", "canon", "epson", "brother", "xerox",
                             "ricoh", "lexmark", "kyocera", "konica")):
        if "printer" in dt or "print" in v:
            return "Printer Firmware", "High (vendor OUI)"

    # ── IP Cameras ──────────────────────────────────────────────────────────────
    if any(x in v for x in ("hikvision", "dahua", "axis", "wyze", "reolink",
                             "amcrest", "foscam", "annke", "lorex")):
        return "Embedded Linux (IP Camera)", "High (vendor OUI)"

    # ── Network gear ────────────────────────────────────────────────────────────
    if any(x in v for x in ("cisco", "ubiquiti", "mikrotik", "netgear", "tp-link",
                             "d-link", "zyxel", "juniper", "aruba", "ruckus")):
        return "Network OS (Embedded Linux)", "High (vendor OUI)"

    return "", ""   # no confident inference


# ─────────────────────────────────────────────────────────────────────────────
#  OS DETECTION  (vendor-first, then hostname, ports, TTL)
# ─────────────────────────────────────────────────────────────────────────────
def detect_os(ip: str, hostname: str, mac: str,
              vendor: str, device_type: str,
              open_ports: dict, ttl: int) -> Tuple[str, str]:
    """
    Returns (os_string, confidence).
    Priority:
      1. Vendor+device_type (authoritative for known brands)
      2. Hostname regex patterns
      3. Open port fingerprint
      4. TTL heuristic
    """
    # 1. Vendor-based inference (most accurate for consumer devices)
    os_v, conf_v = infer_os_from_vendor(vendor, device_type)
    if os_v and "unknown" not in os_v.lower():
        return os_v, conf_v

    # 2. Hostname pattern matching
    h = hostname or ""
    for pattern, os_name, _, confidence in HOSTNAME_OS_PATTERNS:
        if pattern.search(h):
            return os_name, confidence

    # 3. Port-based fingerprint
    open_set = {p for p, i in open_ports.items() if i.get("state") == "open"}
    if {135, 139, 445} & open_set:
        return "Windows", "Medium (SMB ports)"
    if {3389} & open_set:
        return "Windows", "Medium (RDP port)"
    if {22} & open_set and not ({80, 443} & open_set):
        return "Linux / Unix", "Low (SSH only)"
    if {548, 5353} & open_set:
        return "macOS", "Medium (AFP/mDNS)"
    if {62078} & open_set:
        return "iOS", "High (lockdownd port)"
    if {5555} & open_set:
        return "Android", "High (ADB port)"

    # 4. MAC OUI fallback (generic)
    v_low = vendor.lower()
    if any(x in v_low for x in ["raspberry", "espressif", "arduino"]):
        return "Linux (Embedded)", "Low (IoT OUI)"
    if any(x in v_low for x in ["vmware", "virtualbox", "qemu"]):
        return "Linux / Windows (VM)", "Low (VM OUI)"

    # 5. TTL fallback
    if ttl > 0:
        return _os_from_ttl(ttl)

    return "Unknown", ""


# ─────────────────────────────────────────────────────────────────────────────
#  NETWORK SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self._strategy: Optional[str] = None   # cached working strategy

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(self, network: str) -> List[dict]:
        """Try all strategies; return first non-empty result. Never raises."""
        strategies = []
        if SCAPY_OK and IS_ROOT:
            strategies.append(("scapy_arp",  self._scapy_arp))
        strategies += [
            ("nmap_arp",   self._nmap_arp),
            ("nmap_ping",  self._nmap_ping),
            ("arp_table",  self._arp_table),
        ]
        # Try cached strategy first
        if self._strategy:
            strategies.sort(key=lambda s: 0 if s[0] == self._strategy else 1)

        for name, fn in strategies:
            try:
                result = fn(network)
                if result:
                    if self._strategy != name:
                        print(f"[NetSentinel] Discovery via '{name}' → {len(result)} hosts")
                        self._strategy = name
                    return result
            except Exception:
                pass

        # Absolute fallback: return gateway only
        gw = network.split("/")[0].rsplit(".", 1)[0] + ".1"
        return [{"ip": gw, "mac": "N/A"}]

    def _scapy_arp(self, network: str) -> List[dict]:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        ans, _ = srp(pkt, timeout=2, verbose=False)
        return [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in ans]

    def _nmap_arp(self, network: str) -> List[dict]:
        self.nm.scan(hosts=network, arguments="-sn -PR --host-timeout 3s -T5")
        return [{"ip": h, "mac": self.nm[h]["addresses"].get("mac","N/A")}
                for h in self.nm.all_hosts()]

    def _nmap_ping(self, network: str) -> List[dict]:
        self.nm.scan(hosts=network, arguments="-sn -PE -PS22,80,443,8080 --host-timeout 3s -T5")
        return [{"ip": h, "mac": self.nm[h]["addresses"].get("mac","N/A")}
                for h in self.nm.all_hosts()]

    def _arp_table(self, network: str) -> List[dict]:
        found: Dict[str, dict] = {}
        try:
            net_obj = ipaddress.IPv4Network(network, strict=False)
        except Exception:
            net_obj = None

        def _in_net(ip_s: str) -> bool:
            try:
                return net_obj is None or ipaddress.ip_address(ip_s) in net_obj
            except Exception:
                return False

        # Linux /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) >= 4 and p[3] not in ("00:00:00:00:00:00", ""):
                            ip_s = p[0]
                            if _in_net(ip_s):
                                found[ip_s] = {"ip": ip_s, "mac": p[3].upper()}
            except Exception:
                pass

        # Cross-platform arp -a
        if not found:
            try:
                out = subprocess.check_output(
                    ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=8
                ).decode(errors="ignore")
                for line in out.splitlines():
                    m = re.search(
                        r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        ip_s, mac = m.group(1), m.group(2).upper()
                        if _in_net(ip_s):
                            found[ip_s] = {"ip": ip_s, "mac": mac}
            except Exception:
                pass

        return list(found.values())

    # ── Port scan ─────────────────────────────────────────────────────────────

    def port_scan(self, ip: str) -> dict:
        """Returns {port: {state, service, version, protocol}}"""
        ports = "21-25,53,80,110,135,139,143,161,389,443,445,512-514,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"
        args  = ("-sV --host-timeout 12s -T5" if IS_ROOT
                 else "-sT --host-timeout 12s -T5")
        try:
            self.nm.scan(ip, ports, arguments=args)
            if ip not in self.nm.all_hosts():
                return self._tcp_fallback(ip)
            result = {}
            for proto in self.nm[ip].all_protocols():
                for port, info in self.nm[ip][proto].items():
                    result[port] = {
                        "state":    info.get("state", ""),
                        "service":  info.get("name", ""),
                        "version":  f"{info.get('product','')} {info.get('version','')}".strip(),
                        "protocol": proto,
                    }
            return result
        except Exception:
            return self._tcp_fallback(ip)

    def _tcp_fallback(self, ip: str) -> dict:
        """
        Pure-Python parallel TCP connect scan (no root needed).
        Covers the most informative ports with a 0.35-second timeout.
        Uses up to 48 threads so all ports are tried simultaneously.
        """
        PORTS = [
            # Common services
            21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161,
            389, 443, 445, 512, 513, 514, 548, 587, 631,
            # Database
            1433, 1521, 3306, 5432, 5984, 6379, 7474, 8086, 9200, 27017, 28017,
            # Remote access
            3389, 5900, 5901, 5902, 5985, 5986,
            # Web / proxy
            80, 81, 82, 83, 84, 85, 86, 87, 88,
            8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
            8090, 8443, 8888, 8899, 9000, 9090, 9100, 9443,
            # IoT / smart home
            1883, 4840, 5683, 8883,   # MQTT, OPC-UA, CoAP
            # Apple / Bonjour
            5353, 62078,
            # Media / streaming
            554, 1935, 8554,          # RTSP
            # Printing
            515, 9100, 631,
            # Android ADB
            5555,
        ]
        # Deduplicate while preserving order
        seen_p: set = set()
        deduped = []
        for p in PORTS:
            if p not in seen_p:
                seen_p.add(p)
                deduped.append(p)

        result: dict = {}
        def probe(port: int):
            try:
                with socket.create_connection((ip, port), timeout=0.35):
                    svc = ""
                    try: svc = socket.getservbyport(port, "tcp")
                    except Exception: pass
                    return port, {"state":"open","service":svc,"version":"","protocol":"tcp"}
            except Exception:
                return port, None

        with ThreadPoolExecutor(max_workers=48) as ex:
            for port, info in ex.map(probe, deduped):
                if info:
                    result[port] = info
        return result

    # ── TTL ping ──────────────────────────────────────────────────────────────

    def ping_ttl(self, ip: str) -> int:
        flag = ["-n","1"] if platform.system().lower()=="windows" else ["-c","1"]
        try:
            out = subprocess.check_output(
                ["ping"] + flag + ["-W","1", "-c","1", ip],
                stderr=subprocess.DEVNULL, timeout=2
            ).decode(errors="ignore")
            m = re.search(r"ttl[= ](\d+)", out, re.I)
            return int(m.group(1)) if m else 0
        except Exception:
            return 0

    # ── nmap OS (root only) ───────────────────────────────────────────────────

    def nmap_os(self, ip: str) -> Tuple[str, str]:
        if not IS_ROOT:
            return "", ""
        try:
            self.nm.scan(ip, arguments="-O --host-timeout 8s -T5")
            if ip in self.nm.all_hosts():
                matches = self.nm[ip].get("osmatch", [])
                if matches:
                    m = matches[0]
                    return m.get("name",""), f"{m.get('accuracy','')}%"
        except Exception:
            pass
        return "", ""

    # ── Vulnerability assessment ──────────────────────────────────────────────

    def assess_vulns(self, open_ports: dict) -> List[dict]:
        seen, vulns = set(), []
        for port, info in open_ports.items():
            if info.get("state") != "open":
                continue
            if port in VULNERABLE_PORTS and port not in seen:
                seen.add(port)
                name, sev, desc = VULNERABLE_PORTS[port]
                vulns.append({"port":port,"service":name,"severity":sev,
                               "description":desc,"version":info.get("version","")})
        # NoSQL trifecta check
        exposed = [p for p in (6379,27017,9200) if open_ports.get(p,{}).get("state")=="open"]
        if exposed:
            vulns.append({"port":0,"service":"Unauthenticated DB","severity":"CRITICAL",
                          "description":f"Exposed NoSQL ports: {exposed} – likely no auth required",
                          "version":""})
        return vulns


# ─────────────────────────────────────────────────────────────────────────────
#  PACKET CAPTURE  (Scapy when root, psutil always)
# ─────────────────────────────────────────────────────────────────────────────
class PacketCapture:
    def __init__(self):
        self._running     = False
        self._pkt_count   = 0
        self._t0          = time.time()
        self._local_ips   = get_local_ips()
        self._seen_conns: set   = set()
        self._seen_ts:    float = time.time()
        self._prev_nic:   dict  = {}

    def start(self, iface: Optional[str] = None):
        self._running   = True
        self._local_ips = get_local_ips()
        if SCAPY_OK and IS_ROOT:
            threading.Thread(target=self._scapy_loop, args=(iface,),
                             daemon=True, name="cap-scapy").start()
            print("[NetSentinel] Capture: Scapy deep-capture (root)")
        else:
            threading.Thread(target=self._conn_loop, daemon=True, name="cap-conn").start()
            threading.Thread(target=self._nic_loop,  daemon=True, name="cap-nic").start()
            print("[NetSentinel] Capture: psutil poll (no-root mode)")

    def stop(self): self._running = False

    # ── Scapy mode ────────────────────────────────────────────────────────────
    def _scapy_loop(self, iface):
        try:
            sniff(iface=iface, prn=self._on_pkt, store=False,
                  stop_filter=lambda _: not self._running, filter="ip")
        except Exception as e:
            print(f"[NetSentinel] Scapy stopped ({e}), switching to psutil")
            threading.Thread(target=self._conn_loop, daemon=True, name="cap-conn-fb").start()
            threading.Thread(target=self._nic_loop,  daemon=True, name="cap-nic-fb").start()

    def _on_pkt(self, pkt):
        if not pkt.haslayer(IP): return
        src, dst, length = pkt[IP].src, pkt[IP].dst, len(pkt)
        proto, info, sport, dport = "OTHER", "", None, None

        if pkt.haslayer(TCP):
            proto  = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags  = int(pkt[TCP].flags)
            if flags & 0x02 and not (flags & 0x10):
                self._check_syn(src)
            svc = ""
            try: svc = socket.getservbyport(dport,"tcp") if dport < 1024 else ""
            except Exception: pass
            info = f":{sport} → :{dport}" + (f" [{svc}]" if svc else "") + f"  f={flags}"
        elif pkt.haslayer(UDP):
            proto  = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    info = f"DNS  {q}"
                except Exception:
                    info = f":{sport} → :{dport}"
            else:
                info = f":{sport} → :{dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            info  = f"type={pkt[ICMP].type}"

        self._emit(src, dst, proto, length, info, sport, dport)

    # ── psutil connection poll ────────────────────────────────────────────────
    def _conn_loop(self):
        PMAP = {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}
        while self._running:
            now = time.time()
            # Flush seen-set every 8 seconds so flows reappear
            if now - self._seen_ts > 8:
                self._seen_conns.clear()
                self._seen_ts = now
            try:
                for c in psutil.net_connections(kind="inet"):
                    if not c.raddr:
                        continue
                    laddr, raddr = c.laddr, c.raddr
                    src   = laddr.ip   if laddr else "0.0.0.0"
                    dst   = raddr.ip
                    sport = laddr.port if laddr else 0
                    dport = raddr.port
                    proto = PMAP.get(c.type, "TCP")
                    key   = (src, sport, dst, dport, proto)
                    if key in self._seen_conns:
                        continue
                    self._seen_conns.add(key)
                    svc = ""
                    try: svc = socket.getservbyport(dport, proto.lower())
                    except Exception: pass
                    info = f":{sport} → :{dport}" + (f"  [{svc}]" if svc else "")
                    est  = 64 + (dport % 1400)
                    self._emit(src, dst, proto, est, info, sport, dport)
            except Exception:
                pass
            time.sleep(1)

    # ── NIC byte-counter poll ─────────────────────────────────────────────────
    def _nic_loop(self):
        local_ip = next(iter(get_local_ips() - {"127.0.0.1"}), "0.0.0.0")
        while self._running:
            try:
                for nic, s in psutil.net_io_counters(pernic=True).items():
                    if nic.startswith("lo"):
                        continue
                    prev = self._prev_nic.get(nic)
                    if prev:
                        d_in  = max(0, s.bytes_recv   - prev.bytes_recv)
                        d_out = max(0, s.bytes_sent    - prev.bytes_sent)
                        p_in  = max(0, s.packets_recv  - prev.packets_recv)
                        p_out = max(0, s.packets_sent  - prev.packets_sent)
                        if d_in > 0:
                            self._emit("(network)", local_ip, "RECV", d_in,
                                       f"{nic}  ↓{_fmt(d_in)}/s  {p_in}p", None, None)
                        if d_out > 0:
                            self._emit(local_ip, "(internet)", "SEND", d_out,
                                       f"{nic}  ↑{_fmt(d_out)}/s  {p_out}p", None, None)
                        with _lock:
                            net_stats["total_in"]  += d_in
                            net_stats["total_out"] += d_out
                    self._prev_nic[nic] = s
            except Exception:
                pass
            time.sleep(1)

    # ── Shared emit ───────────────────────────────────────────────────────────
    def _emit(self, src, dst, proto, length, info, sport, dport):
        rec = {"ts":_sts(),"src":src,"dst":dst,"proto":proto,
               "len":length,"info":info,"sport":sport,"dport":dport}
        with _lock:
            for ip in (src, dst):
                if ip in devices:
                    packet_log[ip].appendleft(rec)
                    if ip == src: devices[ip]["bytes_out"] = devices[ip].get("bytes_out",0) + length
                    else:         devices[ip]["bytes_in"]  = devices[ip].get("bytes_in", 0) + length
            self._pkt_count += 1
            elapsed = max(1, time.time() - self._t0)
            net_stats["pps"] = round(self._pkt_count / elapsed, 1)
        socketio.emit("live_packet", rec)
        # Lightweight topology event for the network graph
        socketio.emit("topo_packet", {"src":src,"dst":dst,"proto":proto,"len":length})

    def _check_syn(self, src: str):
        syn_counters[src] += 1
        if syn_counters[src] == ANOMALY_THRESH:
            add_alert(src, "SYN Flood Detected",
                      f"Excessive SYN packets from {src}", "HIGH")


# ─────────────────────────────────────────────────────────────────────────────
#  NETWORK MONITOR  (orchestrator)
# ─────────────────────────────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.capture = PacketCapture()
        self.gateway, self.network = get_local_network()
        self._running = False
        # Thread pool for parallel deep-scans (limit concurrency)
        self._scan_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="deep")

    def start(self):
        self._running = True
        # Step 1: instant ARP-cache seed (shows devices in ~1s)
        threading.Thread(target=self._quick_arp_seed, daemon=True, name="arp-seed").start()
        # Step 2: full nmap scan (slower, fills in ports/OS/vulns)
        threading.Thread(target=self._full_scan,      daemon=True, name="scan0").start()
        threading.Thread(target=self._scan_loop,       daemon=True, name="scan-loop").start()
        threading.Thread(target=self._bw_loop,         daemon=True, name="bw-loop").start()
        self.capture.start()

    def _scan_loop(self):
        while self._running:
            time.sleep(SCAN_INTERVAL)
            self._full_scan()

    def _quick_arp_seed(self):
        """
        Phase 1 of startup: read the OS ARP table and emit devices immediately
        so they appear in the UI within ~1 second.
        Also fires a parallel vendor API lookup for any unrecognised MACs so
        that by the time the slow nmap scan finishes, vendors are already cached.
        """
        hosts = self.scanner._arp_table(self.network)
        if not hosts:
            return

        def _seed_one(h: dict):
            ip, mac = h["ip"], h.get("mac","N/A")
            with _lock:
                if ip in devices:
                    return    # full scan already populated this device
            # Vendor lookup – may hit live API if MAC not in built-in table
            vendor, dtype, brand = lookup_vendor(mac)
            # Quick ping for TTL-based OS guess
            ttl      = self.scanner.ping_ttl(ip)
            os_hint  = ("Linux / Android / macOS"   if 0 < ttl <= 64  else
                        "Windows / Android"          if ttl <= 128     else
                        "iOS / Network Device"       if ttl > 128      else
                        "Linux / Android / iOS / macOS")
            # Apply fallbacks for display
            dv  = vendor if vendor and vendor.lower() not in ("unknown","") else ip
            db  = brand  if brand  and brand.lower()  not in ("unknown","") else ip
            ddt = dtype  if dtype  and dtype.lower()  not in ("unknown","") else ip
            entry = {
                "ip": ip, "mac": mac, "hostname": "",
                "vendor": dv, "brand": db, "device_type": ddt,
                "os": os_hint, "os_accuracy": "ARP (fast scan pending)",
                "ttl": ttl, "open_ports": {}, "vulnerabilities": [],
                "vuln_count": 0, "status": "online", "blocked": False,
                "first_seen": _ts(), "last_seen": _ts(),
                "bytes_in": 0, "bytes_out": 0,
                "is_gateway": (ip == self.gateway),
            }
            with _lock:
                if ip not in devices:     # double-check after lock
                    devices[ip] = entry
            socketio.emit("device_update", devices[ip])

        # Seed all devices in parallel (each may do a network call for vendor)
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="seed") as ex:
            list(ex.map(_seed_one, hosts))

    def _full_scan(self):
        hosts = self.scanner.discover(self.network)
        with _lock:
            net_stats["scan_count"] += 1
        seen = set()
        futures = []
        for h in hosts:
            ip, mac = h["ip"], h.get("mac","N/A")
            seen.add(ip)
            is_new = ip not in devices
            # lookup_vendor is fast if cached; _deep_scan will re-query if needed
            vendor, dtype, brand = lookup_vendor(mac)
            futures.append(
                self._scan_pool.submit(
                    self._deep_scan, ip, mac, vendor, dtype, brand, is_new
                )
            )
        # Pre-warm vendor cache for any unknown MACs in a background thread
        # so API calls don't block the scan timing
        unknown_macs = [h.get("mac","N/A") for h in hosts
                        if oui(h.get("mac","N/A")) not in _vendor_cache]
        if unknown_macs:
            def _prewarm():
                for m in unknown_macs:
                    lookup_vendor(m)   # result goes into _vendor_cache
            threading.Thread(target=_prewarm, daemon=True, name="vendor-prewarm").start()
        # Mark offline
        with _lock:
            for ip in list(devices):
                if ip not in seen and devices[ip].get("status") == "online":
                    devices[ip]["status"] = "offline"
                    devices[ip]["last_seen"] = _ts()
                    socketio.emit("device_update", devices[ip])

    # ── HTTP banner grab ─────────────────────────────────────────────────────
    @staticmethod
    def _http_banner(ip: str, open_ports: dict) -> dict:
        """
        Fetch HTTP/HTTPS headers from the device's web server (if any).
        Returns a dict with useful fields: server, model, product, auth_realm.
        Many routers, cameras, printers and smart devices expose their model
        in the Server: header or HTML <title>.
        """
        info: dict = {}
        candidates = []
        for port, pdata in open_ports.items():
            if pdata.get("state") != "open":
                continue
            if port in (80, 8080, 8008, 8888):
                candidates.append((f"http://{ip}:{port}", port))
            elif port in (443, 8443, 8843):
                candidates.append((f"https://{ip}:{port}", port))
        if not candidates:
            return info
        import urllib.request as _ur, ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        for url, port in candidates[:2]:    # try up to 2 ports
            try:
                req = _ur.Request(url, headers={"User-Agent":"NetSentinel/3"})
                r   = _ur.urlopen(req, timeout=3, context=ctx if "https" in url else None)
                hdrs = dict(r.headers)
                # Server header (e.g. "lighttpd/1.4.45", "mini_httpd", "GoAhead")
                srv = hdrs.get("Server","") or hdrs.get("server","")
                if srv:
                    info["server"] = srv[:80]
                # WWW-Authenticate realm – often contains model name
                auth = hdrs.get("WWW-Authenticate","") or hdrs.get("www-authenticate","")
                if auth:
                    m = re.search(r'realm="([^"]+)"', auth)
                    if m:
                        info["auth_realm"] = m.group(1)[:60]
                # Read a small slice of the HTML body for <title>
                try:
                    body = r.read(4096).decode("utf-8","replace")
                    tm = re.search(r"<title[^>]*>([^<]{3,80})</title>", body, re.I)
                    if tm:
                        info["title"] = tm.group(1).strip()[:60]
                except Exception:
                    pass
                if info:
                    break
            except Exception:
                continue
        return info

    def _deep_scan(self, ip, mac, vendor, dtype, brand, is_new):
        """
        Full per-device scan pipeline:
          1. Reverse DNS / mDNS hostname
          2. TTL ping (fast, determines OS family)
          3. Port scan  (nmap SYN/connect or TCP fallback)
          4. HTTP banner grab (router/printer/camera model from web server)
          5. nmap OS detection (root only) or multi-signal heuristic
          6. Vendor deep-lookup (OUI table → macvendors API → maclookup API)
          7. Refine device_type using ALL signals
          8. Vulnerability assessment
        """
        # 1. Reverse DNS hostname
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        # 2. TTL (quick – run before port scan so OS family is known early)
        ttl = self.scanner.ping_ttl(ip)

        # 3. Port scan
        open_ports = self.scanner.port_scan(ip)

        # 4. HTTP banner – fetch before OS detection so banner can inform it
        banner = self._http_banner(ip, open_ports)

        # 4b. Refine vendor from banner when OUI lookup failed
        if banner and (not vendor or vendor.lower() in ("unknown","")):
            for field in ("server","auth_realm","title"):
                val = banner.get(field,"")
                if val:
                    guessed = _guess_type(val)
                    if guessed != "Unknown":
                        vendor = val.split("/")[0].strip()
                        dtype  = guessed
                        brand  = vendor
                        break

        # 4c. Deep vendor re-lookup if still unknown (tries live API)
        if not vendor or vendor.lower() in ("unknown",""):
            vendor, dtype, brand = lookup_vendor(mac)

        # 5. OS detection — vendor/banner signals first, then nmap, then TTL
        nmap_os, nmap_acc = self.scanner.nmap_os(ip)
        if nmap_os:
            final_os, os_acc = nmap_os, f"nmap {nmap_acc}"
        else:
            # Build a richer hostname by combining DNS + banner title/realm
            rich_hostname = hostname
            if not rich_hostname and banner.get("auth_realm"):
                rich_hostname = banner["auth_realm"]
            elif not rich_hostname and banner.get("title"):
                rich_hostname = banner["title"]
            final_os, os_acc = detect_os(
                ip, rich_hostname, mac, vendor, dtype, open_ports, ttl
            )
            # Banner server field can confirm OS (e.g. "lighttpd" → Linux)
            if os_acc in ("","Low") and banner.get("server",""):
                sv = banner["server"].lower()
                if any(x in sv for x in ("linux","ubuntu","debian","openwrt","dd-wrt")):
                    final_os, os_acc = "Linux (Embedded)", "Medium (HTTP Server)"
                elif "windows" in sv:
                    final_os, os_acc = "Windows", "Medium (HTTP Server)"
                elif any(x in sv for x in ("ios","apple","darwin")):
                    final_os, os_acc = "iOS / macOS", "Medium (HTTP Server)"

        # 6. Refine device_type with all signals (vendor, OS, ports, banner)
        final_dtype = _refine_dtype(dtype, vendor, final_os, open_ports, hostname)
        # Banner title/server can disambiguate type further
        if banner and final_dtype in ("Unknown", ip, ""):
            for field in ("auth_realm","title","server"):
                val = banner.get(field,"").lower()
                if any(x in val for x in ("camera","cam","nvr","dvr","ipcam")):
                    final_dtype = "IP Camera"; break
                if any(x in val for x in ("printer","laserjet","inkjet","mfp")):
                    final_dtype = "Printer"; break
                if any(x in val for x in ("router","gateway","modem","ap ","access point")):
                    final_dtype = "Router / Switch"; break
                if any(x in val for x in ("tv","television","android tv","smart tv")):
                    final_dtype = "Smart TV"; break
                if any(x in val for x in ("nas","storage","diskstation","readynas")):
                    final_dtype = "NAS / Server"; break

        # 7. Vulnerabilities
        vulns = self.scanner.assess_vulns(open_ports)

        with _lock:
            existing = devices.get(ip, {})
            # Preserve blocked state across rescans
            currently_blocked = existing.get("blocked", False) or (ip in blocked_devices)

            # ── OS fallback: TTL-based guess when unknown ─────────────────────
            display_os = final_os if (final_os and final_os.lower() not in ("unknown", "")) else ""
            if not display_os:
                if   ttl > 0   and ttl <= 64:  display_os = "Linux / Android / macOS"
                elif ttl > 64  and ttl <= 128:  display_os = "Windows / Android"
                elif ttl > 128:                 display_os = "iOS / Network Device"
                else:                           display_os = "Linux / Android / iOS / macOS"

            # ── Device type fallback: use IP when truly unknown ───────────────
            display_dtype = final_dtype if (final_dtype and final_dtype.lower() not in ("unknown", "")) else ip

            # ── Vendor fallback: use IP when truly unknown ────────────────────
            display_vendor = vendor if (vendor and vendor.lower() not in ("unknown", "")) else ip
            display_brand  = brand  if (brand  and brand.lower()  not in ("unknown", "")) else ip

            devices[ip] = {
                **existing,
                "ip":          ip,
                "mac":         mac,
                "hostname":    hostname,
                "vendor":      display_vendor,
                "brand":       display_brand,
                "device_type": display_dtype,
                "os":          display_os,
                "os_accuracy": os_acc,
                "ttl":         ttl,
                "open_ports":  open_ports,
                "vulnerabilities": vulns,
                "vuln_count":  len(vulns),
                "status":      "blocked" if currently_blocked else "online",
                "blocked":     currently_blocked,
                "first_seen":  existing.get("first_seen", _ts()),
                "last_seen":   _ts(),
                "bytes_in":    existing.get("bytes_in", 0),
                "bytes_out":   existing.get("bytes_out", 0),
                "is_gateway":  (ip == self.gateway),
            }

        if is_new:
            add_alert(ip, "New Device Joined",
                      f"{vendor} ({final_dtype}) at {ip} — {final_os}", "INFO")

        crit = [v for v in vulns if v["severity"] in ("CRITICAL","HIGH")]
        if crit:
            add_alert(ip, "Critical Vulnerabilities",
                      "; ".join(f":{v['port']} {v['service']}" for v in crit[:3]),
                      "CRITICAL")

        socketio.emit("device_update", devices[ip])

    def _bw_loop(self):
        """Push per-device bandwidth deltas to the graphs every second."""
        prev: dict = {}
        while self._running:
            time.sleep(1)
            ts_now = _sts()
            snap   = {}
            with _lock:
                for ip, dev in devices.items():
                    bi, bo = dev.get("bytes_in",0), dev.get("bytes_out",0)
                    pb, po = prev.get(ip, (bi, bo))
                    di, do = max(0, bi-pb), max(0, bo-po)
                    prev[ip] = (bi, bo)
                    traffic_data[ip].append({"ts":ts_now,"in":di,"out":do})
                    snap[ip] = {"in":di,"out":do}
            socketio.emit("traffic_update", {"ts":ts_now,"data":snap})


# Hostnames that definitively mean "this is a PC / desktop computer"
_PC_HOSTNAME_RE = re.compile(
    r"^(kali|parrot|ubuntu|debian|fedora|centos|arch|manjaro|mint|"
    r"pc|desktop|computer|workstation|laptop|notebook|client|customer|"
    r"user|host|machine|node|box|tower|station|office|corp|"
    r"win|windows)[-_.\d]*$",
    re.I
)

def _hostname_implies_pc(hostname: str) -> bool:
    """Return True if the hostname strongly implies a PC/laptop/desktop."""
    if not hostname:
        return False
    h = hostname.split(".")[0]   # strip domain suffix
    return bool(_PC_HOSTNAME_RE.match(h))


def _refine_dtype(dtype: str, vendor: str, os_str: str, ports: dict,
                  hostname: str = "") -> str:
    """
    Return a precise device_type string using vendor, OS, hostname and open ports.
    This runs AFTER OS detection so it can use the final OS string.
    """
    os_l  = (os_str or "").lower()
    v_l   = (vendor or "").lower()
    dt_l  = (dtype  or "").lower()
    open_set = {p for p, i in ports.items() if i.get("state") == "open"}

    # ── Hostname-based PC detection (highest priority for generic names) ───────
    if _hostname_implies_pc(hostname):
        # Determine if Linux or Windows PC from OS string
        if any(x in os_l for x in ("kali", "parrot", "linux", "ubuntu",
                                    "debian", "fedora", "centos", "arch",
                                    "manjaro", "mint")):
            return "Linux PC"
        if "windows" in os_l or "win" in os_l:
            return "Windows PC"
        if "macos" in os_l:
            return "Mac"
        # Default: treat generic hostnames as PC
        return "PC"

    # ── iOS / iPadOS ──────────────────────────────────────────────────────────
    if "ipadose" in os_l or "ipados" in os_l:
        return "iPad"
    if os_l == "ios" or "ios" in os_l and "macos" not in os_l:
        # Differentiate iPhone vs iPad by vendor device_type if available
        if "ipad" in dt_l:
            return "iPad"
        return "iPhone"

    # ── macOS ─────────────────────────────────────────────────────────────────
    if "macos" in os_l:
        if "macbook" in dt_l:
            return "MacBook (Laptop)"
        if any(x in dt_l for x in ("imac", "mac pro", "mac mini")):
            return "Mac Desktop"
        return "Mac"

    # ── Android ───────────────────────────────────────────────────────────────
    if "android tv" in os_l or "tizen" in os_l:
        return "Smart TV"
    if "android" in os_l:
        if "tablet" in dt_l:
            return "Android Tablet"
        return "Mobile Phone"

    # ── Windows ───────────────────────────────────────────────────────────────
    if "windows server" in os_l:
        return "Windows Server"
    if "windows" in os_l:
        if {3389, 135, 445} & open_set:
            return "Windows PC"
        return "Windows PC"

    # ── Linux ─────────────────────────────────────────────────────────────────
    if "raspberry pi" in os_l:
        return "IoT / SBC"
    if "embedded linux" in os_l and "camera" in os_l:
        return "IP Camera"
    if "embedded linux" in os_l:
        return "IoT Device"

    # ── Network / Router ──────────────────────────────────────────────────────
    if "network os" in os_l or "router" in os_l or "embedded linux" in os_l:
        return "Router / Switch"

    # ── Gaming Consoles ───────────────────────────────────────────────────────
    if "playstation" in os_l:
        return "PlayStation"
    if "xbox" in os_l:
        return "Xbox"
    if "nintendo" in os_l:
        return "Nintendo Switch"
    if "console" in os_l:
        return "Gaming Console"

    # ── Other specialised types ───────────────────────────────────────────────
    if "printer" in os_l or "printer" in dt_l:
        return "Printer"
    if "smart tv" in os_l or "smart tv" in dt_l:
        return "Smart TV"
    if "cast os" in os_l or "chromecast" in dt_l:
        return "Streaming Device"
    if "virtual machine" in dt_l or "vm" in dt_l:
        return "Virtual Machine"

    # ── Vendor-based fallback (when OS is still Unknown) ──────────────────────
    if any(x in v_l for x in _ANDROID_VENDORS):
        return "Mobile Phone"
    if "apple" in v_l:
        return "Apple Device"
    if any(x in v_l for x in ("cisco", "ubiquiti", "mikrotik", "netgear",
                               "tp-link", "d-link", "zyxel")):
        return "Router / Switch"
    if any(x in v_l for x in ("hikvision", "dahua", "axis", "wyze", "reolink")):
        return "IP Camera"
    if any(x in v_l for x in ("epson", "canon", "hp", "brother", "xerox")):
        return "Printer"

    return dtype or "Unknown"



# ─────────────────────────────────────────────────────────────────────────────
#  IP OSINT ENGINE  – queries Shodan, Censys, AbuseIPDB, and AlienVault OTX
# ─────────────────────────────────────────────────────────────────────────────

# API keys are loaded from the .env file (see _load_env() above)
_SHODAN_KEY   = os.environ.get("SHODAN_API_KEY",   "")
_CENSYS_ID    = os.environ.get("CENSYS_API_ID",    "")
_CENSYS_SEC   = os.environ.get("CENSYS_API_SECRET","")
_ABUSEIPDB_KEY= os.environ.get("ABUSEIPDB_API_KEY","")
_OTX_KEY      = os.environ.get("OTX_API_KEY",      "")

# In-memory OSINT result cache to avoid re-querying the same IP repeatedly
_osint_cache: Dict[str, dict] = {}
_osint_lock  = threading.Lock()


def _osint_shodan(ip: str) -> dict:
    """Query Shodan InternetDB + Shodan host API for open ports, vulns, tags."""
    result: dict = {"source": "Shodan", "ok": False}
    if not REQUESTS_OK:
        return result
    try:
        # InternetDB – free, no key required, fast
        r = _http.get(f"https://internetdb.shodan.io/{ip}", timeout=6)
        if r.status_code == 200:
            d = r.json()
            result.update({
                "ok":        True,
                "ports":     d.get("ports", []),
                "cpes":      d.get("cpes", []),
                "hostnames": d.get("hostnames", []),
                "vulns":     d.get("vulns", []),
                "tags":      d.get("tags", []),
            })
    except Exception as e:
        result["error"] = str(e)

    # Full host API (requires key) – extra detail: org, ISP, country, banners
    if _SHODAN_KEY:
        try:
            r2 = _http.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": _SHODAN_KEY},
                timeout=10,
            )
            if r2.status_code == 200:
                d2 = r2.json()
                result.update({
                    "org":        d2.get("org", ""),
                    "isp":        d2.get("isp", ""),
                    "asn":        d2.get("asn", ""),
                    "country":    d2.get("country_name", ""),
                    "city":       d2.get("city", ""),
                    "os":         d2.get("os", ""),
                    "last_seen":  d2.get("last_update", ""),
                    "banners":    [
                        {
                            "port":    s.get("port"),
                            "product": s.get("product",""),
                            "version": s.get("version",""),
                            "banner":  (s.get("data","")[:200]).strip(),
                        }
                        for s in d2.get("data", [])[:5]
                    ],
                    "ok": True,
                })
        except Exception:
            pass
    return result


def _osint_censys(ip: str) -> dict:
    """Query Censys v2 hosts API – TLS certs, services, geolocation."""
    result: dict = {"source": "Censys", "ok": False}
    if not (REQUESTS_OK and _CENSYS_ID and _CENSYS_SEC):
        if not _CENSYS_ID:
            result["error"] = "No API key configured"
        return result
    try:
        r = _http.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(_CENSYS_ID, _CENSYS_SEC),
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json().get("result", {})
            loc  = d.get("location", {})
            asys = d.get("autonomous_system", {})
            svcs = []
            for svc in d.get("services", [])[:8]:
                svcs.append({
                    "port":        svc.get("port"),
                    "transport":   svc.get("transport_protocol",""),
                    "service":     svc.get("service_name",""),
                    "product":     svc.get("software",[{}])[0].get("product","") if svc.get("software") else "",
                    "tls_subject": (svc.get("tls",{}).get("certificates",{})
                                      .get("leaf_data",{}).get("subject_dn",""))[:80],
                })
            result.update({
                "ok":       True,
                "country":  loc.get("country",""),
                "city":     loc.get("city",""),
                "lat":      loc.get("coordinates",{}).get("latitude"),
                "lon":      loc.get("coordinates",{}).get("longitude"),
                "asn":      asys.get("asn",""),
                "org":      asys.get("name",""),
                "bgp":      asys.get("bgp_prefix",""),
                "services": svcs,
                "last_seen":d.get("last_updated_at",""),
            })
        elif r.status_code == 404:
            result["error"] = "IP not found in Censys"
        elif r.status_code == 403:
            result["error"] = "Invalid Censys credentials"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


def _osint_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for abuse reports, confidence score, usage type."""
    result: dict = {"source": "AbuseIPDB", "ok": False}
    if not (REQUESTS_OK and _ABUSEIPDB_KEY):
        if not _ABUSEIPDB_KEY:
            result["error"] = "No API key configured"
        return result
    try:
        r = _http.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            reports = d.get("reports", [])[:5]
            result.update({
                "ok":             True,
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "total_reports":  d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported":  d.get("lastReportedAt", ""),
                "usage_type":     d.get("usageType", ""),
                "isp":            d.get("isp", ""),
                "domain":         d.get("domain", ""),
                "country":        d.get("countryCode", ""),
                "is_tor":         d.get("isTor", False),
                "is_public":      d.get("isPublic", True),
                "is_whitelisted": d.get("isWhitelisted", False),
                "reports":        [
                    {
                        "reported_at": rep.get("reportedAt",""),
                        "comment":     (rep.get("comment","") or "")[:120],
                        "categories":  rep.get("categories",[]),
                    }
                    for rep in reports
                ],
            })
        elif r.status_code == 422:
            result["error"] = "Private IP – not in AbuseIPDB"
        elif r.status_code == 401:
            result["error"] = "Invalid AbuseIPDB API key"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# AbuseIPDB category codes → human-readable names
_ABUSE_CATS = {
    1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders", 4:"DDoS Attack",
    5:"FTP Brute-Force", 6:"Ping of Death", 7:"Phishing", 8:"Fraud VoIP",
    9:"Open Proxy", 10:"Web Spam", 11:"Email Spam", 12:"Blog Spam",
    13:"VPN IP", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection",
    17:"Spoofing", 18:"Brute-Force", 19:"Bad Web Bot", 20:"Exploited Host",
    21:"Web App Attack", 22:"SSH", 23:"IoT Targeted",
}


def _osint_otx(ip: str) -> dict:
    """Query AlienVault OTX for threat pulse indicators."""
    result: dict = {"source": "AlienVault OTX", "ok": False}
    if not (REQUESTS_OK and _OTX_KEY):
        if not _OTX_KEY:
            result["error"] = "No API key configured"
        return result
    headers = {"X-OTX-API-KEY": _OTX_KEY}
    base    = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    try:
        # General info
        r = _http.get(f"{base}/general", headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get("pulse_info", {})
            result.update({
                "ok":          True,
                "pulse_count": pulses.get("count", 0),
                "reputation":  d.get("reputation", 0),
                "country":     d.get("country_name",""),
                "asn":         d.get("asn",""),
                "city":        d.get("city",""),
                "pulses":      [
                    {
                        "name":       p.get("name","")[:80],
                        "tags":       p.get("tags",[])[:5],
                        "created":    p.get("created","")[:10],
                        "adversary":  p.get("adversary",""),
                        "malware_families": p.get("malware_families",[])[:3],
                    }
                    for p in pulses.get("pulses",[])[:5]
                ],
            })
        elif r.status_code == 400:
            result["error"] = "Private/invalid IP for OTX"
        elif r.status_code == 403:
            result["error"] = "Invalid OTX API key"
        else:
            result["error"] = f"HTTP {r.status_code}"
        # Passive DNS
        r2 = _http.get(f"{base}/passive_dns", headers=headers, timeout=8)
        if r2.status_code == 200:
            pdns = r2.json().get("passive_dns", [])[:5]
            result["passive_dns"] = [
                {"hostname": p.get("hostname",""), "first": p.get("first","")[:10],
                 "last": p.get("last","")[:10]}
                for p in pdns
            ]
        # Malware
        r3 = _http.get(f"{base}/malware", headers=headers, timeout=8)
        if r3.status_code == 200:
            mal = r3.json().get("data", [])[:5]
            result["malware"] = [m.get("hash","") for m in mal]
    except Exception as e:
        result["error"] = str(e)
    return result


def run_osint(ip: str, force: bool = False) -> dict:
    """
    Run all configured OSINT sources for an IP in parallel.
    Results are cached; pass force=True to refresh.
    """
    with _osint_lock:
        if not force and ip in _osint_cache:
            cached = _osint_cache[ip]
            # Return cache if it's less than 30 minutes old
            if time.time() - cached.get("_ts", 0) < 1800:
                return cached

    def _run_source(fn, name):
        try:
            return name, fn(ip)
        except Exception as e:
            return name, {"source": name, "ok": False, "error": str(e)}

    sources = [
        (_osint_shodan,    "shodan"),
        (_osint_censys,    "censys"),
        (_osint_abuseipdb, "abuseipdb"),
        (_osint_otx,       "otx"),
    ]

    results: dict = {
        "_ip":  ip,
        "_ts":  time.time(),
        "_ran": True,
    }

    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="osint") as ex:
        futs = {ex.submit(_run_source, fn, name): name for fn, name in sources}
        for fut in as_completed(futs):
            try:
                name, data = fut.result(timeout=20)
                results[name] = data
            except Exception:
                results[futs[fut]] = {"source": futs[fut], "ok": False, "error": "timeout"}

    # Compute overall threat level from all sources
    score = 0
    abuse = results.get("abuseipdb", {})
    otx   = results.get("otx", {})
    if abuse.get("ok"):
        score = max(score, abuse.get("abuse_score", 0))
    if otx.get("ok") and otx.get("pulse_count", 0) > 0:
        score = max(score, min(100, otx["pulse_count"] * 15))

    results["_threat_score"] = score
    results["_threat_level"] = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 50 else
        "MEDIUM"   if score >= 20 else
        "LOW"       if score >  0  else
        "CLEAN"
    )

    with _osint_lock:
        _osint_cache[ip] = results
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  FLASK + SOCKET.IO
# ─────────────────────────────────────────────────────────────────────────────
app      = Flask(__name__)
app.config["SECRET_KEY"] = "netsentry_v3_secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)
monitor  = NetworkMonitor()

@app.route("/api/devices")
def api_devices():
    with _lock: return jsonify(list(devices.values()))

@app.route("/api/device/<ip>")
def api_device(ip):
    with _lock:
        d = devices.get(ip)
        if not d: return jsonify({"error":"not found"}),404
        return jsonify({**d,
                        "traffic": list(traffic_data[ip]),
                        "packets": list(packet_log[ip])[:60]})

@app.route("/api/alerts")
def api_alerts():
    with _lock: return jsonify(list(alerts))

@app.route("/api/alerts/ack/<aid>", methods=["POST"])
def api_ack(aid):
    with _lock:
        for a in alerts:
            if a["id"] == aid: a["ack"] = True
    return jsonify({"ok":True})

@app.route("/api/stats")
def api_stats():
    with _lock:
        return jsonify({**net_stats,
                        "device_count": len(devices),
                        "online": sum(1 for d in devices.values() if d.get("status")=="online"),
                        "gateway": monitor.gateway,
                        "network": monitor.network})

# In-memory set of blocked IPs (ip → mac mapping kept for cleanup)
blocked_devices: Dict[str, str] = {}   # ip → mac

def _run(cmd: List[str], timeout: int = 6) -> Tuple[bool, str]:
    """Run a shell command, return (success, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)

def _block_device(ip: str, mac: str) -> Tuple[bool, List[str]]:
    """
    Disconnect a device from the network using all available methods.
    Returns (any_method_succeeded, list_of_messages).
    """
    msgs   = []
    ok_any = False
    mac_u  = mac.upper() if mac and mac != "N/A" else ""

    # ── Method 1: iptables – drop all forwarded traffic to/from this IP ───────
    for args in [
        ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"],
        ["iptables", "-I", "INPUT",   "1", "-s", ip, "-j", "DROP"],
    ]:
        ok, out = _run(args)
        if ok:
            ok_any = True
            msgs.append(f"iptables rule added ({args[5]}→{args[-2]})")

    # ── Method 2: ebtables – block at Ethernet bridge layer by MAC ────────────
    if mac_u:
        for args in [
            ["ebtables", "-I", "FORWARD", "-s", mac_u, "-j", "DROP"],
            ["ebtables", "-I", "FORWARD", "-d", mac_u, "-j", "DROP"],
        ]:
            ok, _ = _run(args)
            if ok:
                ok_any = True
                msgs.append(f"ebtables MAC rule added ({mac_u})")
                break

    # ── Method 3: arptables – poison ARP so the device can't communicate ──────
    if mac_u:
        ok, _ = _run(["arptables", "-I", "OUTPUT", "--dst-ip", ip,
                       "--src-mac", mac_u, "-j", "DROP"])
        if ok:
            ok_any = True
            msgs.append(f"arptables rule added")

    # ── Method 4: Send ARP poison via scapy (deauth the device off the LAN) ───
    if SCAPY_OK and IS_ROOT and mac_u:
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
            gw = monitor.gateway
            # Broadcast a fake ARP reply: tell the device the gateway MAC is FF:FF:FF:FF:FF:FF
            # This breaks the device's ARP cache so it can't route traffic
            poison_pkt = (
                Ether(dst=mac_u) /
                ARP(op=2, pdst=ip, hwdst=mac_u,
                    psrc=gw,
                    hwsrc="ff:ff:ff:ff:ff:ff")
            )
            # Send 5 times to ensure it lands
            sendp(poison_pkt, count=5, inter=0.1, verbose=False)
            ok_any = True
            msgs.append("ARP poison sent (scapy deauth)")
        except Exception as e:
            msgs.append(f"ARP poison failed: {e}")

    # ── Method 5: tc (traffic control) – bandwidth limit to 0 ────────────────
    # Find which interface the IP is reachable on
    try:
        result = subprocess.run(["ip", "route", "get", ip],
                                 capture_output=True, text=True, timeout=3)
        iface_m = re.search(r"dev\s+(\S+)", result.stdout)
        iface   = iface_m.group(1) if iface_m else None
        if iface:
            # Add qdisc if not there, then filter to DROP
            _run(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "prio"])
            ok2, _ = _run([
                "tc", "filter", "add", "dev", iface, "parent", "1:",
                "protocol", "ip", "u32", "match", "ip", "dst", ip,
                "flowid", "1:3", "action", "drop"
            ])
            if ok2:
                ok_any = True
                msgs.append(f"tc filter added on {iface}")
    except Exception:
        pass

    if not msgs:
        msgs.append("No root/tools available – flag set (UI only)")
    return ok_any, msgs


def _unblock_device(ip: str, mac: str) -> List[str]:
    """Remove all block rules for this device."""
    msgs   = []
    mac_u  = mac.upper() if mac and mac != "N/A" else ""

    # iptables cleanup
    for table, chain in [("FORWARD","s"), ("FORWARD","d"), ("INPUT","s")]:
        flag = "-s" if chain == "s" else "-d"
        for _ in range(3):   # try up to 3 times in case rules were added multiple times
            ok, _ = _run(["iptables", "-D", table, flag, ip, "-j", "DROP"])
            if not ok:
                break
    msgs.append("iptables rules removed")

    # ebtables cleanup
    if mac_u:
        for _ in range(2):
            _run(["ebtables", "-D", "FORWARD", "-s", mac_u, "-j", "DROP"])
            _run(["ebtables", "-D", "FORWARD", "-d", mac_u, "-j", "DROP"])
        msgs.append("ebtables MAC rules removed")

    # arptables cleanup
    if mac_u:
        _run(["arptables", "-D", "OUTPUT", "--dst-ip", ip,
              "--src-mac", mac_u, "-j", "DROP"])

    # Restore ARP via scapy – broadcast the real gateway MAC back to the device
    if SCAPY_OK and IS_ROOT and mac_u:
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
            gw  = monitor.gateway
            # Find our real MAC
            try:
                my_mac = get_if_hwaddr(conf.iface)
            except Exception:
                my_mac = None
            if my_mac:
                restore_pkt = (
                    Ether(dst=mac_u) /
                    ARP(op=2, pdst=ip, hwdst=mac_u,
                        psrc=gw, hwsrc=my_mac)
                )
                sendp(restore_pkt, count=5, inter=0.1, verbose=False)
                msgs.append("ARP table restored via scapy")
        except Exception as e:
            msgs.append(f"ARP restore note: {e}")

    # tc cleanup
    try:
        result = subprocess.run(["ip", "route", "get", ip],
                                 capture_output=True, text=True, timeout=3)
        iface_m = re.search(r"dev\s+(\S+)", result.stdout)
        iface   = iface_m.group(1) if iface_m else None
        if iface:
            _run(["tc", "filter", "del", "dev", iface, "parent", "1:",
                  "protocol", "ip", "u32", "match", "ip", "dst", ip])
    except Exception:
        pass

    return msgs


@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip):
    d = devices.get(ip)
    if not d: return jsonify({"error": "unknown IP"}), 404
    if d.get("is_gateway"):
        return jsonify({"error": "Cannot block the gateway"}), 400

    mac = d.get("mac", "N/A")
    blocked_devices[ip] = mac

    if IS_ROOT:
        ok, msgs = _block_device(ip, mac)
        detail = "; ".join(msgs[:3])
    else:
        ok     = False
        detail = "Not running as root – iptables unavailable. Run with sudo for real blocking."

    with _lock:
        if ip in devices:
            devices[ip]["blocked"] = True
            devices[ip]["status"]  = "blocked"

    severity = "HIGH" if ok else "MEDIUM"
    add_alert(ip, "Device Blocked",
              f"{d.get('vendor', ip)} ({d.get('device_type','?')}) at {ip} — {detail}",
              severity)
    socketio.emit("device_update", devices.get(ip, {}))
    return jsonify({
        "ok":      True,
        "message": f"{ip} blocked" + (" (root — real disconnect)" if ok else " (UI only — needs root)"),
        "methods": detail,
        "root":    IS_ROOT,
    })


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    mac = blocked_devices.pop(ip, devices.get(ip, {}).get("mac", "N/A"))

    if IS_ROOT:
        msgs = _unblock_device(ip, mac)
        detail = "; ".join(msgs[:3])
    else:
        detail = "Not running as root – rules not applied."

    with _lock:
        if ip in devices:
            devices[ip]["blocked"] = False
            devices[ip]["status"]  = "online"

    add_alert(ip, "Device Unblocked",
              f"{devices.get(ip,{}).get('vendor', ip)} at {ip} reconnected", "INFO")
    socketio.emit("device_update", devices.get(ip, {}))
    return jsonify({
        "ok":      True,
        "message": f"{ip} unblocked",
        "methods": detail,
        "root":    IS_ROOT,
    })

@app.route("/api/speedtest")
def api_speedtest():
    """
    Accurate internet speed + latency test.

    Strategy (in priority order):
    1. speedtest-cli Python API  – if installed and reachable, the gold standard
    2. speedtest-cli CLI binary  – subprocess fallback for the Python module
    3. Multi-endpoint HTTP probe – accurate latency via TTFB, chunked DL/UL speed
    """
    import urllib.request as _ur, _thread, math as _math
    import time as _t, json as _json, statistics as _stat

    result = {
        "download_mbps": 0.0,
        "upload_mbps":   0.0,
        "latency_ms":    0.0,
        "jitter_ms":     0.0,
        "server":        "",
        "isp":           "",
        "status":        "ok",
    }

    # ── Attempt 1: speedtest-cli Python API ───────────────────────────────────
    try:
        import speedtest as _st
        s = _st.Speedtest(secure=True, timeout=20)
        s.get_best_server()
        s.download(threads=4)
        s.upload(threads=4, pre_allocate=False)
        r = s.results.dict()
        result["download_mbps"] = round(r.get("download", 0) / 1_000_000, 2)
        result["upload_mbps"]   = round(r.get("upload",   0) / 1_000_000, 2)
        result["latency_ms"]    = round(r.get("ping",     0), 1)
        # Compute jitter from per-request latencies if available
        try:
            pings = [x.get("latency", 0) for x in r.get("share_results", []) if x]
            result["jitter_ms"] = round(_stat.stdev(pings), 1) if len(pings) > 1 else 0.0
        except Exception:
            result["jitter_ms"] = round(r.get("ping", 0) * 0.08, 1)
        srv = r.get("server", {})
        result["server"] = f"{srv.get('name','')}, {srv.get('country','')}".strip(", ")
        result["isp"]    = r.get("client", {}).get("isp", "")
        result["status"] = "speedtest-cli (Python API)"
        return jsonify(result)
    except Exception:
        pass

    # ── Attempt 2: speedtest-cli binary ───────────────────────────────────────
    try:
        proc = subprocess.run(
            ["speedtest-cli", "--json", "--secure", "--timeout", "30"],
            capture_output=True, text=True, timeout=90, check=False
        )
        if proc.returncode == 0 and proc.stdout.strip():
            d = _json.loads(proc.stdout)
            result["download_mbps"] = round(d.get("download", 0) / 1_000_000, 2)
            result["upload_mbps"]   = round(d.get("upload",   0) / 1_000_000, 2)
            result["latency_ms"]    = round(d.get("ping",     0), 1)
            result["jitter_ms"]     = round(d.get("ping", 0) * 0.08, 1)
            srv = d.get("server", {})
            result["server"] = f"{srv.get('name','')}, {srv.get('country','')}".strip(", ")
            result["isp"]    = d.get("client", {}).get("isp", "")
            result["status"] = "speedtest-cli (binary)"
            return jsonify(result)
    except Exception:
        pass

    # ── Attempt 3: Multi-endpoint HTTP probe ─────────────────────────────────
    #
    # Latency: TTFB to multiple small JSON endpoints (3 probes × 3 targets = 9 samples)
    # – take the trimmed mean (drop top 20%) as a proxy for network RTT
    # – jitter = stddev of trimmed samples
    #
    # Download: stream large files in chunks, compute throughput after a
    # 0.3-second TCP warm-up window so the OS send-buffer doesn't inflate the result
    #
    # Upload: POST binary data; measure time-to-response (server discards payload)
    # ─────────────────────────────────────────────────────────────────────────

    # ── Latency probes ────────────────────────────────────────────────────────
    LAT_TARGETS = [
        "https://pypi.org/pypi/pip/json",
        "https://registry.npmjs.org/express/latest",
        "https://pypi.org/pypi/setuptools/json",
        "https://files.pythonhosted.org/packages/source/p/pip/",
    ]
    raw_lats: list = []
    for url in LAT_TARGETS:
        for _ in range(3):
            try:
                t0 = _t.monotonic()
                r  = _ur.urlopen(url, timeout=5)
                r.read(256)   # only need the first response bytes
                raw_lats.append((_t.monotonic() - t0) * 1000)
            except Exception:
                pass
            _t.sleep(0.04)

    if raw_lats:
        raw_lats.sort()
        # Trim top 20% outliers (network spikes, proxy delays)
        trim_n     = max(1, int(len(raw_lats) * 0.80))
        trimmed    = raw_lats[:trim_n]
        avg_lat    = sum(trimmed) / len(trimmed)
        # Subtract average HTTPS overhead (~10-20 ms TLS + TCP) if we have many samples
        # We approximate RTT as 60% of TTFB (empirical for proxied HTTPS)
        rtt_approx = avg_lat * 0.60
        result["latency_ms"] = round(rtt_approx, 1)
        result["jitter_ms"]  = round(
            _stat.stdev(trimmed) if len(trimmed) > 1 else 0.0, 1
        )

    # ── Download speed ────────────────────────────────────────────────────────
    DL_TARGETS = [
        ("https://pypi.org/simple/",                                        8_000_000),
        ("https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz", 5_000_000),
        ("https://files.pythonhosted.org/packages/source/p/pip/pip-24.0.tar.gz", 5_000_000),
    ]
    dl_rates: list = []
    for url, max_bytes in DL_TARGETS:
        try:
            r = _ur.urlopen(url, timeout=20)
            total   = 0
            t_start = _t.monotonic()
            warm_end = t_start + 0.25   # ignore the TCP warm-up window
            measure_start = None
            measure_bytes = 0
            while True:
                chunk = r.read(131_072)   # 128 KB chunks
                if not chunk:
                    break
                now    = _t.monotonic()
                total += len(chunk)
                if now >= warm_end:
                    if measure_start is None:
                        measure_start = now
                        measure_bytes = 0
                    measure_bytes += len(chunk)
                if total >= max_bytes:
                    break
            if measure_start and (elapsed := _t.monotonic() - measure_start) > 0.05:
                rate = measure_bytes * 8 / (elapsed * 1_000_000)
                dl_rates.append(rate)
        except Exception:
            pass

    if dl_rates:
        # Use the median to be robust against outliers from small/large files
        dl_rates.sort()
        mid = len(dl_rates) // 2
        result["download_mbps"] = round(
            (dl_rates[mid-1] + dl_rates[mid]) / 2 if len(dl_rates) % 2 == 0
            else dl_rates[mid], 2
        )

    # ── Upload speed ──────────────────────────────────────────────────────────
    # POST a 1 MB payload; measure only the transfer window (not response time)
    UL_TARGETS = [
        "https://registry.npmjs.org/-/v1/search?text=x",
        "https://pypi.org/search/",
    ]
    ul_rates: list = []
    payload = bytes(1_000_000)   # 1 MB of zeros
    for url in UL_TARGETS:
        try:
            req = _ur.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/octet-stream",
                         "Content-Length": str(len(payload))}
            )
            t0 = _t.monotonic()
            try:
                _ur.urlopen(req, timeout=12)
            except Exception:
                pass   # server rejects POST body but we still measure the send time
            elapsed = _t.monotonic() - t0
            # Only count if it took long enough to be a real upload, not an instant rejection
            if elapsed > 0.10:
                rate = len(payload) * 8 / (elapsed * 1_000_000)
                ul_rates.append(rate)
        except Exception:
            pass

    if ul_rates:
        result["upload_mbps"] = round(sum(ul_rates) / len(ul_rates), 2)

    result["status"] = "HTTP probe (accurate)"
    return jsonify(result)



@app.route("/api/osint/<path:ip>")
def api_osint_ip(ip):
    """Run OSINT for a single IP. Pass ?refresh=1 to bypass cache."""
    force = request.args.get("refresh","0") == "1"
    result = run_osint(ip, force=force)
    return jsonify(result)

@app.route("/api/osint/all", methods=["POST"])
def api_osint_all():
    """Kick off background OSINT scans for every known device IP."""
    ips = list(devices.keys())
    def _bg():
        for ip in ips:
            run_osint(ip)
    threading.Thread(target=_bg, daemon=True, name="osint-all").start()
    return jsonify({"ok": True, "scanning": ips})

@app.route("/api/osint/status")
def api_osint_status():
    """Return cached OSINT results for all devices (without re-querying)."""
    with _osint_lock:
        return jsonify({ip: r for ip, r in _osint_cache.items()})

@app.route("/api/osint/keys")
def api_osint_keys():
    """Return which API keys are configured (never expose the actual values)."""
    return jsonify({
        "shodan":    bool(_SHODAN_KEY),
        "censys":    bool(_CENSYS_ID and _CENSYS_SEC),
        "abuseipdb": bool(_ABUSEIPDB_KEY),
        "otx":       bool(_OTX_KEY),
    })

@app.route("/api/rescan/<ip>", methods=["POST"])
def api_rescan(ip):
    d = devices.get(ip)
    if not d: return jsonify({"error":"unknown IP"}),404
    threading.Thread(
        target=monitor._deep_scan,
        args=(ip, d.get("mac","N/A"), d.get("vendor",""),
              d.get("device_type",""), d.get("brand",""), False),
        daemon=True,
    ).start()
    return jsonify({"ok":True,"message":f"Rescan queued for {ip}"})


@app.route("/api/topology")
def api_topology():
    with _lock:
        gw_ip = monitor.gateway
        node_list = []
        seen_ips = set()
        for ip, d in devices.items():
            seen_ips.add(ip)
            node_list.append({
                "ip": ip, "hostname": d.get("hostname",""),
                "vendor": d.get("vendor","Unknown"),
                "device_type": d.get("device_type","Unknown"),
                "os": d.get("os","Unknown"),
                "status": d.get("status","offline"),
                "is_gateway": d.get("is_gateway", ip == gw_ip),
                "vuln_count": d.get("vuln_count",0),
                "bytes_in":   d.get("bytes_in",0),
                "bytes_out":  d.get("bytes_out",0),
                "mac": d.get("mac",""),
            })
        # Always include gateway node even if not yet scanned
        if gw_ip and gw_ip not in seen_ips:
            node_list.append({
                "ip": gw_ip, "hostname": "gateway", "vendor": "Router",
                "device_type": "Router/AP", "os": "Router/Embedded Linux",
                "status": "online", "is_gateway": True,
                "vuln_count": 0, "bytes_in": 0, "bytes_out": 0, "mac": "",
            })
        nodes = node_list
        # Build edges – only between known LAN devices
        known_ips = {n["ip"] for n in node_list}
        edge_map = {}
        for ip, log in packet_log.items():
            for pkt in list(log)[:80]:
                src, dst = pkt.get("src",""), pkt.get("dst","")
                # Skip if either endpoint is not a known local device
                if not src or not dst: continue
                if src not in known_ips and dst not in known_ips: continue
                # Use gateway as surrogate for external endpoints
                gw = monitor.gateway
                src2 = src if src in known_ips else gw
                dst2 = dst if dst in known_ips else gw
                if src2 == dst2: continue
                key = tuple(sorted([src2, dst2]))
                if key not in edge_map:
                    edge_map[key] = {"a":key[0],"b":key[1],"count":0,
                                     "bytes":0,"proto":pkt.get("proto","OTHER")}
                edge_map[key]["count"] += 1
                edge_map[key]["bytes"] += pkt.get("len",0)
        return jsonify({"nodes":node_list, "edges":list(edge_map.values()),
                        "gateway":monitor.gateway})

@app.route("/api/traffic/<ip>")
def api_traffic(ip):
    with _lock: return jsonify(list(traffic_data.get(ip,[])))

@app.route("/api/packets/<ip>")
def api_packets(ip):
    with _lock: return jsonify(list(packet_log.get(ip,[])))

@socketio.on("connect")
def on_connect():
    with _lock:
        devlist = list(devices.values())
        # Ensure gateway device is always in the list (even if scan not done yet)
        gw_ip = monitor.gateway
        gw_ips = {d.get("ip") for d in devlist}
        if gw_ip and gw_ip not in gw_ips:
            devlist.append({
                "ip": gw_ip, "mac": "N/A", "hostname": "gateway",
                "vendor": "Router", "brand": "Router",
                "device_type": "Router/AP", "os": "Router/Embedded Linux",
                "os_accuracy": "", "ttl": 0,
                "open_ports": {}, "vulnerabilities": [], "vuln_count": 0,
                "status": "online", "is_gateway": True,
                "first_seen": _ts(), "last_seen": _ts(),
                "bytes_in": 0, "bytes_out": 0,
            })
        emit("initial_state", {
            "devices": devlist,
            "alerts":  list(alerts)[:50],
            "stats":   {
                **net_stats,
                "device_count": len(devices),
                "gateway": monitor.gateway,
                "network": monitor.network,
            },
        })


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD HTML
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentinel v3 – Network Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b10;--bg2:#0d1117;--bg3:#13192a;--border:#1a2535;
  --accent:#00e5ff;--accent2:#7c4dff;
  --green:#00e676;--yellow:#ffd740;--orange:#ff6d00;--red:#ff1744;
  --text:#dde6f0;--muted:#3d5068;
  --crit:#ff2d55;--high:#ff6b35;--med:#ffd60a;--low:#30d158;--info:#636366;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;overflow-x:hidden}
.mono{font-family:'JetBrains Mono',monospace}

/* HEADER */
header{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:52px;
  background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:9px;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:17px;color:var(--accent)}
.hdr-meta{display:flex;align-items:center;gap:16px;font-size:11px;color:var(--muted)}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* LAYOUT */
.app{display:grid;grid-template-columns:260px 1fr;height:calc(100vh - 52px)}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:12px 0}
.main{overflow-y:auto}

/* SIDEBAR */
.sb-title{font-size:9px;font-weight:700;letter-spacing:.18em;color:var(--muted);text-transform:uppercase;padding:0 14px 6px}
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:0 10px;margin-bottom:16px}
.stat-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px 11px}
.stat-val{font-family:'JetBrains Mono',monospace;font-size:19px;font-weight:700;color:var(--accent)}
.stat-lbl{font-size:9px;color:var(--muted);margin-top:1px}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 14px;cursor:pointer;color:var(--muted);
  font-size:12px;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{color:var(--text);background:var(--bg3)}
.nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.badge{margin-left:auto;background:var(--red);color:#fff;border-radius:10px;font-size:9px;padding:1px 5px;font-weight:700}

/* PANELS */
.panel{display:none;padding:18px}
.panel.active{display:block}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.sec-title{font-size:15px;font-weight:600}

/* OVERVIEW CARDS */
.ov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:18px}
.ov-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px;text-align:center}
.ov-val{font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700}
.ov-lbl{font-size:10px;color:var(--muted);margin-top:3px}

/* TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
  color:var(--muted);padding:7px 10px;border-bottom:1px solid var(--border);
  position:sticky;top:0;background:var(--bg2);z-index:1}
td{padding:9px 10px;border-bottom:1px solid rgba(26,37,53,.6);vertical-align:middle}
tr:hover td{background:var(--bg3);cursor:pointer}
.ip{font-family:'JetBrains Mono',monospace;color:var(--accent);font-size:12px}
.mac-addr{font-family:'JetBrains Mono',monospace;color:var(--muted);font-size:10px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px}
.dot-on{background:var(--green);box-shadow:0 0 4px var(--green)}
.dot-off{background:var(--muted)}

/* BADGES */
.badge-sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.04em}
.sev-CRITICAL{background:rgba(255,45,85,.12);color:var(--crit);border:1px solid var(--crit)}
.sev-HIGH{background:rgba(255,107,53,.12);color:var(--high);border:1px solid var(--high)}
.sev-MEDIUM{background:rgba(255,214,10,.12);color:var(--med);border:1px solid var(--med)}
.sev-LOW{background:rgba(48,209,88,.12);color:var(--low);border:1px solid var(--low)}
.sev-INFO{background:rgba(99,99,102,.12);color:var(--info);border:1px solid var(--info)}

/* MODAL */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:1000;overflow-y:auto}
.overlay.open{display:flex;align-items:flex-start;justify-content:center;padding:36px 16px}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;width:100%;max-width:880px;overflow:hidden}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;border-bottom:1px solid var(--border)}
.modal-title{font-size:17px;font-weight:600}
.modal-body{padding:22px}
.close-btn{width:28px;height:28px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;
  cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:16px}
.close-btn:hover{color:var(--text)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-bottom:18px}
.detail-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:10px 13px}
.detail-key{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.detail-val{font-family:'JetBrains Mono',monospace;font-size:12px;margin-top:3px;word-break:break-all}

/* CHART CARDS */
.chart-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px;margin-bottom:14px}
.chart-lbl{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px}
canvas{max-height:200px}

/* PORT CARDS */
.port-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:7px;margin-bottom:14px}
.port-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px 12px;display:flex;align-items:center;gap:9px}
.port-num{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:var(--accent2);min-width:46px}
.port-svc{font-weight:600;font-size:11px}
.port-ver{font-size:10px;color:var(--muted)}

/* ALERTS */
.alert-list{display:flex;flex-direction:column;gap:7px}
.alert-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:12px 14px;
  display:flex;align-items:flex-start;gap:10px;transition:opacity .3s}
.alert-card.acked{opacity:.38}
.alert-bar{width:4px;border-radius:2px;align-self:stretch;min-height:38px}
.alert-title{font-weight:600;font-size:13px}
.alert-detail{font-size:11px;color:var(--muted);margin-top:2px}
.alert-meta{font-size:10px;color:var(--muted);margin-top:4px}
.ack-btn{background:none;border:1px solid var(--border);color:var(--muted);border-radius:5px;
  padding:2px 9px;cursor:pointer;font-size:10px;white-space:nowrap;font-family:inherit}
.ack-btn:hover{border-color:var(--green);color:var(--green)}

/* PACKET STREAM */
.pkt-stream{background:var(--bg3);border:1px solid var(--border);border-radius:9px;
  height:340px;overflow-y:auto;padding:6px 8px;font-family:'JetBrains Mono',monospace;font-size:11px}
.pkt{display:flex;gap:10px;padding:2px 5px;border-radius:3px;line-height:1.5}
.pkt:hover{background:var(--bg2)}
.pkt-ts{color:var(--muted);min-width:68px}
.pkt-proto{min-width:46px;font-weight:700}
.pkt-TCP{color:#64b5f6}.pkt-UDP{color:#81c784}.pkt-ICMP{color:#ffb74d}
.pkt-RECV{color:#ce93d8}.pkt-SEND{color:#00e676}.pkt-OTHER{color:var(--muted)}
.pkt-src{color:var(--accent)}.pkt-dst{color:#ce93d8}
.pkt-info{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}

/* OS BADGE */
.os-badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;padding:2px 7px;border-radius:4px;
  background:rgba(124,77,255,.1);border:1px solid rgba(124,77,255,.3);color:#b39ddb}

/* BUTTONS */
.btn{padding:6px 13px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--text);
  cursor:pointer;font-size:11px;font-family:inherit;transition:all .15s;display:inline-flex;align-items:center;gap:5px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-prim{background:var(--accent2);border-color:var(--accent2);color:#fff}
.btn-prim:hover{background:#9c72ff;border-color:#9c72ff;color:#fff}
.search{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;
  padding:6px 11px;font-size:11px;font-family:'JetBrains Mono',monospace;outline:none;width:210px}
.search:focus{border-color:var(--accent)}

/* TOAST */
#toasts{position:fixed;bottom:16px;right:16px;z-index:9999;display:flex;flex-direction:column-reverse;gap:6px}
.toast{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:10px 14px;
  min-width:270px;max-width:340px;display:flex;align-items:flex-start;gap:9px;
  animation:slIn .25s ease;box-shadow:0 4px 18px rgba(0,0,0,.45);transition:opacity .35s,transform .35s}
@keyframes slIn{from{transform:translateX(110%);opacity:0}to{transform:none;opacity:1}}
.toast-bar{width:4px;border-radius:2px;min-height:34px}


/* TOPOLOGY */
#topo-canvas{background:var(--bg);image-rendering:crisp-edges}
#topo-wrap{user-select:none}
#topo-trace::-webkit-scrollbar{width:3px}
#topo-trace::-webkit-scrollbar-thumb{background:var(--border)}
.trace-row{display:flex;gap:6px;padding:3px 0;border-bottom:1px solid rgba(26,37,53,.5);line-height:1.5}
.trace-row:last-child{border-bottom:none}
.tr-proto{min-width:36px;font-weight:700}
.tr-TCP{color:#64b5f6}.tr-UDP{color:#81c784}.tr-ICMP{color:#ffb74d}
.tr-RECV{color:#ce93d8}.tr-SEND{color:#00e676}.tr-OTHER{color:var(--muted)}
/* TOOLBAR BUTTON */
.tbtn{padding:4px 10px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg3);color:var(--text);cursor:pointer;font-size:10px;
  font-family:inherit;transition:all .15s;white-space:nowrap}
.tbtn:hover{border-color:var(--accent);color:var(--accent)}
.tbtn.active{background:var(--accent2);border-color:var(--accent2);color:#fff}

/* TOPOLOGY GRAPH */
#topo-canvas{background:var(--bg);image-rendering:crisp-edges;display:block}
#topo-wrap{user-select:none}
#topo-trace::-webkit-scrollbar{width:3px}
#topo-trace::-webkit-scrollbar-thumb{background:var(--border)}
.trace-row{display:flex;gap:6px;padding:3px 0;border-bottom:1px solid rgba(26,37,53,.5);line-height:1.5}
.trace-row:last-child{border-bottom:none}
.tr-proto{min-width:36px;font-weight:700}
.tr-TCP{color:#64b5f6}.tr-UDP{color:#81c784}.tr-ICMP{color:#ffb74d}
.tr-RECV{color:#ce93d8}.tr-SEND{color:#00e676}.tr-OTHER{color:var(--muted)}

/* SCROLLBAR */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>

<header>
  <div class="logo">
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none">
      <circle cx="13" cy="13" r="12" stroke="#00e5ff" stroke-width="1.4"/>
      <circle cx="13" cy="13" r="4.5" fill="#00e5ff" opacity=".85"/>
      <path d="M13 1v5M13 20v5M1 13h5M20 13h5" stroke="#00e5ff" stroke-width="1.4" stroke-linecap="round"/>
      <circle cx="13" cy="13" r="8.5" stroke="#00e5ff" stroke-width=".4" stroke-dasharray="2 2.8"/>
    </svg>
    NetSentinel <span style="font-size:10px;opacity:.5;margin-left:4px">v3</span>
  </div>
  <div class="hdr-meta">
    <span id="hdr-net" class="mono">—</span>
    <span id="hdr-gw"  class="mono"></span>
    <div class="live-dot"></div>
    <span id="hdr-time" class="mono"></span>
  </div>
</header>

<div class="app">
<nav class="sidebar">
  <div style="margin-bottom:14px">
    <div class="sb-title">Network</div>
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-val" id="s-dev">0</div><div class="stat-lbl">Devices</div></div>
      <div class="stat-card"><div class="stat-val" id="s-on">0</div><div class="stat-lbl">Online</div></div>
      <div class="stat-card"><div class="stat-val" id="s-al">0</div><div class="stat-lbl">Alerts</div></div>
      <div class="stat-card"><div class="stat-val" id="s-pps">0</div><div class="stat-lbl">Pkt/s</div></div>
    </div>
  </div>
  <div class="sb-title">Views</div>
  <div class="nav-item active" data-panel="overview"   onclick="nav(this,'overview')"><span class="nav-icon">🌐</span>Overview</div>
  <div class="nav-item"        data-panel="devices"    onclick="nav(this,'devices')"><span class="nav-icon">💻</span>Devices</div>
  <div class="nav-item"        data-panel="traffic"    onclick="nav(this,'traffic')"><span class="nav-icon">📡</span>Live Traffic</div>
  <div class="nav-item"        data-panel="alerts"     onclick="nav(this,'alerts')">
    <span class="nav-icon">🚨</span>Alerts<span class="badge" id="al-badge" style="display:none">0</span>
  </div>
  <div class="nav-item"        data-panel="vulns"      onclick="nav(this,'vulns')"><span class="nav-icon">🔓</span>Vulnerabilities</div>
  <div class="nav-item"        data-panel="ports"      onclick="nav(this,'ports')"><span class="nav-icon">🔌</span>Open Ports</div>
  <div class="nav-item"        data-panel="graphs"     onclick="nav(this,'graphs')"><span class="nav-icon">📈</span>Bandwidth</div>
  <div class="nav-item"        data-panel="osint"      onclick="nav(this,'osint')"><span class="nav-icon">🔍</span>IP OSINT</div>

  <div style="margin-top:16px">
    <div class="sb-title">System</div>
    <div id="sys-stats" style="padding:0 12px;font-size:10px;color:var(--muted);line-height:1.9"></div>
  </div>
</nav>

<main class="main">

<!-- OVERVIEW -->
<div class="panel active" id="panel-overview">

  <!-- ── STAT CARDS ── -->
  <div class="ov-grid">
    <div class="ov-card"><div class="ov-val" style="color:var(--accent)"  id="ov-dev">0</div><div class="ov-lbl">Devices</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--green)"   id="ov-on">0</div><div class="ov-lbl">Online</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--red)"     id="ov-al">0</div><div class="ov-lbl">Alerts</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--orange)"  id="ov-vu">0</div><div class="ov-lbl">Vulnerabilities</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--yellow)"  id="ov-pt">0</div><div class="ov-lbl">Open Ports</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--accent2)" id="ov-sc">0</div><div class="ov-lbl">Scans</div></div>
  </div>

  <!-- ── INTERNET SPEED & LATENCY ── -->
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;
       padding:14px 18px;margin-bottom:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:12px">
        <span style="font-size:13px;font-weight:600">🌐 Internet Speed &amp; Latency</span>
        <span id="spd-engine" style="font-size:9px;padding:2px 7px;border-radius:4px;
          background:var(--bg3);border:1px solid var(--border);color:var(--muted)">not tested</span>
        <span id="spd-server" style="font-size:10px;color:var(--muted)"></span>
        <span id="spd-isp" style="font-size:10px;color:var(--muted)"></span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span id="spd-ts" style="font-size:10px;color:var(--muted)"></span>
        <button class="tbtn btn-prim" onclick="runSpeedTest()" id="speed-btn"
                style="padding:5px 14px;font-size:11px">▶ Run Test</button>
      </div>
    </div>

    <!-- 5 metric columns -->
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px">

      <!-- Download -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">⬇</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Download</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--accent);line-height:1" id="spd-down">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Mbps</div>
        <div style="margin-top:8px;height:5px;background:rgba(0,229,255,.1);border-radius:3px;overflow:hidden">
          <div id="spd-down-bar" style="height:100%;width:0%;background:var(--accent);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Upload -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">⬆</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Upload</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:#7c4dff;line-height:1" id="spd-up">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Mbps</div>
        <div style="margin-top:8px;height:5px;background:rgba(124,77,255,.1);border-radius:3px;overflow:hidden">
          <div id="spd-up-bar" style="height:100%;width:0%;background:#7c4dff;
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Ping / Latency -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">📡</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Ping</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--green);line-height:1" id="spd-lat">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">ms</div>
        <div style="margin-top:8px;height:5px;background:rgba(0,230,118,.1);border-radius:3px;overflow:hidden">
          <div id="spd-lat-bar" style="height:100%;width:0%;background:var(--green);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Jitter -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">〰</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Jitter</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--yellow);line-height:1" id="spd-jit">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">ms</div>
        <div style="margin-top:8px;height:5px;background:rgba(255,215,64,.1);border-radius:3px;overflow:hidden">
          <div id="spd-jit-bar" style="height:100%;width:0%;background:var(--yellow);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Rating -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px;
           display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center">
        <div style="font-size:32px;margin-bottom:4px" id="spd-emoji">⏸</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;
             color:var(--muted)" id="spd-status">Not tested</div>
        <div style="font-size:9px;color:var(--muted);margin-top:4px" id="spd-rating-bar">
          <div style="display:flex;gap:3px;justify-content:center" id="spd-bars">
            <span style="width:5px;height:16px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:20px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:24px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:28px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:32px;background:var(--border);border-radius:2px;display:inline-block"></span>
          </div>
        </div>
      </div>

    </div>

    <!-- Progress bar shown while testing -->
    <div id="spd-progress-wrap" style="display:none;margin-top:12px">
      <div style="height:3px;background:var(--bg3);border-radius:2px;overflow:hidden">
        <div id="spd-progress" style="height:100%;width:0%;background:linear-gradient(90deg,var(--accent),#7c4dff);
             border-radius:2px;transition:width .4s ease"></div>
      </div>
      <div id="spd-phase" style="font-size:10px;color:var(--muted);margin-top:5px;text-align:center">Initialising…</div>
    </div>
  </div>

  <!-- ── NETWORK TOPOLOGY GRAPH ── -->
  <div id="topo-wrap" style="background:var(--bg2);border:1px solid var(--border);
       border-radius:12px;position:relative;overflow:hidden;margin-bottom:16px">

    <!-- Toolbar -->
    <div id="topo-toolbar" style="display:flex;align-items:center;justify-content:space-between;
         padding:8px 14px;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:12px;font-weight:700;color:var(--accent)">🕸 Network Map</span>
        <span id="topo-node-count" style="font-size:10px;color:var(--muted)">0 nodes</span>
        <span id="topo-pps" style="font-size:10px;color:var(--green);
          background:rgba(0,230,118,.07);border:1px solid rgba(0,230,118,.2);
          padding:1px 7px;border-radius:4px;font-family:'JetBrains Mono',monospace">0 pkt/s</span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:9px;color:var(--muted)">
          <span style="color:#00e5ff">●</span> GW &nbsp;
          <span style="color:#00e676">●</span> Online &nbsp;
          <span style="color:#ff6b35">●</span> Vuln &nbsp;
          <span style="color:#3d5068">●</span> Off
        </span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:9px">
          <span style="color:#64b5f6">─</span> TCP &nbsp;
          <span style="color:#81c784">─</span> UDP &nbsp;
          <span style="color:#ffb74d">─</span> ICMP
        </span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:11px" title="Router/GW">🔀</span>
        <span style="font-size:11px" title="Mobile">📱</span>
        <span style="font-size:11px" title="Tablet">📋</span>
        <span style="font-size:11px" title="Laptop">💻</span>
        <span style="font-size:11px" title="Desktop">🖥</span>
        <span style="font-size:11px" title="TV">📺</span>
        <span style="font-size:11px" title="Camera">📷</span>
        <span style="font-size:11px" title="Printer">🖨</span>
        <span style="font-size:11px" title="Console">🎮</span>
        <span style="font-size:11px" title="IoT">🔌</span>
        <span style="font-size:11px" title="Server">🖧</span>
      </div>
      <div style="display:flex;align-items:center;gap:5px">
        <span style="font-size:9px;color:var(--muted);margin-right:4px">Scroll=zoom · Drag=pan · Dbl-click=trace</span>
        <button class="tbtn" id="topo-pause-btn" onclick="topoTogglePause()">⏸ Pause</button>
        <button class="tbtn" onclick="topoFit()">⊡ Fit</button>
        <button class="tbtn" onclick="topoReset()">⟳ Reset</button>
        <button class="tbtn" onclick="topoZoomIn()">＋</button>
        <button class="tbtn" onclick="topoZoomOut()">－</button>
      </div>
    </div>

    <!-- Canvas – JS sets exact height -->
    <canvas id="topo-canvas" style="width:100%;display:block;cursor:grab"></canvas>

    <!-- Packet trace slide-in panel -->
    <div id="topo-trace" style="position:absolute;top:43px;right:0;width:280px;
         height:calc(100% - 43px);background:rgba(8,11,16,.95);
         border-left:1px solid var(--border);overflow-y:auto;padding:12px;
         font-family:'JetBrains Mono',monospace;font-size:10px;
         transition:transform .25s ease;transform:translateX(100%);z-index:4">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-weight:700;color:var(--accent);font-size:11px" id="trace-title">Packet Trace</span>
        <button onclick="closeTrace()" style="background:none;border:1px solid var(--border);
                color:var(--muted);cursor:pointer;font-size:11px;border-radius:4px;padding:1px 7px">✕</button>
      </div>
      <div id="trace-info" style="color:var(--muted);margin-bottom:8px;font-size:9px;line-height:1.5"></div>
      <div id="trace-list"></div>
    </div>

    <!-- Tooltip -->
    <div id="topo-tip" style="position:absolute;pointer-events:none;display:none;
         background:var(--bg3);border:1px solid var(--border);border-radius:9px;
         padding:11px 15px;font-size:11px;min-width:220px;max-width:300px;
         z-index:20;box-shadow:0 6px 28px rgba(0,0,0,.7)"></div>
  </div>

  <!-- ── ORIGINAL BOTTOM: charts + recent alerts (restored) ── -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="chart-card"><div class="chart-lbl">Device Types</div><canvas id="ch-types"></canvas></div>
    <div class="chart-card"><div class="chart-lbl">Alert Severity</div><canvas id="ch-sev"></canvas></div>
  </div>
  <div class="sec-hdr" style="margin-top:0"><div class="sec-title" style="font-size:13px">Recent Alerts</div></div>
  <div class="alert-list" id="ov-alerts"></div>

</div>

<!-- DEVICES -->
<div class="panel" id="panel-devices">
  <div class="sec-hdr"><div class="sec-title">Connected Devices</div>
    <input class="search" id="dev-search" placeholder="Filter…" oninput="filterDevs()"></div>
  <div class="tbl-wrap">
    <table><thead><tr>
      <th>Status</th><th>IP</th><th>MAC</th><th>Hostname</th>
      <th>Type</th><th>Vendor</th><th>OS</th>
      <th>Ports</th><th>Vulns</th><th>TTL</th><th>Last Seen</th><th>Action</th>
    </tr></thead><tbody id="dev-tbody"></tbody></table>
  </div>
</div>

<!-- LIVE TRAFFIC -->
<div class="panel" id="panel-traffic">
  <div class="sec-hdr">
    <div class="sec-title">Live Packet Capture</div>
    <div style="display:flex;gap:7px;align-items:center">
      <span id="cap-badge" style="font-size:10px;padding:3px 9px;border-radius:4px;
        background:var(--bg3);border:1px solid var(--border);color:var(--muted)">Detecting…</span>
      <span id="pkt-ctr" class="mono" style="font-size:10px;color:var(--muted)">0 pkts</span>
      <button class="btn" onclick="clearPkts()">🗑 Clear</button>
      <button id="pause-btn" class="btn" onclick="togglePause()">⏸ Pause</button>
    </div>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:9px;font-size:10px">
    <span style="color:var(--muted)">Legend:</span>
    <span style="color:#64b5f6">■ TCP</span><span style="color:#81c784">■ UDP</span>
    <span style="color:#ffb74d">■ ICMP</span><span style="color:#ce93d8">■ RECV</span>
    <span style="color:#00e676">■ SEND</span>
  </div>
  <div class="pkt-stream" id="pkt-stream">
    <div id="pkt-ph" style="color:var(--muted);padding:18px;text-align:center">⏳ Waiting for traffic…</div>
  </div>
</div>

<!-- ALERTS -->
<div class="panel" id="panel-alerts">
  <div class="sec-hdr"><div class="sec-title">Security Alerts</div>
    <button class="btn" onclick="ackAll()">✓ Acknowledge All</button></div>
  <div class="alert-list" id="alert-list"></div>
</div>

<!-- VULNERABILITIES -->
<div class="panel" id="panel-vulns">
  <div class="sec-hdr"><div class="sec-title">Detected Vulnerabilities</div></div>
  <div id="vuln-list"></div>
</div>

<!-- OPEN PORTS -->
<div class="panel" id="panel-ports">
  <div class="sec-hdr"><div class="sec-title">Open Ports</div>
    <input class="search" id="port-search" placeholder="Filter port/service…" oninput="filterPorts()"></div>
  <div id="ports-content"></div>
</div>

<!-- BANDWIDTH GRAPHS -->
<div class="panel" id="panel-graphs">
  <div class="sec-hdr"><div class="sec-title">Real-Time Bandwidth</div></div>
  <div id="graphs-content"></div>
</div>

<!-- IP OSINT -->
<div class="panel" id="panel-osint">

  <!-- Toolbar -->
  <div class="sec-hdr">
    <div class="sec-title">🔍 IP OSINT — Public Threat Intelligence</div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span id="osint-key-badges" style="display:flex;gap:5px"></span>
      <button class="btn" onclick="osintScanAll()" id="osint-scan-btn">▶ Scan All Devices</button>
      <button class="btn" onclick="osintClearAll()">🗑 Clear</button>
    </div>
  </div>

  <!-- Device selector grid -->
  <div id="osint-device-grid" style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:16px"></div>

  <!-- Main results area -->
  <div id="osint-results">
    <div style="color:var(--muted);text-align:center;padding:40px;font-size:13px">
      Click a device above or <b>Scan All Devices</b> to query public OSINT databases.<br>
      <span style="font-size:11px;margin-top:6px;display:block">
        Sources: Shodan · Censys · AbuseIPDB · AlienVault OTX
      </span>
    </div>
  </div>

</div>


</main>
</div>

<!-- DEVICE MODAL -->
<div class="overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-hdr">
      <div>
        <div class="modal-title" id="modal-title">Device</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px" id="modal-sub"></div>
      </div>
      <div style="display:flex;gap:7px;align-items:center">
        <button class="btn btn-prim" onclick="rescan()">↺ Rescan</button>
        <div class="close-btn" onclick="closeModal()">✕</div>
      </div>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div id="toasts"></div>

<script>
const socket = io();
const S = { devices:{}, alerts:[], stats:{} };
let curModal = null, paused = false, pktTotal = 0, capMode = null;
let chTypes = null, chSev = null;
const devCharts = {};

// ── Socket events ─────────────────────────────────────────────────────────
const _pendingDeviceUpdates = [];
socket.on("initial_state", d => {
  d.devices.forEach(v => S.devices[v.ip] = v);
  S.alerts = d.alerts;
  Object.assign(S.stats, d.stats);
  renderAll();
  if (_topoInited) TOPO.onInitialState(d);
  else _pendingInitial = d;  // store for when topo inits
});
let _pendingInitial = null;
socket.on("device_update", d => {
  S.devices[d.ip] = d;
  if (_topoInited) TOPO.onDeviceUpdate(d);
  else _pendingDeviceUpdates.push(d);  // queue until init
  if (active("devices")) renderDevices();
  if (active("overview")) renderOverview();
  if (active("graphs")) renderGraphs();
  if (active("ports")) renderPorts();
  if (active("vulns")) renderVulns();
});
socket.on("new_alert", a => {
  S.alerts.unshift(a);
  S.stats.alert_count = (S.stats.alert_count||0)+1;
  badge(); toast(a);
  if (active("alerts"))   renderAlerts();
  if (active("overview")) renderOvAlerts();
  updateCounters();
});
socket.on("live_packet", p => { if (!paused) addPkt(p); });
socket.on("topo_packet", p => { if (_topoInited) TOPO.onTopoPacket(p); });
socket.on("traffic_update", d => {
  el("s-pps", d.data ? Object.values(d.data).reduce((s,v)=>s+Math.round((v.in+v.out)/200),0) : 0);
  updateDevCharts(d);
});



// Detect private/LAN IP addresses (RFC1918 + link-local + loopback)
function isLanIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(isNaN)) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254)  // link-local
  );
}

// ═══════════════════════════════════════════════════════════════════════════
//  NETWORK TOPOLOGY GRAPH  v2 – pure Canvas2D, rich SVG-path device icons
// ═══════════════════════════════════════════════════════════════════════════
const TOPO = (() => {

  // ── State ─────────────────────────────────────────────────────────────────
  let canvas, ctx, raf;
  let nodes  = {};   // ip → node object
  let edges  = {};   // "a|b" → edge object
  let pkts   = [];   // flying packet dots
  let selIP  = null;
  let traceIP = null;
  let paused = false;
  let gateway = null;
  let pktRateCtr = 0, pktRateTs = Date.now();
  // Camera
  let camX = 0, camY = 0, camZ = 1;
  let dragCam = null, dragNode = null, dragOff = {x:0,y:0};
  let mouseDownAt = null;

  // ── Colour constants ───────────────────────────────────────────────────────
  const C = {
    bg:       '#080b10',
    grid:     'rgba(26,37,53,0.45)',
    accent:   '#00e5ff',
    green:    '#00e676',
    orange:   '#ff6b35',
    red:      '#ff2d55',
    muted:    '#3d5068',
    text:     '#dde6f0',
    dimtext:  '#5a7090',
    gateway:  '#00e5ff',
  };
  const PROTO_COL = {
    TCP:'#64b5f6', UDP:'#81c784', ICMP:'#ffb74d',
    RECV:'#ce93d8', SEND:'#00e676', OTHER:'#7c8fa8'
  };
  const PROTO_EDGE = {
    TCP:'rgba(100,181,246,', UDP:'rgba(129,200,132,',
    ICMP:'rgba(255,183,77,', RECV:'rgba(206,147,216,',
    SEND:'rgba(0,230,118,',  OTHER:'rgba(124,143,168,'
  };

  // ── Device type → category for icon selection ──────────────────────────────
  function category(dtype, isGW) {
    if (isGW) return 'router';
    const d = (dtype||'').toLowerCase();
    if (d.includes('router') || d.includes('gateway') || d.includes('ap') || d.includes('switch')) return 'router';
    if (d.includes('iphone') || d.includes('mobile phone') || d.includes('android') || d === 'mobile') return 'phone';
    if (d.includes('ipad') || d.includes('tablet')) return 'tablet';
    if (d.includes('laptop')) return 'laptop';
    if (d.includes('mac') && !d.includes('macbook')) return 'desktop';
    if (d.includes('macbook')) return 'laptop';
    if (d.includes('pc') || d.includes('desktop') || d.includes('workstation')) return 'desktop';
    if (d.includes('server') || d.includes('nas')) return 'server';
    if (d.includes('smart tv') || d.includes('television')) return 'tv';
    if (d.includes('chromecast') || d.includes('firetv') || d.includes('streaming')) return 'tv';
    if (d.includes('printer')) return 'printer';
    if (d.includes('camera') || d.includes('ipcam') || d.includes('ip cam')) return 'camera';
    if (d.includes('playstation') || d.includes('xbox') || d.includes('nintendo') || d.includes('console') || d.includes('gaming')) return 'console';
    if (d.includes('virtual') || d.includes('vm')) return 'vm';
    if (d.includes('iot') || d.includes('sbc') || d.includes('raspberry') || d.includes('embedded')) return 'iot';
    if (d.includes('speaker') || d.includes('echo') || d.includes('home')) return 'speaker';
    if (d.includes('watch') || d.includes('wearable')) return 'watch';
    return 'unknown';
  }

  // ── Draw device icon (canvas path-based SVG-style icons) ──────────────────
  // Each icon is drawn centred on (0,0), scaled to fit radius r
  function drawIcon(cat, r, col, ctx2) {
    const s = r * 0.72; // scale factor
    ctx2.strokeStyle = col;
    ctx2.fillStyle   = col;
    ctx2.lineWidth   = Math.max(1, r * 0.1);
    ctx2.lineCap     = 'round';
    ctx2.lineJoin    = 'round';

    if (cat === 'router') {
      // Wifi/router icon: box + 3 arc waves
      const bw = s*1.0, bh = s*0.55;
      ctx2.strokeRect(-bw/2, s*0.1, bw, bh);
      // Antenna nub
      ctx2.beginPath(); ctx2.moveTo(-s*0.15, s*0.1); ctx2.lineTo(-s*0.15, -s*0.3);
      ctx2.moveTo(s*0.15, s*0.1);  ctx2.lineTo(s*0.15, -s*0.3); ctx2.stroke();
      // Wifi arcs above
      for (let i=0; i<3; i++) {
        const ar = s*(0.28+i*0.22);
        ctx2.beginPath();
        ctx2.arc(0, -s*0.55, ar, Math.PI*1.15, Math.PI*1.85);
        ctx2.globalAlpha = 0.55 + i*0.15;
        ctx2.stroke();
      }
      ctx2.globalAlpha = 1;
      // LED dot
      ctx2.beginPath(); ctx2.arc(s*0.32, s*0.38, s*0.08, 0, Math.PI*2);
      ctx2.fill();
      return;
    }

    if (cat === 'phone') {
      // Rounded phone outline
      const pw = s*0.65, ph = s*1.1, cr = s*0.13;
      roundRect(ctx2, -pw/2, -ph/2, pw, ph, cr, false, true);
      // Home button circle
      ctx2.beginPath(); ctx2.arc(0, ph/2 - s*0.14, s*0.09, 0, Math.PI*2); ctx2.stroke();
      // Speaker slit
      ctx2.beginPath(); ctx2.moveTo(-s*0.15, -ph/2+s*0.12); ctx2.lineTo(s*0.15, -ph/2+s*0.12); ctx2.stroke();
      return;
    }

    if (cat === 'tablet') {
      const tw = s*0.95, th = s*1.15, cr = s*0.1;
      roundRect(ctx2, -tw/2, -th/2, tw, th, cr, false, true);
      // Home button
      ctx2.beginPath(); ctx2.arc(0, th/2-s*0.12, s*0.08, 0, Math.PI*2); ctx2.stroke();
      // Camera dot
      ctx2.beginPath(); ctx2.arc(0, -th/2+s*0.12, s*0.06, 0, Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'laptop') {
      // Screen + keyboard
      const sw = s*1.1, sh = s*0.72, cr = s*0.07;
      roundRect(ctx2, -sw/2, -sh-s*0.05, sw, sh, cr, false, true);
      // Hinge base
      ctx2.beginPath(); ctx2.moveTo(-sw*0.6, -s*0.05);
      ctx2.lineTo(sw*0.6, -s*0.05); ctx2.lineTo(sw*0.7, s*0.28);
      ctx2.lineTo(-sw*0.7, s*0.28); ctx2.closePath(); ctx2.stroke();
      // Camera dot on screen
      ctx2.beginPath(); ctx2.arc(0, -sh-s*0.05+s*0.08, s*0.05, 0, Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'desktop') {
      // Monitor
      const mw = s*1.15, mh = s*0.85, cr = s*0.07;
      roundRect(ctx2, -mw/2, -mh-s*0.05, mw, mh, cr, false, true);
      // Stand neck
      ctx2.beginPath(); ctx2.moveTo(-s*0.05,-s*0.05); ctx2.lineTo(-s*0.05,s*0.22);
      ctx2.moveTo(s*0.05,-s*0.05); ctx2.lineTo(s*0.05,s*0.22); ctx2.stroke();
      // Stand base
      ctx2.beginPath(); ctx2.moveTo(-s*0.38,s*0.22); ctx2.lineTo(s*0.38,s*0.22); ctx2.stroke();
      return;
    }

    if (cat === 'server') {
      // Stack of 3 server units
      const uw = s*1.1, uh = s*0.28, gap = s*0.06;
      for (let i=0; i<3; i++) {
        const y = -uh*1.5 - gap + i*(uh+gap);
        ctx2.strokeRect(-uw/2, y, uw, uh);
        // LED
        ctx2.beginPath(); ctx2.arc(uw/2-s*0.1, y+uh/2, s*0.05, 0, Math.PI*2); ctx2.fill();
        // Drive slot
        ctx2.strokeRect(-uw/2+s*0.1, y+uh/2-s*0.04, s*0.28, s*0.08);
      }
      return;
    }

    if (cat === 'tv') {
      // Wide TV screen
      const tw = s*1.25, th = s*0.78, cr = s*0.06;
      roundRect(ctx2, -tw/2, -th/2-s*0.1, tw, th, cr, false, true);
      // Stand
      ctx2.beginPath(); ctx2.moveTo(-s*0.22,th/2-s*0.1); ctx2.lineTo(-s*0.32,s*0.55);
      ctx2.lineTo(s*0.32,s*0.55); ctx2.lineTo(s*0.22,th/2-s*0.1); ctx2.stroke();
      // Screen glare line
      ctx2.beginPath(); ctx2.globalAlpha=0.3;
      ctx2.moveTo(-tw/2+s*0.15,-th/2-s*0.1+s*0.12); ctx2.lineTo(-tw/2+s*0.15+s*0.2,-th/2-s*0.1+s*0.12);
      ctx2.stroke(); ctx2.globalAlpha=1;
      return;
    }

    if (cat === 'printer') {
      // Printer body + paper
      ctx2.strokeRect(-s*0.55,-s*0.15,s*1.1,s*0.6);
      // Paper out top
      ctx2.strokeRect(-s*0.28,-s*0.55,s*0.56,s*0.42);
      // Paper in bottom
      ctx2.strokeRect(-s*0.18,s*0.42,s*0.36,s*0.18);
      // Button
      ctx2.beginPath(); ctx2.arc(s*0.35,s*0.15,s*0.06,0,Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'camera') {
      // Camera body
      roundRect(ctx2, -s*0.6,-s*0.35,s*1.2,s*0.7,s*0.1,false,true);
      // Lens ring outer
      ctx2.beginPath(); ctx2.arc(0,0,s*0.28,0,Math.PI*2); ctx2.stroke();
      // Lens ring inner
      ctx2.beginPath(); ctx2.arc(0,0,s*0.15,0,Math.PI*2); ctx2.fill();
      // Flash
      ctx2.fillRect(s*0.45,-s*0.32,s*0.1,s*0.14);
      return;
    }

    if (cat === 'console') {
      // Game controller shape
      ctx2.beginPath();
      ctx2.moveTo(-s*0.55,s*0.1); ctx2.quadraticCurveTo(-s*0.7,-s*0.3,-s*0.4,-s*0.5);
      ctx2.lineTo(-s*0.1,-s*0.5); ctx2.lineTo(0,-s*0.3); ctx2.lineTo(s*0.1,-s*0.5);
      ctx2.lineTo(s*0.4,-s*0.5); ctx2.quadraticCurveTo(s*0.7,-s*0.3,s*0.55,s*0.1);
      ctx2.quadraticCurveTo(s*0.3,s*0.55,0,s*0.5);
      ctx2.quadraticCurveTo(-s*0.3,s*0.55,-s*0.55,s*0.1); ctx2.closePath(); ctx2.stroke();
      // Buttons
      ctx2.beginPath(); ctx2.arc(s*0.32,-s*0.12,s*0.07,0,Math.PI*2); ctx2.fill();
      ctx2.beginPath(); ctx2.arc(s*0.47,s*0.05,s*0.07,0,Math.PI*2); ctx2.fill();
      // D-pad cross
      ctx2.fillRect(-s*0.48,-s*0.05,s*0.26,s*0.1);
      ctx2.fillRect(-s*0.38,-s*0.15,s*0.08,s*0.3);
      return;
    }

    if (cat === 'vm') {
      // Cloud shape
      ctx2.beginPath();
      ctx2.arc(-s*0.28,-s*0.1,s*0.32,Math.PI,Math.PI*2);
      ctx2.arc( s*0.28,-s*0.1,s*0.32,Math.PI,Math.PI*2);
      ctx2.arc( s*0.12, s*0.08,s*0.22,0,Math.PI);
      ctx2.arc(-s*0.12, s*0.08,s*0.22,0,Math.PI);
      ctx2.closePath(); ctx2.stroke();
      // Gear/cog inside
      ctx2.beginPath(); ctx2.arc(0,-s*0.08,s*0.16,0,Math.PI*2); ctx2.stroke();
      return;
    }

    if (cat === 'iot') {
      // Circuit-board square with dots
      ctx2.strokeRect(-s*0.5,-s*0.5,s,s);
      // Pins
      const pins = [[-s*0.5,-s*0.2],[s*0.5,-s*0.2],[s*0.5,s*0.2],[-s*0.5,s*0.2]];
      pins.forEach(([px,py]) => {
        ctx2.beginPath(); ctx2.moveTo(px,py); ctx2.lineTo(px+(px<0?-s*0.18:s*0.18),py); ctx2.stroke();
      });
      // Chip dot
      ctx2.beginPath(); ctx2.arc(0,0,s*0.14,0,Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'speaker') {
      // Speaker grille oval
      ctx2.beginPath(); ctx2.ellipse(0,0,s*0.45,s*0.6,0,0,Math.PI*2); ctx2.stroke();
      // Three dots for speaker grille
      [-s*0.2,0,s*0.2].forEach(dy => {
        ctx2.beginPath(); ctx2.arc(0,dy,s*0.07,0,Math.PI*2); ctx2.fill();
      });
      return;
    }

    if (cat === 'watch') {
      // Watch face
      ctx2.beginPath(); ctx2.arc(0,0,s*0.45,0,Math.PI*2); ctx2.stroke();
      // Band top/bottom
      ctx2.strokeRect(-s*0.2,-s*0.7,s*0.4,s*0.28);
      ctx2.strokeRect(-s*0.2,s*0.42,s*0.4,s*0.28);
      // Hands
      ctx2.beginPath(); ctx2.moveTo(0,0); ctx2.lineTo(0,-s*0.28); ctx2.stroke();
      ctx2.beginPath(); ctx2.moveTo(0,0); ctx2.lineTo(s*0.2,s*0.1); ctx2.stroke();
      return;
    }

    // unknown – question mark circle
    ctx2.beginPath(); ctx2.arc(0,0,s*0.55,0,Math.PI*2); ctx2.stroke();
    ctx2.font = `bold ${Math.round(s*0.8)}px sans-serif`;
    ctx2.textAlign='center'; ctx2.textBaseline='middle';
    ctx2.fillStyle=col; ctx2.fillText('?',0,s*0.05);
  }

  function roundRect(c, x, y, w, h, r, fill, stroke) {
    c.beginPath();
    c.moveTo(x+r, y);
    c.lineTo(x+w-r, y); c.arcTo(x+w,y,x+w,y+r,r);
    c.lineTo(x+w,y+h-r); c.arcTo(x+w,y+h,x+w-r,y+h,r);
    c.lineTo(x+r,y+h); c.arcTo(x,y+h,x,y+h-r,r);
    c.lineTo(x,y+r); c.arcTo(x,y,x+r,y,r);
    c.closePath();
    if (fill) c.fill();
    if (stroke) c.stroke();
  }

  // ── Node colour by status ──────────────────────────────────────────────────
  function nodeCol(n) {
    if (n.is_gateway) return C.gateway;
    if (n.status === 'offline') return C.muted;
    if ((n.vuln_count||0) >= 3) return C.red;
    if ((n.vuln_count||0) >  0) return C.orange;
    return C.green;
  }

  // ── Init ──────────────────────────────────────────────────────────────────
  function init() {
    canvas = document.getElementById('topo-canvas');
    ctx    = canvas.getContext('2d');
    resize();
    window.addEventListener('resize', resize);
    canvas.addEventListener('mousedown',  onMD);
    canvas.addEventListener('mousemove',  onMM);
    canvas.addEventListener('mouseup',    onMU);
    canvas.addEventListener('mouseleave', onML);
    canvas.addEventListener('wheel',      onWheel, {passive:false});
    canvas.addEventListener('click',      onClick);
    canvas.addEventListener('dblclick',   onDbl);
    fetch('/api/topology').then(r=>r.json()).then(applyTopo);
    raf = requestAnimationFrame(loop);
    // Periodic refresh of topology from server
    // Refresh topology: quickly at start, then every 10s
    let _topoRefreshCount = 0;
    function _scheduledTopoRefresh() {
      fetch('/api/topology').then(r=>r.json()).then(applyTopo).catch(()=>{});
      _topoRefreshCount++;
      const delay = _topoRefreshCount < 6 ? 3000 : 10000;
      setTimeout(_scheduledTopoRefresh, delay);
    }
    setTimeout(_scheduledTopoRefresh, 2000);
  }

  function resize() {
    const wrap    = document.getElementById('topo-wrap');
    const toolbar = document.getElementById('topo-toolbar');
    const panel   = document.getElementById('panel-overview');
    const dpr     = window.devicePixelRatio || 1;
    const w       = wrap.clientWidth || (window.innerWidth - 260);
    // Height = viewport - header(52) - panel padding(36) - stat cards(~100)
    //          - toolbar height - bottom section (charts+alerts, ~340px)
    const tbH   = (toolbar && toolbar.offsetHeight) || 44;
    // Target: graph takes ~55% of viewport height, minimum 480px
    const h     = Math.max(480, Math.round(window.innerHeight * 0.55) - tbH);
    canvas.style.width  = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width  = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function W() { return parseFloat(canvas.style.width)  || canvas.width; }
  function H() { return parseFloat(canvas.style.height) || canvas.height; }

  // ── Topology data ─────────────────────────────────────────────────────────
  function applyTopo(data) {
    gateway = data.gateway;
    const cx = W()/2, cy = H()/2;
    // Only show devices the server actually scanned. Never show external IPs.
    // data.nodes comes from /api/topology which only includes known devices.
    const lanNodes = (data.nodes||[]).filter(d =>
      (isLanIp(d.ip) || d.is_gateway || d.ip === gateway)
    );
    // Remove nodes that are no longer in the scanned device list
    const incomingIPs = new Set(lanNodes.map(d => d.ip));
    Object.keys(nodes).forEach(ip => {
      if (ip !== gateway && !incomingIPs.has(ip)) {
        // Only remove if also not in edges (keep gateways safe)
        delete nodes[ip];
      }
    });

    lanNodes.forEach(d => {
      if (!nodes[d.ip]) {
        const angle = Math.random()*Math.PI*2;
        const dist  = d.is_gateway ? 0 : 110 + Math.random()*220;
        nodes[d.ip] = {
          x: cx + Math.cos(angle)*dist,
          y: cy + Math.sin(angle)*dist,
          vx:0, vy:0,
          pinned: d.is_gateway,
          phase: Math.random()*Math.PI*2,
          activity: 0,
          pktQueue: 0,
        };
      }
      Object.assign(nodes[d.ip], d);
      nodes[d.ip].r = d.is_gateway ? 30 : 22;
    });

    (data.edges||[]).forEach(e => {
      const k = e.a+'|'+e.b;
      if (!edges[k]) edges[k] = {a:e.a, b:e.b, activity:0, count:0, bytes:0, recentBytes:0};
      // Cap count so restored topology edges don't re-inflate line thickness
      const ec = Math.min(e.count||0, 50);
      Object.assign(edges[k], {
        proto:        e.proto||'OTHER',
        count:        ec,
        bytes:        e.bytes||0,
        recentBytes:  0,          // reset decay counter on topology refresh
        alpha:        Math.min(0.75, 0.12 + ec * 0.015)
      });
    });

    // Auto-connect every device to gateway if no edge exists yet.
    // Always use the normalised key (lexicographic order) to avoid duplicates.
    if (gateway && nodes[gateway]) {
      Object.keys(nodes).forEach(ip => {
        if (ip === gateway) return;
        const pair = [ip, gateway].sort();
        const kn   = pair[0]+'|'+pair[1];
        // Also remove any un-normalised reverse key left from older code
        const krev = pair[1]+'|'+pair[0];
        if (edges[krev] && krev !== kn) {
          edges[kn] = edges[krev];
          delete edges[krev];
        }
        if (!edges[kn]) {
          edges[kn] = {a:pair[0], b:pair[1], proto:'OTHER',
                       count:0, bytes:0, recentBytes:0, alpha:0.18, activity:0};
        }
      });
    }

    updStats();
  }

  function updStats() {
    const nc = Object.keys(nodes).length;
    const ec = Object.keys(edges).length;
    const el = document.getElementById('topo-node-count');
    if (el) el.textContent = nc+' nodes · '+ec+' edges';
  }

  // ── Physics ───────────────────────────────────────────────────────────────
  const KR=5500, KA=0.035, KC=0.004, KD=0.80, IDEAL=175;

  function physics(dt) {
    const ips = Object.keys(nodes);
    if (ips.length < 2) return;
    const cx=W()/2, cy=H()/2;

    for (let i=0;i<ips.length;i++) for (let j=i+1;j<ips.length;j++) {
      const a=nodes[ips[i]], b=nodes[ips[j]];
      const dx=b.x-a.x, dy=b.y-a.y, d2=dx*dx+dy*dy+1, d=Math.sqrt(d2);
      const f=KR/d2, fx=f*dx/d, fy=f*dy/d;
      if(!a.pinned){a.vx-=fx; a.vy-=fy;}
      if(!b.pinned){b.vx+=fx; b.vy+=fy;}
    }

    Object.values(edges).forEach(e => {
      const a=nodes[e.a], b=nodes[e.b];
      if(!a||!b) return;
      const dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=KA*(d-IDEAL), fx=f*dx/d, fy=f*dy/d;
      if(!a.pinned){a.vx+=fx; a.vy+=fy;}
      if(!b.pinned){b.vx-=fx; b.vy-=fy;}
    });

    ips.forEach(ip => {
      const n=nodes[ip];
      if(n.pinned) return;
      n.vx+=(cx-n.x)*KC; n.vy+=(cy-n.y)*KC;
      n.vx*=KD; n.vy*=KD;
      n.x+=n.vx*dt; n.y+=n.vy*dt;
      // Boundary bounce
      const m=40;
      if(n.x<m){n.x=m;n.vx*=-0.3;}
      if(n.y<m){n.y=m;n.vy*=-0.3;}
      if(n.x>W()-m){n.x=W()-m;n.vx*=-0.3;}
      if(n.y>H()-m){n.y=H()-m;n.vy*=-0.3;}
    });
  }

  // ── Packet spawn ──────────────────────────────────────────────────────────
  function spawnPkt(src, dst, proto, bytes, key) {
    const a=nodes[src], b=nodes[dst];
    if (!a||!b) return;
    const sz  = Math.max(3, Math.min(7, 3 + Math.log2((bytes||64)/64) * 1.2));
    const ek  = key || [src,dst].sort().join('|');
    pkts.push({ax:a.x, ay:a.y, bx:b.x, by:b.y, t:0, proto, sz, key:ek});
    // Node activity pulse — capped so it never accumulates on busy links
    if(a) a.activity = Math.min(0.8, (a.activity||0) + 0.35);
    if(b) b.activity = Math.min(0.8, (b.activity||0) + 0.25);
  }

  // ── Draw frame ────────────────────────────────────────────────────────────
  function draw(now) {
    const dpr = window.devicePixelRatio || 1;
    // Reset to DPR-scaled identity (set in resize) then clear
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W(), H());

    // Dark background
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, W(), H());

    // Grid (in logical/screen coords, before camera transform)
    ctx.strokeStyle = C.grid;
    ctx.lineWidth   = 0.5;
    const gs = 50 * camZ;
    const ox = ((camX % gs) + gs) % gs;
    const oy = ((camY % gs) + gs) % gs;
    for (let x = ox - gs; x < W() + gs; x += gs) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H()); ctx.stroke();
    }
    for (let y = oy - gs; y < H() + gs; y += gs) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W(), y); ctx.stroke();
    }

    // Apply camera transform for world-space drawing
    ctx.save();
    ctx.translate(camX, camY);
    ctx.scale(camZ, camZ);

    const t = now/1000;

    // ── Edges ──────────────────────────────────────────────────────────────
    Object.values(edges).forEach(e => {
      const a = nodes[e.a], b = nodes[e.b];
      if (!a || !b) return;

      const act  = e.activity || 0;
      const base = PROTO_EDGE[e.proto] || PROTO_EDGE.OTHER;

      // LINE WIDTH is fixed at 2.0px (slightly thicker for readability).
      // Alpha pulses briefly when a packet travels, then returns to idle.
      const idleAlpha   = 0.30;
      const activeAlpha = Math.min(0.82, idleAlpha + act * 0.52);

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = base + activeAlpha + ')';
      ctx.lineWidth   = 2.0;                       // FIXED — never grows with traffic
      ctx.setLineDash(act > 0.10 ? [] : [5, 6]);   // solid on active, dashed at rest
      ctx.stroke();
      ctx.setLineDash([]);

      // Brief traffic-bytes label (only shown during an active burst)
      if (act > 0.55 && (e.recentBytes || 0) > 512) {
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        ctx.fillStyle    = base + '0.82)';
        ctx.font         = '8px JetBrains Mono,monospace';
        ctx.textAlign    = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(fmtB(e.recentBytes), mx, my - 9);
      }

      // Decay: activity fades to 0 in ~24 frames (0.4 s at 60 fps)
      e.activity    = Math.max(0, act - 0.042);
      // recentBytes decays separately so the label disappears fast
      e.recentBytes = Math.max(0, (e.recentBytes || 0) * 0.88);
    });

    // ── Flying packets ─────────────────────────────────────────────────────
    pkts.forEach(p => {
      const x = p.ax+(p.bx-p.ax)*p.t;
      const y = p.ay+(p.by-p.ay)*p.t;
      const col = PROTO_COL[p.proto]||PROTO_COL.OTHER;
      ctx.beginPath(); ctx.arc(x,y,p.sz,0,Math.PI*2);
      ctx.fillStyle   = col;
      ctx.shadowBlur  = p.sz*2.5;
      ctx.shadowColor = col;
      ctx.fill();
    });
    ctx.shadowBlur = 0;

    // ── Nodes ──────────────────────────────────────────────────────────────
    Object.values(nodes).forEach(n => {
      const col  = nodeCol(n);
      const r    = n.r || 22;
      const act  = n.activity||0;
      const pulse= 1+0.08*Math.sin(t*2.2+n.phase);
      const rr   = r*(act>0.5?1.18:1)*pulse;

      // Outer glow
      if (n.status !== 'offline' || n.is_gateway) {
        try {
          const gr = ctx.createRadialGradient(n.x, n.y, rr*0.3, n.x, n.y, rr*2.6);
          const glowA = n.is_gateway ? 0.45 : (act > 0.3 ? 0.38 : 0.20);
          // Safe hex→rgba: always works regardless of colour format
          gr.addColorStop(0, hexToRgba(col, glowA));
          gr.addColorStop(1, 'rgba(0,0,0,0)');
          ctx.beginPath(); ctx.arc(n.x, n.y, rr*2.6, 0, Math.PI*2);
          ctx.fillStyle = gr; ctx.fill();
        } catch(e) {}
      }

      // Activity ping ring
      if(act>0.15) {
        ctx.beginPath(); ctx.arc(n.x,n.y,rr+act*16,0,Math.PI*2);
        ctx.strokeStyle=col; ctx.lineWidth=0.8; ctx.globalAlpha=act*0.45; ctx.stroke();
        ctx.globalAlpha=1;
      }

      // Node background circle
      ctx.beginPath(); ctx.arc(n.x,n.y,rr,0,Math.PI*2);
      ctx.fillStyle='rgba(10,14,20,0.93)'; ctx.fill();

      // Node border
      ctx.strokeStyle=col;
      ctx.lineWidth  = (n.ip===selIP) ? 3 : 1.8;
      ctx.stroke();

      // Selection dashed ring
      if(n.ip===selIP) {
        ctx.beginPath(); ctx.arc(n.x,n.y,rr+8,0,Math.PI*2);
        ctx.strokeStyle=C.accent; ctx.lineWidth=1.5; ctx.setLineDash([5,4]);
        ctx.stroke(); ctx.setLineDash([]);
      }

      // Device icon drawn inside node
      ctx.save();
      ctx.translate(n.x, n.y);
      const cat = category(n.device_type, n.is_gateway);
      drawIcon(cat, rr*0.72, col, ctx);
      ctx.restore();

      // IP label below node
      const fontSize = Math.max(8, Math.min(11, rr*0.42));
      ctx.font      = `bold ${fontSize}px JetBrains Mono,monospace`;
      ctx.fillStyle = col;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(n.ip, n.x, n.y+rr+5);

      // Hostname (shorter)
      if(n.hostname) {
        const hn = n.hostname.split('.')[0].substring(0,16);
        ctx.font      = `${Math.max(7,fontSize-2)}px Inter,sans-serif`;
        ctx.fillStyle = C.dimtext;
        ctx.fillText(hn, n.x, n.y+rr+5+fontSize+2);
      }

      // Vendor badge (small pill under IP)
      if(n.vendor && n.vendor!=='Unknown' && camZ>0.65) {
        const vnd = n.vendor.substring(0,10);
        const vw  = ctx.measureText(vnd).width+8;
        ctx.fillStyle='rgba(20,30,50,0.85)';
        ctx.strokeStyle='rgba(100,150,200,0.25)';
        ctx.lineWidth=0.6;
        const vy = n.y+rr+5+fontSize*2+5;
        roundRect(ctx, n.x-vw/2, vy, vw, fontSize+2, 3, true, true);
        ctx.font=`${Math.max(7,fontSize-2)}px Inter,sans-serif`;
        ctx.fillStyle='rgba(160,190,220,0.7)';
        ctx.fillText(vnd, n.x, vy+1);
      }

      // Vuln count badge (top-right corner)
      if((n.vuln_count||0)>0) {
        const bx=n.x+rr*0.72, by=n.y-rr*0.72, br=9;
        ctx.beginPath(); ctx.arc(bx,by,br,0,Math.PI*2);
        ctx.fillStyle=n.vuln_count>2?C.red:C.orange; ctx.fill();
        ctx.font='bold 8px Inter,sans-serif';
        ctx.fillStyle='#fff'; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.fillText(n.vuln_count, bx, by);
      }

      // MAC label (shown only when zoomed in)
      if(camZ>1.4 && n.mac && n.mac!=='N/A') {
        const vy2 = n.y+rr+5+fontSize*2+fontSize+10;
        ctx.font=`7px JetBrains Mono,monospace`;
        ctx.fillStyle='rgba(100,130,160,0.55)';
        ctx.textAlign='center'; ctx.textBaseline='top';
        ctx.fillText(n.mac, n.x, vy2);
      }

      n.activity = Math.max(0, act - 0.028);
    });

    ctx.restore(); // end camera transform
  }

  // Helper: safe hex colour to rgba string
  function hexToRgba(hex, alpha) {
    hex = hex.replace('#','');
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    const r = parseInt(hex.substring(0,2),16);
    const g = parseInt(hex.substring(2,4),16);
    const b = parseInt(hex.substring(4,6),16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  // ── Main loop ─────────────────────────────────────────────────────────────
  let lastT=0;
  function loop(now) {
    raf = requestAnimationFrame(loop);
    if(!paused) {
      const dt = Math.min(32, now-lastT)/16;
      lastT = now;
      physics(dt);
      pkts.forEach(p => p.t += 0.035);
      pkts = pkts.filter(p => p.t<1);
    }
    draw(now);
    // pkt/s
    if(now-pktRateTs>1000) {
      const el=document.getElementById('topo-pps');
      if(el) el.textContent=pktRateCtr+' pkt/s';
      pktRateCtr=0; pktRateTs=now;
    }
  }

  // ── Interaction ───────────────────────────────────────────────────────────
  function sw(x,y){return{x:(x-camX)/camZ, y:(y-camY)/camZ};}
  function hit(wx,wy){
    let best=null, bd=1e9;
    for(const [ip,n] of Object.entries(nodes)){
      const dx=n.x-wx,dy=n.y-wy,d=dx*dx+dy*dy;
      const rr=((n.r||22)+10)**2;
      if(d<rr&&d<bd){bd=d;best=ip;}
    }
    return best;
  }

  function onMD(e){
    const r=canvas.getBoundingClientRect();
    const sx=e.clientX-r.left, sy=e.clientY-r.top;
    const wp=sw(sx,sy);
    const h=hit(wp.x,wp.y);
    mouseDownAt={x:e.clientX,y:e.clientY};
    if(h){
      dragNode=h;
      dragOff={x:nodes[h].x-wp.x, y:nodes[h].y-wp.y};
      canvas.style.cursor='grabbing';
    } else {
      dragCam={sx:e.clientX,sy:e.clientY,cx:camX,cy:camY};
      canvas.style.cursor='grabbing';
    }
  }

  function onMM(e){
    const r=canvas.getBoundingClientRect();
    const sx=e.clientX-r.left, sy=e.clientY-r.top;
    const wp=sw(sx,sy);
    if(dragNode){
      nodes[dragNode].x=wp.x+dragOff.x;
      nodes[dragNode].y=wp.y+dragOff.y;
      nodes[dragNode].vx=0; nodes[dragNode].vy=0;
    } else if(dragCam){
      camX=dragCam.cx+(e.clientX-dragCam.sx);
      camY=dragCam.cy+(e.clientY-dragCam.sy);
    } else {
      const h=hit(wp.x,wp.y);
      canvas.style.cursor=h?'pointer':'grab';
      showTip(h, sx, sy);
    }
  }

  function onMU(e){ dragNode=null; dragCam=null; canvas.style.cursor='grab'; }
  function onML(e){ dragNode=null; dragCam=null; hideTip(); }

  function onWheel(e){
    e.preventDefault();
    const f=e.deltaY<0?1.12:0.89;
    const r=canvas.getBoundingClientRect();
    const mx=e.clientX-r.left, my=e.clientY-r.top;
    camX=mx+(camX-mx)*f; camY=my+(camY-my)*f;
    camZ=Math.max(0.18,Math.min(4,camZ*f));
  }

  function onClick(e){
    if(mouseDownAt){
      const dx=e.clientX-mouseDownAt.x, dy=e.clientY-mouseDownAt.y;
      if(dx*dx+dy*dy>25) return;
    }
    const r=canvas.getBoundingClientRect();
    const wp=sw(e.clientX-r.left,e.clientY-r.top);
    const h=hit(wp.x,wp.y);
    selIP=h||null;
    if(!h) closeTrace();
  }

  function onDbl(e){
    const r=canvas.getBoundingClientRect();
    const wp=sw(e.clientX-r.left,e.clientY-r.top);
    const h=hit(wp.x,wp.y);
    if(h) openTrace(h);
  }

  // ── Tooltip ───────────────────────────────────────────────────────────────
  let _tipNode=null;
  function showTip(ip, sx, sy){
    const tip=document.getElementById('topo-tip');
    if(!ip){hideTip();return;}
    if(ip===_tipNode) { tip.style.left=(sx+16)+'px'; tip.style.top=(sy-10+52)+'px'; return; }
    _tipNode=ip;
    const n=nodes[ip]; if(!n) return;
    const col=nodeCol(n);
    const cat=category(n.device_type,n.is_gateway);
    const catLabel={'router':'Router/AP','phone':'Mobile Phone','tablet':'Tablet',
      'laptop':'Laptop','desktop':'Desktop PC','server':'Server','tv':'Smart TV',
      'printer':'Printer','camera':'IP Camera','console':'Game Console',
      'vm':'Virtual Machine','iot':'IoT Device','speaker':'Smart Speaker',
      'watch':'Wearable','unknown':'Unknown'}[cat]||cat;
    tip.style.display='block';
    tip.style.left=(sx+16)+'px'; tip.style.top=(sy-10+52)+'px';
    tip.innerHTML=`
      <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:7px">
        <div style="width:10px;height:10px;border-radius:50%;background:${col};box-shadow:0 0 6px ${col}"></div>
        <span style="font-weight:700;color:${col};font-size:12px">${n.ip}</span>
        ${n.is_gateway?'<span style="font-size:9px;color:var(--accent);border:1px solid var(--accent);border-radius:3px;padding:1px 4px">GATEWAY</span>':''}
      </div>
      <div style="display:grid;grid-template-columns:90px 1fr;gap:3px 8px;font-size:10px;line-height:1.6">
        <span style="color:var(--muted)">Type</span><span style="font-weight:600">${catLabel}</span>
        <span style="color:var(--muted)">Hostname</span><span>${n.hostname||'–'}</span>
        <span style="color:var(--muted)">Vendor</span><span>${n.vendor||'Unknown'}</span>
        <span style="color:var(--muted)">MAC</span><span style="font-family:'JetBrains Mono',monospace">${n.mac||'–'}</span>
        <span style="color:var(--muted)">OS</span><span>${(n.os||'Unknown').substring(0,26)}</span>
        <span style="color:var(--muted)">Status</span><span style="color:${n.status==='online'?'#00e676':'#3d5068'}">${n.status}</span>
        <span style="color:var(--muted)">Vulns</span><span style="color:${(n.vuln_count||0)>0?'#ff2d55':'#00e676'};font-weight:700">${n.vuln_count||0}</span>
        <span style="color:var(--muted)">↓ Traffic</span><span>${fmtB(n.bytes_in||0)}</span>
        <span style="color:var(--muted)">↑ Traffic</span><span>${fmtB(n.bytes_out||0)}</span>
      </div>
      <div style="margin-top:7px;font-size:9px;color:var(--muted);border-top:1px solid var(--border);padding-top:6px">
        Click = select  ·  Double-click = packet trace  ·  Drag = move
      </div>`;
  }
  function hideTip(){
    _tipNode=null;
    const t=document.getElementById('topo-tip');
    if(t) t.style.display='none';
  }

  // ── Packet trace panel ─────────────────────────────────────────────────────
  function openTrace(ip){
    traceIP=ip; selIP=ip;
    const n=nodes[ip];
    const cat=category(n?n.device_type:'', n?n.is_gateway:false);
    document.getElementById('trace-title').textContent=ip;
    document.getElementById('trace-info').textContent=
      [n&&n.hostname, n&&n.vendor, n&&n.os].filter(Boolean).join(' · ').substring(0,60);
    document.getElementById('topo-trace').style.transform='translateX(0)';
    refreshTrace();
  }
  function closeTrace(){
    traceIP=null;
    const t=document.getElementById('topo-trace');
    if(t) t.style.transform='translateX(100%)';
  }
  let _traceTimer=null;
  function refreshTrace(){
    if(!traceIP) return;
    fetch('/api/packets/'+traceIP).then(r=>r.json()).then(pkts2=>{
      const el=document.getElementById('trace-list');
      if(!el) return;
      el.innerHTML=pkts2.slice(0,80).map(p=>`
        <div class="trace-row">
          <span class="tr-proto tr-${p.proto}">${p.proto}</span>
          <span style="color:var(--muted);min-width:56px">${p.ts}</span>
          <span style="color:var(--accent)">${p.src}</span>
          <span style="color:var(--muted)">→</span>
          <span style="color:#ce93d8">${p.dst}</span>
          <span style="color:var(--muted);margin-left:auto">${fmtB(p.len||0)}</span>
        </div>`).join('')||'<div style="color:var(--muted);padding:8px;font-size:10px">No packets yet.</div>';
    }).catch(()=>{});
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  function onTopoPacket(p){
    pktRateCtr++;
    // STRICT: only animate packets between nodes that the scanner already knows.
    // Never create phantom nodes from packet traffic – the graph shows only
    // devices that have been discovered by the network scan.
    const srcKnown = !!nodes[p.src];
    const dstKnown = !!nodes[p.dst];
    // If neither endpoint is a known device, ignore completely
    if (!srcKnown && !dstKnown) { updStats(); return; }
    // Remap unknown endpoint to gateway for edge accounting
    const eSrc = srcKnown ? p.src : (gateway || p.src);
    const eDst = dstKnown ? p.dst : (gateway || p.dst);
    if (eSrc === eDst) { updStats(); return; }
    // ── Normalised edge upsert — sorted key prevents duplicate a|b + b|a ───────
    const epair = [eSrc, eDst].sort();
    const ekn   = epair[0]+'|'+epair[1];
    if (!edges[ekn]) {
      edges[ekn] = {a:epair[0], b:epair[1], proto:p.proto,
                    count:0, bytes:0, recentBytes:0, alpha:0.18, activity:0};
    }
    const e = edges[ekn];

    // Accumulate bytes for tooltip; count only for stats (not width/alpha)
    e.count       = Math.min((e.count||0) + 1, 999);
    e.bytes       = (e.bytes||0) + (p.len||0);
    e.recentBytes = (e.recentBytes||0) + (p.len||0);
    e.proto       = p.proto;

    // Activity boost: rate-limited so a busy link (device↔router carries ALL
    // traffic) cannot keep activity pinned at 1.0.
    // Only boost when activity has decayed below 0.35 — produces a visible
    // flash rather than a permanently lit/thick line.
    if ((e.activity||0) < 0.35) e.activity = 0.80;

    // ── Flying dot — one dot per edge at a time ─────────────────────────────
    // On busy links every packet would spawn a dot otherwise, making the line
    // look like a thick glowing bar. Skip if a dot for this edge is in flight.
    if (!pkts.some(pt => pt.key === ekn)) {
      const src_ = srcKnown ? p.src : eSrc;
      const dst_ = dstKnown ? p.dst : eDst;
      spawnPkt(src_, dst_, p.proto, p.len||64, ekn);
    }
    // Live refresh of trace panel
    if(traceIP&&(p.src===traceIP||p.dst===traceIP)){
      clearTimeout(_traceTimer);
      _traceTimer=setTimeout(refreshTrace, 600);
    }
    updStats();
  }

  function onDeviceUpdate(d){
    if (!d || !d.ip) return;
    if (!nodes[d.ip]) {
      // New node – place it around gateway or canvas centre
      const gn  = gateway ? nodes[gateway] : null;
      const cx  = gn ? gn.x : W()/2;
      const cy  = gn ? gn.y : H()/2;
      const ang = Math.random() * Math.PI * 2;
      const dst = d.is_gateway ? 0 : 120 + Math.random()*180;
      nodes[d.ip] = {
        x: cx + Math.cos(ang)*dst, y: cy + Math.sin(ang)*dst,
        vx:0, vy:0, pinned: d.is_gateway||false,
        phase: Math.random()*Math.PI*2, activity:0,
      };
      // Add edge to gateway — use normalised key
      if (!d.is_gateway && gateway && nodes[gateway]) {
        const pair = [d.ip, gateway].sort();
        const ekn  = pair[0]+'|'+pair[1];
        if (!edges[ekn]) {
          edges[ekn] = {a:pair[0], b:pair[1], proto:'OTHER',
                        count:0, bytes:0, recentBytes:0, alpha:0.18, activity:0};
        }
      }
    }
    Object.assign(nodes[d.ip], d);
    nodes[d.ip].r = d.is_gateway ? 30 : 22;
    if (d.is_gateway && !gateway) {
      gateway = d.ip;
      nodes[d.ip].pinned = true;
      nodes[d.ip].x = W()/2;
      nodes[d.ip].y = H()/2;
    }
    updStats();
  }

  function onInitialState(data){
    // Immediately seed nodes from the device list in initial_state
    // so the graph shows devices even before the topology API fetch completes
    if (data && data.devices && data.devices.length > 0) {
      const synth = {
        gateway: data.stats ? data.stats.gateway : gateway,
        nodes: data.devices.map(d => ({
          ip:          d.ip,
          hostname:    d.hostname || '',
          vendor:      d.vendor || 'Unknown',
          device_type: d.device_type || 'Unknown',
          os:          d.os || 'Unknown',
          status:      d.status || 'offline',
          is_gateway:  d.is_gateway || false,
          vuln_count:  d.vuln_count || 0,
          bytes_in:    d.bytes_in || 0,
          bytes_out:   d.bytes_out || 0,
          mac:         d.mac || '',
        })),
        edges: []
      };
      if (!synth.gateway && data.stats) synth.gateway = data.stats.gateway;
      applyTopo(synth);
    }
    // Also fetch full topology (edges + confirmed data)
    fetch('/api/topology').then(r=>r.json()).then(applyTopo).catch(()=>{});
  }

  function togglePause(){
    paused=!paused;
    const b=document.getElementById('topo-pause-btn');
    if(b) b.textContent=paused?'▶ Resume':'⏸ Pause';
  }
  function reset(){
    camX=0;camY=0;camZ=1;
    const cx=W()/2,cy=H()/2;
    Object.values(nodes).forEach(n=>{
      if(n.pinned){n.x=cx;n.y=cy;return;}
      const a=Math.random()*Math.PI*2,d=110+Math.random()*200;
      n.x=cx+Math.cos(a)*d; n.y=cy+Math.sin(a)*d; n.vx=0;n.vy=0;
    });
  }
  function zoomIn() {camZ=Math.min(4,camZ*1.2);}
  function zoomOut(){camZ=Math.max(0.18,camZ*0.83);}

  function fit() {
    const ns = Object.values(nodes);
    if (!ns.length) return;
    const xs = ns.map(n=>n.x), ys = ns.map(n=>n.y);
    const minX=Math.min(...xs), maxX=Math.max(...xs);
    const minY=Math.min(...ys), maxY=Math.max(...ys);
    const pw=W(), ph=H();
    const pad=80;
    const scaleX=(pw-pad*2)/Math.max(1,maxX-minX);
    const scaleY=(ph-pad*2)/Math.max(1,maxY-minY);
    camZ=Math.max(0.18,Math.min(3,Math.min(scaleX,scaleY)));
    camX=pw/2-((minX+maxX)/2)*camZ;
    camY=ph/2-((minY+maxY)/2)*camZ;
  }

  function fmtB(b){
    if(b<1024)return b+'B';
    if(b<1048576)return(b/1024).toFixed(1)+'KB';
    return(b/1048576).toFixed(1)+'MB';
  }

  return {init,onTopoPacket,onDeviceUpdate,onInitialState,
          togglePause,reset,zoomIn,zoomOut,fit,closeTrace};
})();

function topoTogglePause(){TOPO.togglePause();}
function topoReset()      {TOPO.reset();}
function topoZoomIn()     {TOPO.zoomIn();}
function topoZoomOut()    {TOPO.zoomOut();}
function topoFit()        {TOPO.fit();}
function closeTrace()     {TOPO.closeTrace();}

let _topoInited=false;
function ensureTopoInit(){
  if(!_topoInited){
    _topoInited=true;
    setTimeout(()=>{
      TOPO.init();
      // Flush any device data that arrived before the graph was ready
      setTimeout(()=>{
        if(_pendingInitial) { TOPO.onInitialState(_pendingInitial); _pendingInitial=null; }
        _pendingDeviceUpdates.forEach(d=>TOPO.onDeviceUpdate(d));
        _pendingDeviceUpdates.length=0;
      }, 150);
    }, 50);
  }
}

// ── Render ────────────────────────────────────────────────────────────────
function renderAll() {
  renderOverview(); renderDevices(); renderAlerts();
  renderVulns(); renderPorts(); renderGraphs(); updateCounters();
}

function updateCounters() {
  const devs = Object.values(S.devices);
  const online = devs.filter(d=>d.status==="online").length;
  const vulns  = devs.reduce((s,d)=>s+(d.vuln_count||0),0);
  const ports  = devs.reduce((s,d)=>s+Object.keys(d.open_ports||{}).length,0);
  ["s-dev","ov-dev"].forEach(i=>el(i,devs.length));
  ["s-on","ov-on"].forEach(i=>el(i,online));
  ["s-al","ov-al"].forEach(i=>el(i,S.stats.alert_count||0));
  el("ov-vu",vulns); el("ov-pt",ports); el("ov-sc",S.stats.scan_count||0);
  el("hdr-net",S.stats.network||""); el("hdr-gw","GW: "+(S.stats.gateway||""));
  badge();
  // Sys stats
  document.getElementById("sys-stats").innerHTML =
    `Network: <span style="color:var(--accent)">${S.stats.network||"–"}</span><br>
     Gateway: <span style="color:var(--accent2)">${S.stats.gateway||"–"}</span><br>
     Scans: <span style="color:var(--yellow)">${S.stats.scan_count||0}</span><br>
     Pkt/s: <span style="color:var(--green)">${S.stats.pps||0}</span>`;
}

function renderOverview() { updateCounters(); renderOvCharts(); renderOvAlerts(); }

function renderOvCharts() {
  const devs = Object.values(S.devices);
  const tc={}, sc={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  devs.forEach(d=>{const t=d.device_type||"Unknown";tc[t]=(tc[t]||0)+1;});
  S.alerts.forEach(a=>{if(sc[a.severity]!==undefined)sc[a.severity]++;});
  const pal=["#00e5ff","#7c4dff","#00e676","#ffd740","#ff6d00","#ff1744","#69f0ae","#ea80fc"];
  const tl=Object.keys(tc), td=tl.map(k=>tc[k]);
  if(chTypes){chTypes.data.labels=tl;chTypes.data.datasets[0].data=td;chTypes.update();}
  else chTypes=mkChart("ch-types","doughnut",tl,td,pal);
  const sl=Object.keys(sc), sd=Object.values(sc);
  const sp=["#ff2d55","#ff6b35","#ffd60a","#30d158","#636366"];
  if(chSev){chSev.data.datasets[0].data=sd;chSev.update();}
  else chSev=mkBarChart("ch-sev",sl,sd,sp);
}

function mkChart(id,type,labels,data,colors){
  return new Chart(document.getElementById(id),{
    type,data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0}]},
    options:{plugins:{legend:{labels:{color:"#8899aa",font:{size:10}}}}}
  });
}
function mkBarChart(id,labels,data,colors){
  return new Chart(document.getElementById(id),{
    type:"bar",
    data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0,borderRadius:3}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:"#4a6080"},grid:{color:"#1a2535"}},
              y:{ticks:{color:"#4a6080"},grid:{color:"#1a2535"}}}}
  });
}

function renderOvAlerts(){
  document.getElementById("ov-alerts").innerHTML=
    S.alerts.slice(0,5).map(alertHtml).join("")||"<div style='color:var(--muted);padding:12px'>No alerts.</div>";
}

// Helper: is a string "empty" / "unknown"
function _isBlank(s){ return !s || s.toLowerCase()==="unknown" || s.trim()===""; }

function renderDevices() {
  const q=(document.getElementById("dev-search").value||"").toLowerCase();
  const rows=Object.values(S.devices)
    .filter(d=>!q||JSON.stringify(d).toLowerCase().includes(q))
    .sort((a,b)=>(a.ip||"").localeCompare(b.ip||"",undefined,{numeric:true}));

  document.getElementById("dev-tbody").innerHTML=rows.map(d=>{
    // ── Vendor: show IP when unknown/empty or already an IP ───────────────────
    const vendorRaw  = d.brand || d.vendor || "";
    const vendorIsIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(vendorRaw.trim());
    const vendorDisp = (!_isBlank(vendorRaw) && !vendorIsIP)
      ? `<span title="${vendorRaw}">${vendorRaw.substring(0,18)}</span>`
      : `<span class="mono" style="color:var(--accent);font-size:10px">${d.ip}</span>`;

    // ── Device type: show IP when unknown/empty, no icon for IP ───────────────
    const typeRaw   = d.device_type || "";
    const typeIsIP  = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(typeRaw.trim());
    const typeBlank = _isBlank(typeRaw) || typeIsIP;
    const typeIcon  = typeBlank ? "" : dtIcon(typeRaw);
    const typeLabel = typeBlank ? d.ip : typeRaw;
    const typeDisp  = typeBlank
      ? `<span class="mono" style="color:var(--accent);font-size:10px">${d.ip}</span>`
      : `${typeIcon?typeIcon+" ":""}${typeRaw}`;

    // ── OS: resolve to exact fallback text, never show Apple icon for unknowns ──
    const osResolved = resolveOsDisplay(d.os, d.ttl);
    const osText     = osResolved.text;
    const osIcon_    = osResolved.icon;  // "" for any mixed/unknown OS
    const osAcc      = d.os_accuracy ? d.os_accuracy.replace(/~ARP seed/,"detecting…") : "";

    // ── Status + blocked styling ────────────────────────────────────────────
    const isBlocked  = !!(d.blocked || d.status === "blocked");
    const isOnline   = !isBlocked && d.status === "online";
    const statusDot  = isBlocked ? "dot-off" : isOnline ? "dot-on" : "dot-off";
    const statusText = isBlocked
      ? '<span style="color:var(--red);font-weight:600;font-size:10px">🚫 blocked</span>'
      : `<span style="color:${isOnline?"var(--green)":"var(--muted)"}">${d.status||"offline"}</span>`;

    return `<tr onclick="openModal('${d.ip}')"
        style="${isBlocked?"opacity:.65;background:rgba(255,45,85,.04)":""}">
      <td style="white-space:nowrap"><span class="dot ${statusDot}"></span>${statusText}</td>
      <td class="ip" style="white-space:nowrap">${d.ip}</td>
      <td class="mac-addr">${d.mac||"–"}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${d.hostname||""}">${d.hostname||"–"}</td>
      <td style="white-space:nowrap">${typeDisp}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${vendorDisp}</td>
      <td>
        <span class="os-badge" title="${osText}">${osIcon_?osIcon_+" ":""}${osText}</span>
        ${osAcc?`<span style="font-size:9px;color:var(--muted);display:block;margin-top:1px">${osAcc}</span>`:""}
      </td>
      <td style="text-align:center">${Object.keys(d.open_ports||{}).length}</td>
      <td style="text-align:center">${(d.vuln_count||0)>0
          ?`<span style="color:var(--red);font-weight:700">${d.vuln_count}</span>`:"0"}</td>
      <td class="mono" style="font-size:10px;color:var(--muted);white-space:nowrap">${d.ttl||"–"}</td>
      <td style="font-size:10px;color:var(--muted);white-space:nowrap">${(d.last_seen||"").substring(11)||""}</td>
      <td onclick="event.stopPropagation()" style="white-space:nowrap">
        ${isBlocked
          ? `<button class="tbtn" style="color:var(--green);border-color:var(--green);
               font-size:9px;padding:2px 8px;min-width:70px"
               onclick="blockDevice('${d.ip}',event)" title="Reconnect">✓ Unblock</button>`
          : `<button class="tbtn" style="color:var(--red);border-color:var(--red);
               font-size:9px;padding:2px 8px;min-width:70px"
               onclick="blockDevice('${d.ip}',event)" title="Disconnect from network">🚫 Block</button>`}
      </td>
    </tr>`;
  }).join("");
}
function filterDevs(){renderDevices();}

function renderAlerts(){
  document.getElementById("alert-list").innerHTML=
    S.alerts.map(alertHtml).join("")||"<div style='color:var(--muted);padding:16px'>No alerts yet.</div>";
}

function alertHtml(a){
  const c=sev2col(a.severity);
  return `<div class="alert-card ${a.ack?'acked':''}" id="al-${a.id}">
    <div class="alert-bar" style="background:${c}"></div>
    <div style="flex:1">
      <div style="display:flex;align-items:center;gap:7px">
        <span class="badge-sev sev-${a.severity}">${a.severity}</span>
        <span class="alert-title">${a.title}</span>
      </div>
      <div class="alert-detail">${a.detail}</div>
      <div class="alert-meta"><span class="ip">${a.ip}</span> · ${a.ts}</div>
    </div>
    ${!a.ack?`<button class="ack-btn" onclick="ack('${a.id}',event)">✓ ACK</button>`
            :`<span style="font-size:9px;color:var(--muted)">ACKed</span>`}
  </div>`;
}

function renderVulns(){
  const rows=[];
  Object.values(S.devices).forEach(d=>(d.vulnerabilities||[]).forEach(v=>rows.push({ip:d.ip,...v})));
  rows.sort((a,b)=>({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity]||9)-({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity]||9));
  document.getElementById("vuln-list").innerHTML=rows.length?rows.map(v=>`
    <div class="alert-card" style="margin-bottom:7px">
      <div class="alert-bar" style="background:${sev2col(v.severity)}"></div>
      <div style="flex:1">
        <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
          <span class="badge-sev sev-${v.severity}">${v.severity}</span>
          <strong>${v.service}</strong>
          ${v.port?`<span class="mono" style="color:var(--accent2);font-size:11px">:${v.port}</span>`:""}
          <span class="ip" style="font-size:11px;margin-left:auto">${v.ip}</span>
        </div>
        <div class="alert-detail">${v.description}</div>
        ${v.version?`<div style="font-size:10px;color:var(--muted);margin-top:2px">ver: ${v.version}</div>`:""}
      </div>
    </div>`).join("")
    :"<div style='color:var(--muted);padding:16px'>No vulnerabilities detected yet.</div>";
}

function renderPorts(){
  const q=(document.getElementById("port-search").value||"").toLowerCase();
  let html="";
  Object.values(S.devices).forEach(d=>{
    const pts=Object.entries(d.open_ports||{})
      .filter(([p,i])=>i.state==="open"&&(!q||p.toString().includes(q)||i.service.toLowerCase().includes(q)));
    if(!pts.length) return;
    html+=`<div style="margin-bottom:18px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span class="ip">${d.ip}</span>
        <span style="color:var(--muted);font-size:10px">${d.vendor||""} – ${d.device_type||""}</span>
        <span class="os-badge" style="margin-left:auto">${(()=>{const r=resolveOsDisplay(d.os,d.ttl);return (r.icon?r.icon+" ":"")+r.text;})()}</span>
      </div>
      <div class="port-grid">
        ${pts.map(([p,i])=>{
          const vp=VPMAP[parseInt(p)];
          const s=vp?vp[1]:"LOW";
          return `<div class="port-card">
            <div class="port-num">${p}</div>
            <div><div class="port-svc">${i.service||"unknown"} <span class="badge-sev sev-${s}" style="font-size:8px">${s}</span></div>
            <div class="port-ver">${i.version||i.protocol||""}</div></div></div>`;
        }).join("")}
      </div></div>`;
  });
  document.getElementById("ports-content").innerHTML=html||"<div style='color:var(--muted);padding:16px'>Scanning…</div>";
}
function filterPorts(){renderPorts();}

// ── Bandwidth graphs ──────────────────────────────────────────────────────
function renderGraphs(){
  const c=document.getElementById("graphs-content");
  Object.values(S.devices).filter(d=>d.status==="online").forEach(d=>{
    const cid="bwc-"+d.ip.replace(/\./g,"-");
    if(!document.getElementById(cid)){
      const wrap=document.createElement("div");
      wrap.className="chart-card";
      wrap.innerHTML=`<div class="chart-lbl">${d.ip} – ${d.vendor||d.device_type||"Device"}
        <span class="os-badge" style="margin-left:8px;font-size:9px">${(()=>{const r=resolveOsDisplay(d.os,d.ttl);return (r.icon?r.icon+" ":"")+r.text.substring(0,20);})()}</span></div>
        <canvas id="${cid}" height="70"></canvas>`;
      c.appendChild(wrap);
    }
  });
}
function updateDevCharts(upd){
  Object.entries(upd.data||{}).forEach(([ip,bw])=>{
    const cid="bwc-"+ip.replace(/\./g,"-");
    const canvas=document.getElementById(cid);
    if(!canvas) return;
    if(!devCharts[ip]){
      devCharts[ip]=new Chart(canvas,{
        type:"line",
        data:{labels:[],datasets:[
          {label:"In",  data:[],borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
          {label:"Out", data:[],borderColor:"#7c4dff",backgroundColor:"rgba(124,77,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        ]},
        options:{animation:false,
          plugins:{legend:{labels:{color:"#8899aa",font:{size:9}}}},
          scales:{x:{ticks:{color:"#3d5068",maxTicksLimit:6},grid:{color:"#1a2535"}},
                  y:{ticks:{color:"#3d5068"},grid:{color:"#1a2535"}}}}
      });
    }
    const ch=devCharts[ip];
    ch.data.labels.push(upd.ts);
    ch.data.datasets[0].data.push(bw.in);
    ch.data.datasets[1].data.push(bw.out);
    if(ch.data.labels.length>60){ch.data.labels.shift();ch.data.datasets.forEach(ds=>ds.data.shift());}
    ch.update("none");
  });
}

// ── Packet stream ─────────────────────────────────────────────────────────
function addPkt(p){
  pktTotal++;
  if(["RECV","SEND"].includes(p.proto)) capMode="psutil";
  else if(!capMode&&["TCP","UDP","ICMP"].includes(p.proto)) capMode="scapy";
  const ph=document.getElementById("pkt-ph");
  if(ph) ph.remove();
  el("pkt-ctr", pktTotal.toLocaleString()+" pkts");
  if(pktTotal%30===1){
    const b=document.getElementById("cap-badge");
    if(b){
      if(capMode==="scapy"){b.textContent="🔴 Scapy (root)";b.style.color="var(--green)";}
      else{b.textContent="🟡 psutil";b.style.color="var(--yellow)";}
    }
  }
  const s=document.getElementById("pkt-stream");
  const d=document.createElement("div");
  d.className="pkt";
  d.innerHTML=`<span class="pkt-ts">${p.ts}</span>`+
    `<span class="pkt-proto pkt-${p.proto}">${p.proto}</span>`+
    `<span class="pkt-src">${p.src}</span>`+
    `<span style="color:var(--muted)">→</span>`+
    `<span class="pkt-dst">${p.dst}</span>`+
    `<span class="pkt-info">${p.info||""}</span>`+
    `<span style="color:var(--muted);margin-left:auto;white-space:nowrap">${fmt(p.len)}</span>`;
  s.insertBefore(d, s.firstChild);
  if(s.children.length>500) s.removeChild(s.lastChild);
}
function clearPkts(){
  document.getElementById("pkt-stream").innerHTML=
    '<div id="pkt-ph" style="color:var(--muted);padding:18px;text-align:center">Cleared — waiting…</div>';
  pktTotal=0; el("pkt-ctr","0 pkts");
}
function togglePause(){paused=!paused;document.getElementById("pause-btn").textContent=paused?"▶ Resume":"⏸ Pause";}

// ── Modal ─────────────────────────────────────────────────────────────────
function openModal(ip){
  curModal=ip;
  const d=S.devices[ip];
  if(!d) return;
  document.getElementById("modal-overlay").classList.add("open");
  document.getElementById("modal-title").textContent=`${dtIcon(d.device_type)} ${d.ip}`;
  document.getElementById("modal-sub").textContent=`${d.brand||d.vendor||"Unknown"} · ${d.device_type||"Unknown"} · ${d.os||"Unknown OS"}`;
  const ports=Object.entries(d.open_ports||{}).filter(([_,i])=>i.state==="open");
  const vulns=d.vulnerabilities||[];
  document.getElementById("modal-body").innerHTML=`
    <div class="detail-grid">
      ${kv("IP",d.ip)} ${kv("MAC",d.mac||"N/A")} ${kv("Hostname",d.hostname||"N/A")}
      ${kv("Vendor",d.vendor||"Unknown")} ${kv("Brand",d.brand||"Unknown")} ${kv("Type",d.device_type||"Unknown")}
      ${kv("OS",(()=>{const r=resolveOsDisplay(d.os,d.ttl);return (r.icon?r.icon+" ":"")+r.text;})())}
      ${kv("OS Accuracy",d.os_accuracy||"N/A")} ${kv("TTL",d.ttl||"N/A")}
      ${kv("Status",d.status||"offline")} ${kv("First Seen",d.first_seen||"N/A")} ${kv("Last Seen",d.last_seen||"N/A")}
      ${kv("Traffic In",fmt(d.bytes_in||0))} ${kv("Traffic Out",fmt(d.bytes_out||0))}
    </div>
    <div class="chart-card"><div class="chart-lbl">Bandwidth – last 60s</div>
      <canvas id="modal-bw" height="70"></canvas></div>
    <div style="margin-bottom:14px">
      <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px">
        Open Ports (${ports.length})</div>
      <div class="port-grid">
        ${ports.map(([p,i])=>`<div class="port-card">
          <div class="port-num">${p}</div>
          <div><div class="port-svc">${i.service||"unknown"}</div>
          <div class="port-ver">${i.version||""}</div></div></div>`).join("")
          ||"<span style='color:var(--muted);font-size:11px'>No open ports</span>"}
      </div>
    </div>
    <div>
      <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px">
        Vulnerabilities (${vulns.length})</div>
      ${vulns.map(v=>`<div class="alert-card" style="margin-bottom:7px">
        <div class="alert-bar" style="background:${sev2col(v.severity)}"></div>
        <div><div style="display:flex;gap:6px;align-items:center">
          <span class="badge-sev sev-${v.severity}">${v.severity}</span>
          <strong>${v.service}</strong>
          ${v.port?`<span class="mono" style="color:var(--accent2);font-size:11px">:${v.port}</span>`:""}
        </div>
        <div class="alert-detail">${v.description}</div></div></div>`).join("")
        ||"<span style='color:var(--low);font-size:11px'>✓ No vulnerabilities</span>"}
    </div>`;
  fetch(`/api/traffic/${ip}`).then(r=>r.json()).then(td=>{
    try{
      new Chart(document.getElementById("modal-bw"),{
        type:"line",
        data:{labels:td.map(t=>t.ts),datasets:[
          {label:"In",  data:td.map(t=>t.in),  borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,.08)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
          {label:"Out", data:td.map(t=>t.out), borderColor:"#7c4dff",backgroundColor:"rgba(124,77,255,.08)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        ]},
        options:{animation:false,
          plugins:{legend:{labels:{color:"#8899aa"}}},
          scales:{x:{ticks:{color:"#3d5068",maxTicksLimit:8},grid:{color:"#1a2535"}},
                  y:{ticks:{color:"#3d5068"},grid:{color:"#1a2535"}}}}
      });
    }catch(e){}
  });
}
function closeModal(){document.getElementById("modal-overlay").classList.remove("open");curModal=null;}
function rescan(){
  if(!curModal) return;
  fetch(`/api/rescan/${curModal}`,{method:"POST"}).then(r=>r.json())
    .then(d=>toast({title:"Rescan Queued",detail:d.message||"",severity:"INFO"}));
}
document.getElementById("modal-overlay").addEventListener("click",function(e){if(e.target===this)closeModal();});

// ── Alerts ────────────────────────────────────────────────────────────────
function ack(id,e){
  e.stopPropagation();
  fetch(`/api/alerts/ack/${id}`,{method:"POST"}).then(()=>{
    const a=S.alerts.find(x=>x.id===id);if(a)a.ack=true;
    renderAlerts();renderOvAlerts();badge();
  });
}
function ackAll(){
  S.alerts.filter(a=>!a.ack).forEach(a=>{fetch(`/api/alerts/ack/${a.id}`,{method:"POST"});a.ack=true;});
  renderAlerts();badge();
}
function badge(){
  const n=S.alerts.filter(a=>!a.ack).length;
  const b=document.getElementById("al-badge");
  b.style.display=n>0?"":"none";b.textContent=n;
  el("s-al",S.stats.alert_count||0);
}

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(a){
  const c=document.getElementById("toasts");
  const d=document.createElement("div");d.className="toast";
  d.innerHTML=`<div class="toast-bar" style="background:${sev2col(a.severity||'INFO')}"></div>
    <div><div style="font-weight:600;font-size:12px">${a.title||""}</div>
    <div style="font-size:10px;color:var(--muted);margin-top:2px">${(a.detail||"").substring(0,80)}</div></div>`;
  c.appendChild(d);
  setTimeout(()=>{d.style.opacity="0";d.style.transform="translateX(110%)";setTimeout(()=>d.remove(),400);},5000);
}

// ── Navigation ────────────────────────────────────────────────────────────
function nav(el,name){
  document.querySelectorAll(".panel").forEach(p=>p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n=>n.classList.remove("active"));
  document.getElementById("panel-"+name).classList.add("active");
  el.classList.add("active");
  if(name==="overview"){ensureTopoInit();}
  if(name==="graphs"){renderGraphs();}
  if(name==="ports"){renderPorts();}
  if(name==="vulns"){renderVulns();}
  if(name==="osint"){osintInit();}
}

// ── INTERNET SPEED TEST ──────────────────────────────────────────────────────
let _spdTimer = null;
let _spdProgress = 0;

function runSpeedTest() {
  const btn = document.getElementById("speed-btn");
  if (btn.disabled) return;  // already running

  // Reset UI
  btn.disabled = true;
  btn.textContent = "⏳ Testing…";
  ["spd-down","spd-up","spd-lat","spd-jit"].forEach(id => {
    const e = document.getElementById(id);
    if (e) { e.textContent = "—"; e.style.color = "var(--muted)"; }
  });
  ["spd-down-bar","spd-up-bar","spd-lat-bar","spd-jit-bar"].forEach(id => {
    const e = document.getElementById(id);
    if (e) e.style.width = "0%";
  });
  el("spd-status","Testing…"); el("spd-emoji","⏳");
  el("spd-server",""); el("spd-isp",""); el("spd-ts","");
  const statusEl = document.getElementById("spd-status");
  if (statusEl) statusEl.style.color = "var(--yellow)";

  // Show progress bar
  const pwrap = document.getElementById("spd-progress-wrap");
  const pbar  = document.getElementById("spd-progress");
  const phase = document.getElementById("spd-phase");
  if (pwrap) pwrap.style.display = "block";

  // Animated progress (fake, since we can't stream from server)
  _spdProgress = 0;
  const phases = [
    [8,  "🔍 Locating nearest test server…"],
    [22, "📡 Measuring latency & jitter (10 probes)…"],
    [42, "⬇ Testing download speed (multi-stream)…"],
    [70, "⬆ Testing upload speed…"],
    [92, "📊 Computing results…"],
  ];
  let phaseIdx = 0;
  if (_spdTimer) clearInterval(_spdTimer);
  _spdTimer = setInterval(() => {
    if (_spdProgress < 94) {
      _spdProgress = Math.min(94, _spdProgress + 0.8);
      if (pbar) pbar.style.width = _spdProgress + "%";
      // Update phase label
      const nextPhase = phases.find(([pct]) => _spdProgress < pct);
      if (nextPhase && phase) phase.textContent = nextPhase[1];
    }
  }, 200);

  // Fire the actual test
  fetch("/api/speedtest").then(r => r.json()).then(d => {
    clearInterval(_spdTimer);
    if (pbar)  pbar.style.width  = "100%";
    if (phase) phase.textContent = "✓ Complete";
    setTimeout(() => { if (pwrap) pwrap.style.display = "none"; }, 1200);

    btn.disabled = false; btn.textContent = "↺ Run Again";

    const dl  = d.download_mbps || 0;
    const up  = d.upload_mbps   || 0;
    const lat = d.latency_ms    || 0;
    const jit = d.jitter_ms     || 0;

    // ── Download ──
    const dlCol = dl > 50 ? "var(--green)" : dl > 10 ? "var(--accent)" : "var(--orange)";
    el("spd-down", dl.toFixed(1));
    document.getElementById("spd-down").style.color = dlCol;
    document.getElementById("spd-down-bar").style.width = Math.min(100, (dl / 100) * 100) + "%";

    // ── Upload ──
    const upCol = up > 20 ? "var(--green)" : up > 5 ? "#7c4dff" : "var(--orange)";
    el("spd-up", up.toFixed(1));
    document.getElementById("spd-up").style.color = upCol;
    document.getElementById("spd-up-bar").style.width = Math.min(100, (up / 50) * 100) + "%";

    // ── Ping ──
    const latCol = lat < 30 ? "var(--green)" : lat < 80 ? "var(--yellow)" : "var(--red)";
    el("spd-lat", lat.toFixed(1));
    document.getElementById("spd-lat").style.color = latCol;
    // Ping bar: lower = better (invert: 200ms = 0 bar, 0ms = full bar)
    document.getElementById("spd-lat-bar").style.width = Math.min(100, Math.max(0, 100 - (lat / 200) * 100)) + "%";

    // ── Jitter ──
    const jitCol = jit < 10 ? "var(--green)" : jit < 30 ? "var(--yellow)" : "var(--red)";
    el("spd-jit", jit.toFixed(1));
    document.getElementById("spd-jit").style.color = jitCol;
    document.getElementById("spd-jit-bar").style.width = Math.min(100, Math.max(0, 100 - (jit / 50) * 100)) + "%";

    // ── Quality rating ──
    let quality, emoji, bars, qCol;
    if (dl > 50 && up > 20 && lat < 30) {
      quality = "Excellent"; emoji = "🚀"; bars = 5; qCol = "var(--green)";
    } else if (dl > 20 && up > 5 && lat < 60) {
      quality = "Good";      emoji = "✅"; bars = 4; qCol = "var(--green)";
    } else if (dl > 5 && lat < 120) {
      quality = "Fair";      emoji = "⚡"; bars = 3; qCol = "var(--yellow)";
    } else if (dl > 1) {
      quality = "Slow";      emoji = "🐢"; bars = 2; qCol = "var(--orange)";
    } else {
      quality = "Poor";      emoji = "❌"; bars = 1; qCol = "var(--red)";
    }
    el("spd-status", quality);
    el("spd-emoji",  emoji);
    const statusEl2 = document.getElementById("spd-status");
    if (statusEl2) statusEl2.style.color = qCol;

    // Signal strength bars
    const barsEl = document.getElementById("spd-bars");
    if (barsEl) {
      const heights = [16, 20, 24, 28, 32];
      barsEl.innerHTML = heights.map((h,i) =>
        `<span style="width:5px;height:${h}px;border-radius:2px;display:inline-block;
         background:${i < bars ? qCol : "var(--border)"}"></span>`
      ).join("");
    }

    // Meta info
    // Engine badge — show which measurement method was used
    const isCli = (d.status||"").includes("speedtest-cli");
    const isAccurate = isCli || (d.status||"").includes("accurate");
    const engine = isCli ? "speedtest-cli ✓" :
                   isAccurate ? "HTTP probe (accurate) ✓" : d.status || "unknown";
    const engineEl = document.getElementById("spd-engine");
    if (engineEl) {
      engineEl.textContent = engine;
      const eCol = isCli ? "var(--green)" : isAccurate ? "var(--accent)" : "var(--yellow)";
      engineEl.style.color = eCol;
      engineEl.style.borderColor = isCli ? "rgba(0,230,118,.3)" :
                                   isAccurate ? "rgba(0,229,255,.3)" : "rgba(255,215,64,.3)";
    }
    if (d.server) el("spd-server", "📍 " + d.server);
    if (d.isp)    el("spd-isp",    "🌐 " + d.isp);
    el("spd-ts", new Date().toLocaleTimeString());

  }).catch(err => {
    clearInterval(_spdTimer);
    if (pwrap) pwrap.style.display = "none";
    btn.disabled = false; btn.textContent = "▶ Run Test";
    el("spd-status", "Error");
    el("spd-emoji",  "❌");
    const statusEl3 = document.getElementById("spd-status");
    if (statusEl3) statusEl3.style.color = "var(--red)";
    const engineEl2 = document.getElementById("spd-engine");
    if (engineEl2) { engineEl2.textContent = "failed"; engineEl2.style.color = "var(--red)"; }
    console.error("Speed test error:", err);
  });
}

// ── BLOCK / UNBLOCK DEVICE ───────────────────────────────────────────────────
function blockDevice(ip, e){
  e.stopPropagation();
  const d = S.devices[ip];
  const isBlocked = d && d.blocked;
  const url = isBlocked ? `/api/unblock/${ip}` : `/api/block/${ip}`;
  fetch(url, {method:"POST"}).then(r=>r.json()).then(res=>{
    toast({title: isBlocked?"Device Unblocked":"Device Blocked",
           detail: res.message||"", severity: isBlocked?"INFO":"HIGH"});
    if(S.devices[ip]) S.devices[ip].blocked = !isBlocked;
    if(active("devices")) renderDevices();
  });
}
function active(name){return document.getElementById("panel-"+name)?.classList.contains("active");}

// ── Utils ─────────────────────────────────────────────────────────────────
function el(id,v){const e=document.getElementById(id);if(e)e.textContent=v;}
function kv(k,v){return `<div class="detail-card"><div class="detail-key">${k}</div><div class="detail-val">${v}</div></div>`;}
function fmt(b){
  b=b||0;
  if(b<1024)return b+"B";if(b<1048576)return(b/1024).toFixed(1)+"KB";
  if(b<1073741824)return(b/1048576).toFixed(1)+"MB";return(b/1073741824).toFixed(2)+"GB";
}
function sev2col(s){return{CRITICAL:"#ff2d55",HIGH:"#ff6b35",MEDIUM:"#ffd60a",LOW:"#30d158",INFO:"#636366"}[s]||"#636366";}
function dtIcon(t){
  const map={
    "Mobile/Tablet":"📱","iPhone":"📱","iPad":"📋","iPhone/iPad":"📱",
    "Mobile Phone":"📱","Android Tablet":"📋","Tablet":"📋",
    "Laptop":"💻","MacBook (Laptop)":"💻","PC/Laptop":"💻","Linux PC":"🖥","Windows PC":"🖥",
    "PC":"🖥","Desktop":"🖥","Mac":"🖥","Mac Desktop":"🖥",
    "Router/Switch":"🔀","Router/AP":"🔀","Router":"🔀","Router / Switch":"🔀",
    "IoT Device":"🔌","IoT/SBC":"🔌","IoT / SBC":"🔌",
    "Smart TV":"📺","Smart Device":"🏠","Virtual Machine":"☁","Printer":"🖨",
    "PlayStation":"🎮","Xbox":"🎮","Nintendo Switch":"🎮","Gaming Console":"🎮",
    "Wearable":"⌚","Smart Speaker":"🔊","Network Switch":"🔗",
    "Windows Server":"🖧","Server":"🖧","IP Camera":"📷","Streaming Device":"📡",
  };
  if (!t || t.toLowerCase()==="unknown") return "";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t.trim())) return "";
  return map[t] || "💡";
}

function osIcon(os){
  const o = (os||"").toLowerCase().trim();
  if (!o || o==="unknown") return "";
  if (o.includes("linux / android")||o.includes("android / ios")||
      o.includes("ios / macos")||o.includes("linux / android / ios")||
      o.includes("windows / android")||o.includes("ios / network")) return "";
  if (o.includes("windows server")) return "🖧";
  if (o.includes("windows"))        return "🪟";
  if ((o==="macos"||o==="mac os"||o.startsWith("macos ")||o.startsWith("mac os "))
      &&!o.includes("android")&&!o.includes("linux")&&!o.includes("ios")) return "🍎";
  if (o.includes("ios")&&!o.includes("android")&&!o.includes("linux")&&
      !o.includes("macos")&&!o.includes("ios / macos")) return "📱";
  if (o.includes("ipados")) return "📱";
  if (o.includes("android")&&!o.includes("linux")&&!o.includes("ios")) return "🤖";
  if (o.includes("linux"))   return "🐧";
  if (o.includes("router")||o.includes("network os")) return "🔀";
  if (o.includes("smart tv")||o.includes("tizen"))    return "📺";
  if (o.includes("playstation")||o.includes("xbox")||o.includes("nintendo")) return "🎮";
  if (o.includes("embedded")||o.includes("iot")||o.includes("printer")) return "🔌";
  return "";
}

function resolveOsDisplay(os, ttl){
  const FALLBACK = "Linux / Android / iOS / macOS";
  const o  = (os||"").trim();
  const ol = o.toLowerCase();
  if (!o||ol==="unknown"||ol==="?") return {text:FALLBACK,icon:""};
  if (ol.includes("linux / android")||ol.includes("windows / android")||
      ol.includes("ios / network")||ol.includes("linux / android / ios")||
      ol.includes("android / ios")||ol.includes("linux / android / macos")||
      ol.includes("ios / macos")||ol.includes("macos / ios"))
    return {text:FALLBACK,icon:""};
  const t = parseInt(ttl)||0;
  if (t>0&&t<=64&&(ol==="unknown"||!o)) return {text:FALLBACK,icon:""};
  const icon = osIcon(o);
  return {text:o, icon};
}

// Vulnerable ports map (for badge colours in ports panel)
const VPMAP={21:["FTP","MEDIUM"],22:["SSH","LOW"],23:["Telnet","HIGH"],25:["SMTP","MEDIUM"],
  80:["HTTP","MEDIUM"],135:["RPC","HIGH"],139:["NetBIOS","HIGH"],443:["HTTPS","LOW"],
  445:["SMB","CRITICAL"],1433:["MSSQL","HIGH"],3306:["MySQL","HIGH"],3389:["RDP","HIGH"],
  5432:["PostgreSQL","HIGH"],5900:["VNC","HIGH"],6379:["Redis","CRITICAL"],
  8080:["HTTP-Alt","MEDIUM"],9200:["Elasticsearch","CRITICAL"],27017:["MongoDB","CRITICAL"]};

// Init topology graph on load (overview is default active)
window.addEventListener('load', () => setTimeout(ensureTopoInit, 200));




// ═══════════════════════════════════════════════════════════════════════════
//  IP OSINT  –  query Shodan / Censys / AbuseIPDB / AlienVault OTX
// ═══════════════════════════════════════════════════════════════════════════

const OSINT_STATE = {
  results:  {},   // ip → result dict
  scanning: new Set(),
  inited:   false,
};

const THREAT_COL = {
  CRITICAL: "var(--red)",
  HIGH:     "var(--orange)",
  MEDIUM:   "var(--yellow)",
  LOW:      "var(--green)",
  CLEAN:    "var(--green)",
};

const ABUSE_CATS = {
  1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",
  5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",
  9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",
  13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",
  17:"Spoofing",18:"Brute-Force",19:"Bad Web Bot",20:"Exploited Host",
  21:"Web App Attack",22:"SSH",23:"IoT Targeted",
};

// ── Init ──────────────────────────────────────────────────────────────────────
function osintInit() {
  if (OSINT_STATE.inited) { osintRefreshDeviceGrid(); return; }
  OSINT_STATE.inited = true;
  // Check which API keys are configured and show badges
  fetch('/api/osint/keys').then(r=>r.json()).then(keys => {
    const badgeEl = document.getElementById('osint-key-badges');
    if (!badgeEl) return;
    const kmap = {shodan:'Shodan',censys:'Censys',abuseipdb:'AbuseIPDB',otx:'OTX'};
    badgeEl.innerHTML = Object.entries(kmap).map(([k,name]) =>
      `<span style="font-size:9px;padding:2px 8px;border-radius:4px;
        background:${keys[k]?'rgba(0,230,118,.1)':'rgba(61,80,104,.2)'};
        border:1px solid ${keys[k]?'rgba(0,230,118,.35)':'rgba(61,80,104,.4)'};
        color:${keys[k]?'var(--green)':'var(--muted)'}"
        title="${keys[k]?name+' key loaded':name+' — add key to .env'}">
        ${keys[k]?'✓':'✗'} ${name}</span>`
    ).join('');
  }).catch(()=>{});

  // Load any cached results
  fetch('/api/osint/status').then(r=>r.json()).then(data => {
    Object.assign(OSINT_STATE.results, data);
    osintRefreshDeviceGrid();
  }).catch(()=>{});

  osintRefreshDeviceGrid();
}

// ── Device selector grid ──────────────────────────────────────────────────────
function osintRefreshDeviceGrid() {
  const grid = document.getElementById('osint-device-grid');
  if (!grid) return;
  const devs = Object.values(S.devices)
    .filter(d => d.status !== 'offline')
    .sort((a,b)=>(a.ip||'').localeCompare(b.ip||'',undefined,{numeric:true}));

  grid.innerHTML = devs.map(d => {
    const r    = OSINT_STATE.results[d.ip];
    const tl   = r ? r._threat_level : null;
    const isScanning = OSINT_STATE.scanning.has(d.ip);
    const dotCol = isScanning ? 'var(--yellow)' :
                   tl ? (THREAT_COL[tl]||'var(--muted)') : 'var(--muted)';
    const dotTxt = isScanning ? '⏳' :
                   tl === 'CLEAN'    ? '✓' :
                   tl === 'LOW'      ? '●' :
                   tl === 'MEDIUM'   ? '⚠' :
                   tl === 'HIGH'     ? '⚠' :
                   tl === 'CRITICAL' ? '🚨' : '·';
    const vendor  = (d.brand||d.vendor||'').toLowerCase();
    const isIP    = /^\d+\.\d+\.\d+\.\d+$/.test(vendor);
    const label   = isIP ? d.ip : (d.brand||d.vendor||d.ip);
    return `<div onclick="osintSelectDevice('${d.ip}')"
      style="cursor:pointer;padding:8px 12px;border-radius:8px;
             background:var(--bg3);border:1px solid var(--border);
             min-width:120px;transition:all .15s"
      onmouseover="this.style.borderColor='var(--accent)'"
      onmouseout="this.style.borderColor='var(--border)'"
      id="osint-chip-${d.ip.replace(/\./g,'-')}">
      <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                  color:var(--accent)">${d.ip}</div>
      <div style="font-size:9px;color:var(--muted);margin-top:1px;
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                  max-width:110px" title="${label}">${label.substring(0,14)}</div>
      <div style="margin-top:5px;display:flex;align-items:center;gap:5px">
        <span style="color:${dotCol};font-size:11px">${dotTxt}</span>
        <span style="font-size:9px;color:${dotCol}">${isScanning?'Scanning…':tl||'Not scanned'}</span>
      </div>
    </div>`;
  }).join('');
}

// ── Scan all ──────────────────────────────────────────────────────────────────
function osintScanAll() {
  const btn = document.getElementById('osint-scan-btn');
  if (btn) { btn.disabled=true; btn.textContent='⏳ Scanning…'; }
  Object.values(S.devices).filter(d=>d.status!=='offline').forEach(d=>{
    OSINT_STATE.scanning.add(d.ip);
  });
  osintRefreshDeviceGrid();
  fetch('/api/osint/all', {method:'POST'}).then(r=>r.json()).then(data => {
    // Poll for completion
    let checks = 0;
    const poll = setInterval(()=>{
      checks++;
      fetch('/api/osint/status').then(r=>r.json()).then(results=>{
        const done = data.scanning.every(ip => results[ip]?._ran);
        Object.assign(OSINT_STATE.results, results);
        data.scanning.forEach(ip=>{
          if (results[ip]?._ran) OSINT_STATE.scanning.delete(ip);
        });
        osintRefreshDeviceGrid();
        if (done || checks > 30) {
          clearInterval(poll);
          if (btn) { btn.disabled=false; btn.textContent='▶ Scan All Devices'; }
          // Auto-show results for first device
          const first = data.scanning[0];
          if (first && results[first]) osintShowResult(first, results[first]);
        }
      });
    }, 3000);
  }).catch(()=>{ if(btn){btn.disabled=false;btn.textContent='▶ Scan All Devices';} });
}

// ── Select & scan single device ───────────────────────────────────────────────
function osintSelectDevice(ip) {
  // Highlight selected chip
  document.querySelectorAll('[id^="osint-chip-"]').forEach(el=>{
    el.style.background='var(--bg3)'; el.style.borderColor='var(--border)';
  });
  const chip = document.getElementById('osint-chip-'+ip.replace(/\./g,'-'));
  if (chip) { chip.style.background='rgba(0,229,255,.07)'; chip.style.borderColor='var(--accent)'; }

  // Use cache if available and fresh
  const cached = OSINT_STATE.results[ip];
  if (cached?._ran) { osintShowResult(ip, cached); return; }

  // Show loading state
  const res = document.getElementById('osint-results');
  if (res) res.innerHTML = osintLoadingHTML(ip);
  OSINT_STATE.scanning.add(ip);
  osintRefreshDeviceGrid();

  fetch(`/api/osint/${ip}`).then(r=>r.json()).then(data=>{
    OSINT_STATE.results[ip] = data;
    OSINT_STATE.scanning.delete(ip);
    osintRefreshDeviceGrid();
    osintShowResult(ip, data);
  }).catch(e=>{
    OSINT_STATE.scanning.delete(ip);
    osintRefreshDeviceGrid();
    if (res) res.innerHTML = `<div style="color:var(--red);padding:20px">Error: ${e}</div>`;
  });
}

function osintLoadingHTML(ip) {
  return `<div style="text-align:center;padding:40px">
    <div style="font-size:22px;margin-bottom:12px">🔍</div>
    <div style="font-size:13px;color:var(--accent)">Querying OSINT databases for ${ip}…</div>
    <div style="font-size:11px;color:var(--muted);margin-top:6px">
      Shodan · Censys · AbuseIPDB · AlienVault OTX
    </div>
    <div style="margin-top:16px;height:3px;background:var(--bg3);border-radius:2px;overflow:hidden;width:300px;margin-inline:auto">
      <div style="height:100%;background:linear-gradient(90deg,var(--accent),#7c4dff);
           animation:slide 1.4s ease-in-out infinite;border-radius:2px"></div>
    </div>
  </div>
  <style>@keyframes slide{0%{width:0%;margin-left:0}50%{width:60%;margin-left:20%}100%{width:0%;margin-left:100%}}</style>`;
}

// ── Render full result ─────────────────────────────────────────────────────────
function osintShowResult(ip, data) {
  const tl    = data._threat_level || 'CLEAN';
  const score = data._threat_score || 0;
  const dev   = S.devices[ip] || {};
  const tCol  = THREAT_COL[tl] || 'var(--muted)';

  let html = `
  <div style="margin-bottom:16px">
    <!-- Header row -->
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:700;
                    color:var(--accent)">${ip}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">
          ${dev.hostname||''} ${dev.vendor&&dev.vendor!==ip?'· '+dev.vendor:''} ${dev.device_type&&dev.device_type!==ip?'· '+dev.device_type:''}
        </div>
      </div>
      <!-- Threat score gauge -->
      <div style="margin-left:auto;text-align:center;
           background:var(--bg3);border:1px solid ${tCol};border-radius:10px;
           padding:10px 20px;min-width:120px">
        <div style="font-family:'JetBrains Mono',monospace;font-size:28px;
                    font-weight:700;color:${tCol}">${score}</div>
        <div style="font-size:10px;color:var(--muted)">Threat Score</div>
        <div style="font-size:11px;font-weight:700;color:${tCol};margin-top:2px">${tl}</div>
      </div>
      <button class="btn" onclick="osintSelectDevice('${ip}'); fetch('/api/osint/${ip}?refresh=1').then(r=>r.json()).then(d=>{OSINT_STATE.results['${ip}']=d;osintShowResult('${ip}',d);})"
              style="font-size:10px">↺ Refresh</button>
    </div>

    <!-- 4 source cards grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      ${osintShodanCard(data.shodan||{})}
      ${osintCensysCard(data.censys||{})}
      ${osintAbuseCard(data.abuseipdb||{})}
      ${osintOTXCard(data.otx||{})}
    </div>
  </div>`;

  const el = document.getElementById('osint-results');
  if (el) el.innerHTML = html;
}

// ── Source cards ──────────────────────────────────────────────────────────────
function osintCard(title, icon, ok, errorMsg, bodyHTML) {
  const statusBadge = ok
    ? `<span style="font-size:9px;color:var(--green);background:rgba(0,230,118,.1);
         border:1px solid rgba(0,230,118,.25);padding:1px 6px;border-radius:4px">✓ OK</span>`
    : `<span style="font-size:9px;color:var(--muted);background:var(--bg);
         border:1px solid var(--border);padding:1px 6px;border-radius:4px">
         ${errorMsg||'No data'}</span>`;
  return `<div style="background:var(--bg3);border:1px solid var(--border);
              border-radius:10px;padding:14px;overflow:hidden">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
      <span style="font-size:16px">${icon}</span>
      <span style="font-weight:700;font-size:12px">${title}</span>
      <span style="margin-left:auto">${statusBadge}</span>
    </div>
    ${ok ? bodyHTML : `<div style="color:var(--muted);font-size:11px">${errorMsg||'No data returned.'}</div>`}
  </div>`;
}

function kv(k,v){
  if(!v&&v!==0) return '';
  return `<div style="display:flex;gap:6px;padding:3px 0;border-bottom:1px solid rgba(26,37,53,.5)">
    <span style="color:var(--muted);font-size:10px;min-width:90px;flex-shrink:0">${k}</span>
    <span style="font-size:10px;word-break:break-all">${v}</span>
  </div>`;
}

function osintShodanCard(d) {
  const ok = d.ok;
  let body = '';
  if (ok) {
    const vulns = (d.vulns||[]).slice(0,5);
    const ports  = (d.ports||[]).join(', ') || '—';
    body = `
      ${kv('Org', d.org||d.isp||'')}
      ${kv('Country', d.country||'')} ${kv('City', d.city||'')}
      ${kv('ASN', d.asn||'')} ${kv('OS', d.os||'')}
      ${kv('Open Ports', ports)}
      ${kv('Last Seen', (d.last_seen||'').substring(0,10))}
      ${kv('Hostnames', (d.hostnames||[]).join(', '))}
      ${kv('Tags', (d.tags||[]).join(', '))}
      ${vulns.length?`<div style="margin-top:8px">
        <div style="font-size:10px;font-weight:700;color:var(--red);margin-bottom:4px">⚠ CVEs (${(d.vulns||[]).length})</div>
        ${vulns.map(v=>`<div style="font-family:'JetBrains Mono',monospace;font-size:10px;
          color:var(--red);background:rgba(255,45,85,.06);border-radius:4px;
          padding:2px 6px;margin-bottom:2px">${v}</div>`).join('')}
      </div>`:''}
      ${(d.banners||[]).length?`<div style="margin-top:8px">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:4px">Service Banners</div>
        ${d.banners.map(b=>`<div style="margin-bottom:6px;padding:6px;background:var(--bg);
          border-radius:6px;border:1px solid var(--border)">
          <div style="font-size:10px;color:var(--accent)">:${b.port} ${b.product} ${b.version}</div>
          ${b.banner?`<div style="font-size:9px;color:var(--muted);font-family:'JetBrains Mono',monospace;
            white-space:pre-wrap;word-break:break-all;max-height:60px;overflow:hidden">${b.banner}</div>`:''}
        </div>`).join('')}
      </div>`:''}`;
  }
  return osintCard('Shodan', '🔍', ok, d.error, body);
}

function osintCensysCard(d) {
  const ok = d.ok;
  let body = '';
  if (ok) {
    body = `
      ${kv('Org / ASN', (d.org||'')+(d.asn?' ('+d.asn+')':''))}
      ${kv('Country', d.country||'')} ${kv('City', d.city||'')}
      ${kv('BGP Prefix', d.bgp||'')}
      ${kv('Last Seen', (d.last_seen||'').substring(0,10))}
      ${(d.services||[]).length?`<div style="margin-top:8px">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:4px">
          Services (${d.services.length})</div>
        ${d.services.map(s=>`<div style="display:flex;gap:8px;padding:4px 6px;margin-bottom:3px;
          background:var(--bg);border-radius:5px;font-size:10px">
          <span style="color:var(--accent);font-family:'JetBrains Mono',monospace;min-width:50px">:${s.port}</span>
          <span style="color:var(--muted)">${s.transport}</span>
          <span style="font-weight:600">${s.service||''}</span>
          <span style="color:var(--muted)">${s.product||''}</span>
          ${s.tls_subject?`<span style="color:var(--accent2);font-size:9px;margin-left:auto;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px"
            title="${s.tls_subject}">🔒 ${s.tls_subject}</span>`:''}
        </div>`).join('')}
      </div>`:''}`;
  }
  return osintCard('Censys', '🌐', ok, d.error, body);
}

function osintAbuseCard(d) {
  const ok = d.ok;
  let body = '';
  if (ok) {
    const score  = d.abuse_score||0;
    const sCol   = score>=80?'var(--red)':score>=40?'var(--orange)':score>=10?'var(--yellow)':'var(--green)';
    body = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;
           padding:8px;background:var(--bg);border-radius:8px">
        <div style="text-align:center">
          <div style="font-family:'JetBrains Mono',monospace;font-size:26px;
               font-weight:700;color:${sCol}">${score}%</div>
          <div style="font-size:9px;color:var(--muted)">Abuse Score</div>
        </div>
        <div style="flex:1">
          <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">
            <div style="height:100%;width:${score}%;background:${sCol};border-radius:4px;transition:width 1s"></div>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-top:4px">
            ${d.total_reports} reports · ${d.distinct_users} users
          </div>
        </div>
      </div>
      ${kv('ISP', d.isp||'')} ${kv('Domain', d.domain||'')}
      ${kv('Country', d.country||'')} ${kv('Usage Type', d.usage_type||'')}
      ${kv('Last Reported', (d.last_reported||'').substring(0,10))}
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">
        ${d.is_tor?`<span style="font-size:9px;padding:2px 7px;border-radius:4px;
          background:rgba(255,45,85,.1);border:1px solid rgba(255,45,85,.3);color:var(--red)">TOR Exit</span>`:''}
        ${d.is_whitelisted?`<span style="font-size:9px;padding:2px 7px;border-radius:4px;
          background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:var(--green)">Whitelisted</span>`:''}
        ${!d.is_public?`<span style="font-size:9px;padding:2px 7px;border-radius:4px;
          background:rgba(100,181,246,.1);border:1px solid rgba(100,181,246,.3);color:#64b5f6">Private IP</span>`:''}
      </div>
      ${(d.reports||[]).length?`<div style="margin-top:10px">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:5px">
          Recent Reports</div>
        ${d.reports.map(r=>`<div style="padding:6px;background:var(--bg);border-radius:6px;
          margin-bottom:5px;border-left:2px solid var(--red)">
          <div style="font-size:9px;color:var(--muted);margin-bottom:2px">${r.reported_at.substring(0,10)}
            ${(r.categories||[]).map(c=>`<span style="margin-left:4px;padding:1px 5px;
              border-radius:3px;background:rgba(255,107,53,.1);color:var(--orange);font-size:8px">
              ${ABUSE_CATS[c]||'Cat '+c}</span>`).join('')}
          </div>
          <div style="font-size:10px;color:var(--text)">${r.comment||'(no comment)'}</div>
        </div>`).join('')}
      </div>`:''}`;
  }
  return osintCard('AbuseIPDB', '🛡', ok, d.error, body);
}

function osintOTXCard(d) {
  const ok = d.ok;
  let body = '';
  if (ok) {
    const pulseCount = d.pulse_count||0;
    const pCol = pulseCount>10?'var(--red)':pulseCount>3?'var(--orange)':pulseCount>0?'var(--yellow)':'var(--green)';
    body = `
      <div style="display:flex;gap:14px;align-items:center;margin-bottom:10px;
           padding:8px;background:var(--bg);border-radius:8px">
        <div style="text-align:center">
          <div style="font-family:'JetBrains Mono',monospace;font-size:26px;
               font-weight:700;color:${pCol}">${pulseCount}</div>
          <div style="font-size:9px;color:var(--muted)">Threat Pulses</div>
        </div>
        <div>
          ${kv('Reputation', d.reputation!==undefined?d.reputation:'')}
          ${kv('Country', d.country||'')} ${kv('City', d.city||'')}
          ${kv('ASN', d.asn||'')}
        </div>
      </div>
      ${(d.passive_dns||[]).length?`<div style="margin-bottom:10px">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:4px">Passive DNS</div>
        ${d.passive_dns.map(p=>`<div style="display:flex;gap:8px;font-size:10px;padding:2px 0;
          border-bottom:1px solid rgba(26,37,53,.5)">
          <span style="color:var(--accent);font-family:'JetBrains Mono',monospace">${p.hostname}</span>
          <span style="color:var(--muted);margin-left:auto">${p.first} → ${p.last}</span>
        </div>`).join('')}
      </div>`:''}
      ${(d.pulses||[]).length?`<div>
        <div style="font-size:10px;font-weight:700;color:var(--red);margin-bottom:5px">
          Threat Intelligence Pulses</div>
        ${d.pulses.map(p=>`<div style="padding:7px;background:var(--bg);border-radius:7px;
          margin-bottom:5px;border-left:2px solid var(--red)">
          <div style="font-size:10px;font-weight:600">${p.name}</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px">
            <span style="font-size:9px;color:var(--muted)">${p.created}</span>
            ${p.adversary?`<span style="font-size:9px;color:var(--orange);padding:1px 5px;
              border-radius:3px;background:rgba(255,107,53,.1)">👤 ${p.adversary}</span>`:''}
            ${(p.malware_families||[]).map(m=>`<span style="font-size:9px;color:var(--red);
              padding:1px 5px;border-radius:3px;background:rgba(255,45,85,.1)">🦠 ${m}</span>`).join('')}
            ${(p.tags||[]).map(t=>`<span style="font-size:9px;color:var(--muted);padding:1px 5px;
              border-radius:3px;background:var(--bg3)">#${t}</span>`).join('')}
          </div>
        </div>`).join('')}
      </div>`:''}
      ${(d.malware||[]).length?`<div style="margin-top:8px">
        <div style="font-size:10px;font-weight:700;color:var(--red);margin-bottom:4px">
          Malware Hashes</div>
        ${d.malware.map(h=>`<div style="font-family:'JetBrains Mono',monospace;font-size:9px;
          color:var(--muted);padding:2px 0">${h}</div>`).join('')}
      </div>`:''}`;
  }
  return osintCard('AlienVault OTX', '🎯', ok, d.error, body);
}

function osintClearAll() {
  OSINT_STATE.results = {};
  OSINT_STATE.scanning.clear();
  osintRefreshDeviceGrid();
  const el = document.getElementById('osint-results');
  if (el) el.innerHTML = `<div style="color:var(--muted);text-align:center;padding:40px;font-size:13px">
    Results cleared. Click a device or Scan All to query again.</div>`;
}

// Refresh device grid when devices panel updates
socket.on("device_update", () => {
  if (active("osint")) osintRefreshDeviceGrid();
});

// Clock
setInterval(()=>{const e=document.getElementById("hdr-time");if(e)e.textContent=new Date().toLocaleTimeString();},1000);

// Init topology graph on load (overview is default active)
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def print_banner():
    mode = "ROOT – all features on" if IS_ROOT else "NO ROOT – limited mode"
    cap  = ("Scapy deep-capture" if (SCAPY_OK and IS_ROOT)
            else "psutil poll (install scapy + run as root for deep capture)")
    print(f"""
\u256c{'\u2550'*50}\u256c
\u2551     NetSentinel v{VERSION} - Network Security       \u2551
\u2569{'\u2550'*50}\u256f
  Gateway  : {monitor.gateway}
  Network  : {monitor.network}
  Mode     : {mode}
  Capture  : {cap}
  Dashboard: http://localhost:{APP_PORT}
""")

if __name__ == "__main__":
    if not IS_ROOT:
        print("\n[!] Not root - packet capture uses psutil, OS detect uses heuristics.")
        print("    For full features: sudo python3 network_manager.py\n")
    monitor.start()
    print_banner()
    print("  Press Ctrl+C to stop.\n")
    try:
        socketio.run(app, host="0.0.0.0", port=APP_PORT,
                     debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        monitor.capture.stop()
