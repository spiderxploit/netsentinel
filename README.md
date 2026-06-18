<div align="center">

```
███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**v3 · Real-Time Network Intelligence Dashboard**

![Python](https://img.shields.io/badge/Python-3.8%2B-cyan?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet?style=flat-square)

</div>

---

## Dashboard

![NetSentinel Dashboard](dashboard.png)

---

## Features

- 📡 **Live Network Map** — visualize nodes, edges, TCP/UDP/ICMP traffic in real time  
- 🔍 **Device Discovery** — auto-scan and fingerprint devices on your subnet  
- 🚨 **Alert Engine** — severity-classified alerts with live counts  
- 🛡️ **Vulnerability Tracker** — CVE-aware vuln detection per host  
- 🌐 **Internet Speed & Latency** — HTTP probe with download, upload, ping & jitter  
- 🔓 **Open Port Scanner** — per-device port enumeration  
- 📊 **Bandwidth Monitor** — real-time packet rate graphs  
- 🕵️ **IP OSINT** — enriched intel lookups on any IP  

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/spiderxploit/netsentinel.git
```

```bash
cd netsentinel
```

### 2. Activate the virtual environment

**macOS / Linux**
```bash
source venv/bin/activate
```

**Windows**
```bash
source venv/Scripts/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

**macOS / Linux**
```bash
python3 netsentinel.py
```

**Windows**
```bash
python netsentinel.py
```

---

## Requirements

- Python 3.8+
- Virtual environment (`venv`) included in the repo
- Root / Administrator privileges recommended for packet capture

---

## Project Structure

```
netsentinel/
├── netsentinel.py       # Main entry point
├── requirements.txt     # Python dependencies
├── dashboard.png        # GUI preview
└── venv/                # Virtual environment
```

---

<div align="center">

Built by [@spiderxploit](https://github.com/spiderxploit) · Dark by design 🕷️

</div>
