# CyberGun: Advanced Real-Time Threat Mitigation Suite

![CyberGun Logo](datasets/icons/logo.svg)

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green)](https://pypi.org/project/PyQt5/)
[![LightGBM](https://img.shields.io/badge/ML-LightGBM-orange)](https://lightgbm.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)](https://www.microsoft.com/windows)

> CyberGun is a high-performance, intelligent threat detection and mitigation suite designed for proactive security. It moves beyond traditional signature-based scanning by integrating a **multi-layered defense system** that combines static analysis, machine learning-based behavioral monitoring, and real-time network analysis.

---

## Features

### Multi-Layered Static Scanning
- **Hash Detection** — Instantly identifies known malware via SHA256 hash matching against a live-updated threat database (Abuse.ch MalwareBazaar)
- **YARA Engine** — Employs the industry-standard [signature-base](https://github.com/Neo23x0/signature-base) ruleset to detect tens of thousands of malware families and threat actor patterns
- **Byte Signatures** — Scans for specific, high-confidence malicious byte sequences
- **Machine Learning Models** — Pre-trained LightGBM models classify PE, ELF, PDF, and APK files as benign or malicious — enabling detection of novel and unknown threats

### Dynamic Real-Time Monitoring
- **Behavioral Analysis** — ML-powered engine monitors system-wide process activity to detect suspicious behavioral patterns
- **Live Event Feed** — Dashboard displays critical system events in real-time (new process creation, USB device connections)
- **Real-Time File Guard** — Actively monitors the filesystem for new or modified files and triggers instant on-demand scans

### Professional Network Dashboard
- **Live Traffic Graph** — Real-time graphical plot of network upload and download speeds via PyQtGraph
- **Threat Analysis** — Sniffs network traffic and checks connections against a live-updated IP blacklist (FireHOL)
- **Threat Logging** — All confirmed network threats logged in a consolidated table

### Automated Threat Response
- **Process Termination** — Automatically finds and terminates the running process associated with a high-severity threat
- **File Quarantine** — Securely moves malicious files to an isolated quarantine directory

### Live Threat Intelligence
- One-click or auto-on-startup system to download the latest threat intelligence:
  - Malware hashes from **Abuse.ch MalwareBazaar**
  - IP blacklists from **FireHOL Level 1**
  - Latest **YARA rules** from signature-base

---

## Architecture

CyberGun is built on a **decoupled, signal-driven architecture** using PyQt5:

```
CyberGun/
├── main.py                  # Application entry point
├── SignalBus.py             # Central Qt messaging system (async inter-module comms)
├── core/                    # Core engine orchestrators
│   ├── StaticEngine.py      # Manages all file-based static scanners
│   ├── DynamicEngine.py     # Manages real-time monitors (System, Behavior, USB)
│   └── NetworkEngine.py     # Manages NetworkSniffer and NetworkAnalyzer
├── static_scanners/         # Hash, YARA, ML, byte-signature detection modules
├── dynamic_scanners/        # Behavioral analysis and system monitoring
├── network_scanners/        # Packet sniffing and IP threat correlation
├── gui/                     # PyQt5 dashboard widgets
├── datasets/                # Threat intelligence data (downloaded at runtime)
│   ├── hashes/              # Malware hash databases (auto-downloaded)
│   ├── yara_rules/          # YARA rulesets (clone separately — see setup)
│   ├── network/             # IP blacklists (FireHOL)
│   └── signatures/          # Byte signature CSV rules
├── models/                  # Trained ML models (LightGBM / SVM)
└── requirements.txt
```

### ML Feature Set (55 Volatility-Based Features)
The behavioral ML model uses **55 memory forensics features** extracted from Volatility plugins:
`pslist`, `dlllist`, `handles`, `ldrmodules`, `malfind`, `psxview`, `modules`, `svcscan`, `callbacks`

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Python** | 3.9+ recommended |
| **Git** | Required for cloning and YARA ruleset updates |
| **Npcap** (Windows) | Required by Scapy for live network sniffing. Install from [npcap.com](https://npcap.com) — check **"WinPcap API-compatible Mode"** during install |

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/hckr-zahid/CyberGun.git
cd CyberGun
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Download YARA Ruleset
The YARA engine requires the [signature-base](https://github.com/Neo23x0/signature-base) ruleset:
```bash
cd datasets/yara_rules
git clone https://github.com/Neo23x0/signature-base.git signature-base-master
cd ../..
```

### 5. Download Threat Intelligence Databases
On first launch, CyberGun will automatically download:
- Malware hash databases from Abuse.ch
- IP blacklists from FireHOL

Or trigger manually from the dashboard using the **"Update Threat Intel"** button.

---

## Running the Application

```bash
python main.py
```

The animated boot splash will appear, perform initial database updates and a system scan, then launch the main dashboard where **real-time protection becomes active**.

---

## Technology Stack

| Category | Tools |
|---|---|
| GUI Framework | PyQt5, PyQtGraph |
| Machine Learning | LightGBM, Scikit-learn, Joblib |
| Static Analysis | YARA-Python, custom byte signatures |
| Network Analysis | Scapy |
| System Monitoring | psutil, pywin32 |
| Threat Intelligence | Abuse.ch MalwareBazaar, FireHOL |

---

## Author

**Zahid Ullah**
Cybersecurity Analyst | SOC & Threat Detection | DFIR | CEH | CHFI | (ISC)² CC

- GitHub: [@hckr-zahid](https://github.com/hckr-zahid)
- LinkedIn: [linkedin.com/in/hckr-zahid](https://linkedin.com/in/hckr-zahid)
- Email: hckr.badguy@gmail.com

---

## License

This project is licensed under the [MIT License](LICENSE).

> ⚠️ **Disclaimer:** CyberGun is developed for **educational and defensive security purposes only**. The author is not responsible for any misuse of this tool.
