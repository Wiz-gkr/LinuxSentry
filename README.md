# 🛡️ LinuxSentry

### Lightweight Linux Security Auditing & Enumeration Tool

LinuxSentry is a Python-based Linux security auditing tool designed to automate basic system enumeration and identify potentially risky configurations.

It performs checks for system information, network configuration, listening ports, SUID binaries, world-writable files, and orphaned files.

---

## ✨ Features

- 🖥️ System information enumeration
- 🌐 Network interface enumeration
- 🔌 Listening port detection
- 🔐 SUID binary enumeration
- 📂 World-writable file detection
- 👤 Orphaned file and group detection
- ⚠️ Security finding classification
- 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH severity levels
- 📊 Security score out of 100
- 🚨 Overall risk level assessment
- 🎨 Colored terminal output
- 📄 Export scan results to a text report
- ⚡ Modular Python architecture
- ⏱️ Scan duration tracking

---

## 📁 Project Structure

```text
LinuxSentry/
│
├── audit.py
├── README.md
│
└── modules/
    ├── __init__.py
    ├── system.py
    ├── network.py
    ├── permissions.py
    ├── analyzer.py
    └── ui.py
