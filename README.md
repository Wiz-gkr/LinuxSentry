# 🛡️ LinuxSentry

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Linux%20Security-red?style=for-the-badge)

> 🛡️ A lightweight Python-based tool for Linux security auditing, enumeration, and basic misconfiguration detection.

LinuxSentry is a modular Python tool designed to automate basic Linux security checks and help identify potentially risky system configurations.

It performs system and network enumeration, detects listening ports, audits SUID binaries, identifies world-writable files, checks for orphaned files, and provides a simple security score with an overall risk level.

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
- ⏱️ Scan duration tracking
- ⚡ Modular Python architecture
- 🖥️ Command-line interface with `argparse`

---

## 📁 Project Structure

```text
LinuxSentry/
│
├── audit.py
├── README.md
├── .gitignore
│
└── modules/
    ├── __init__.py
    ├── analyzer.py
    ├── network.py
    ├── permissions.py
    ├── system.py
    └── ui.py
