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
⚙️ Installation
Clone the repository
git clone https://github.com/Wiz-gkr/LinuxSentry.git
Move into the project directory
cd LinuxSentry
Check available options
python3 audit.py --help
🚀 Usage
Run system information scan
python3 audit.py --system
Run network enumeration
python3 audit.py --network
Check listening ports
python3 audit.py --ports
Run permission security checks
python3 audit.py --permissions
Run all scans
python3 audit.py --all
Save results to a report
python3 audit.py --all --output report.txt
🔎 Security Checks
🔐 SUID Binary Enumeration

LinuxSentry searches for files with the SUID permission bit enabled.

SUID binaries can execute with the privileges of the file owner. Unusual or misconfigured SUID binaries may require further security review.

📂 World-Writable Files

The tool identifies files and directories that can be modified by all users.

Some locations are normally world-writable, such as:

/tmp
/var/tmp
/dev/shm

However, world-writable files in unusual or sensitive locations may require investigation.

👤 Orphaned Files

LinuxSentry checks for files that no longer have a valid user or group owner.

These files can appear due to deleted accounts, incorrect permissions, or system misconfiguration.

⚠️ Severity Levels

LinuxSentry classifies findings into three basic severity levels:

Severity	Description
🟢 LOW	Informational finding or known configuration that may require review
🟡 MEDIUM	Potentially risky configuration requiring further investigation
🔴 HIGH	Configuration or finding that may represent a significant security concern

Severity classification is based on simple built-in rules and is intended to assist prioritization.

📊 Security Scoring

LinuxSentry starts with a security score of:

100 / 100

Findings reduce the score:

Severity	Score Impact
🟢 LOW	-2
🟡 MEDIUM	-5
🔴 HIGH	-10

The final score determines the overall risk level:

Score	Risk Level
80–100	🟢 LOW
50–79	🟡 MEDIUM
0–49	🔴 HIGH

⚠️ The security score is a simple prioritization mechanism and should not be considered a complete security assessment.

🖥️ Example Output
============================================================
          LinuxSentry - Security Audit Tool
============================================================

[INFO] Running permission security checks...

[+] SUID BINARY ENUMERATION
------------------------------------------------------------

[+] Found SUID binaries:

  └── /usr/bin/passwd
  └── /usr/bin/su

[+] SECURITY FINDINGS
------------------------------------------------------------

[LOW] Known SUID binary: /usr/bin/passwd
[LOW] Known SUID binary: /usr/bin/su

[MEDIUM] Review unusual SUID binary: /some/path

============================================================
          SECURITY FINDINGS SUMMARY
============================================================

LOW     : 8
MEDIUM  : 3
HIGH    : 0

============================================================
              SECURITY SCORE
============================================================

Score      : 69/100
Risk Level : MEDIUM

[+] OVERALL RISK LEVEL

[MEDIUM] Risk Level: MEDIUM (69/100)

============================================================
             Scan Completed
============================================================

Scan Duration: 4.27 seconds

[+] All selected scans completed.

## 📸 Screenshot

<img width="1920" height="1057" alt="LinuxSentry Screenshot" src="https://github.com/user-attachments/assets/34522363-fd2d-470e-a591-4fcf6def5884" />

🧠 How It Works
                    Linux System
                         │
                         ▼
              ┌─────────────────────┐
              │     LinuxSentry     │
              └─────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   System Scan      Network Scan    Permission Scan
                                         │
                           ┌─────────────┼─────────────┐
                           ▼             ▼             ▼
                         SUID      World-Writable    Orphaned
                                         │
                                         ▼
                                Security Analyzer
                                         │
                                         ▼
                              LOW / MEDIUM / HIGH
                                         │
                                         ▼
                                 Security Score
                                         │
                                         ▼
                                    Risk Level
🛠️ Built With

Python 3
argparse
subprocess
datetime
time
Linux system utilities
Python standard library
No external Python dependencies are currently required.

📄 Report Generation
LinuxSentry can export scan results into a text file:
python3 audit.py --all --output report.txt

The report includes:
Scan generation time
Scan duration
System and network results
Permission findings
Security findings summary
Security score
Overall risk level

🎯 Project Goals

LinuxSentry was built as a hands-on cybersecurity and Python project focused on:
Linux enumeration
Security auditing
Permission analysis
Identifying common misconfigurations
Writing modular Python code
Building command-line security tools

🚧 Future Improvements

 JSON report export
 HTML security reports
 Configuration file support
 Custom severity rules
 Cron job checks
 Docker/container detection
 Additional privilege escalation checks
 Automated remediation suggestions
 Improved security scoring algorithm
 Interactive CLI mode

⚠️ Disclaimer

LinuxSentry is intended for educational purposes and authorized security auditing only.
Always ensure that you have permission before running security checks on systems you do not own or administer.
The results generated by this tool should be reviewed manually and should not be considered a replacement for a professional security assessment.

👨‍💻 Author
Goutham Krishna R
Cybersecurity Enthusiast • Linux • Python • Security Research
🔗 [LinkedIn](https://www.linkedin.com/in/gouthamkrishnar/)

