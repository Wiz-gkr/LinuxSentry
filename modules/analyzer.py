KNOWN_SYSTEM_SUID = [
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec"
]

NORMAL_WORLD_WRITABLE = [
    "/tmp",
    "/var/tmp",
    "/dev/shm"
]


def analyze_suid(files):
    findings = []

    for file in files:
        if file in KNOWN_SYSTEM_SUID:
            findings.append(
                ("LOW", f"Known SUID binary: {file}")
            )
        else:
            findings.append(
                ("MEDIUM", f"Review unusual SUID binary: {file}")
            )

    return findings


def analyze_world_writable(items):
    findings = []

    for item in items:
        if item in NORMAL_WORLD_WRITABLE:
            findings.append(
                ("LOW", f"Expected world-writable directory: {item}")
            )
        else:
            findings.append(
                ("MEDIUM", f"Review world-writable item: {item}")
            )

    return findings


def analyze_orphaned(files):
    findings = []

    for file in files:
        findings.append(
            ("MEDIUM", f"Orphaned file or directory: {file}")
        )

    return findings
