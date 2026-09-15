from modules.findings import Finding


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
                Finding(
                    severity="LOW",
                    category="SUID Security",
                    message=f"Known SUID binary: {file}",
                    recommendation=(
                        "Verify that this system binary requires "
                        "SUID privileges."
                    ),
                    confidence="HIGH"
                )
            )

        else:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="SUID Security",
                    message=f"Review unusual SUID binary: {file}",
                    recommendation=(
                        "Investigate the binary and verify whether "
                        "SUID privileges are required."
                    ),
                    confidence="MEDIUM"
                )
            )

    return findings


def analyze_world_writable(items):
    findings = []

    for item in items:

        if item in NORMAL_WORLD_WRITABLE:
            findings.append(
                Finding(
                    severity="LOW",
                    category="File Permissions",
                    message=(
                        f"Expected world-writable directory: {item}"
                    ),
                    recommendation=(
                        "No immediate action required, but verify "
                        "that the directory permissions are intentional."
                    ),
                    confidence="HIGH"
                )
            )

        else:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="File Permissions",
                    message=f"Review world-writable item: {item}",
                    recommendation=(
                        "Check whether world-write permissions are "
                        "required and remove them if unnecessary."
                    ),
                    confidence="HIGH"
                )
            )

    return findings


def analyze_orphaned(files):
    findings = []

    for file in files:

        findings.append(
            Finding(
                severity="MEDIUM",
                category="File Ownership",
                message=f"Orphaned file or directory: {file}",
                recommendation=(
                    "Verify the file ownership and assign it to "
                    "an appropriate user or group if necessary."
                ),
                confidence="MEDIUM"
            )
        )

    return findings
