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

    common_suid = [
        "/usr/sbin/mount.cifs",
        "/usr/sbin/mount.nfs",
        "/usr/sbin/pppd",
        "/usr/bin/ntfs-3g",
        "/usr/bin/fusermount3",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/xorg/Xorg.wrap",
    ]

    for file in files:

        if file in KNOWN_SYSTEM_SUID:
            findings.append(
                Finding(
                    severity="LOW",
                    category="SUID Security",
                    message=f"Expected system SUID binary: {file}",
                    recommendation=(
                        "Verify that SUID privileges are required "
                        "for this system binary."
                    ),
                    confidence="HIGH"
                )
            )

        elif file in common_suid:
            findings.append(
                Finding(
                    severity="LOW",
                    category="SUID Security",
                    message=f"Common SUID binary detected: {file}",
                    recommendation=(
                        "Verify that the package and SUID permission "
                        "are expected on this system."
                    ),
                    confidence="MEDIUM"
                )
            )

        elif file.startswith("/snap/"):
            findings.append(
                Finding(
                    severity="LOW",
                    category="SUID Security",
                    message=f"Snap-managed SUID binary: {file}",
                    recommendation=(
                        "Verify that the SUID permission belongs "
                        "to the installed Snap package."
                    ),
                    confidence="MEDIUM"
                )
            )

        elif "/kismet_cap_" in file:
            findings.append(
                Finding(
                    severity="LOW",
                    category="SUID Security",
                    message=f"Kismet capture helper: {file}",
                    recommendation=(
                        "Verify that the Kismet capture helper "
                        "is required and comes from a trusted package."
                    ),
                    confidence="HIGH"
                )
            )

        else:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="SUID Security",
                    message=f"Unrecognized SUID binary: {file}",
                    recommendation=(
                        "Identify the owning package, verify the "
                        "binary's purpose, and confirm that SUID "
                        "privileges are required."
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
                    message=f"Expected world-writable directory: {item}",
                    recommendation=(
                        "Verify that the directory permissions "
                        "are intentional."
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
                        "Check whether world-write permissions "
                        "are required and remove them if unnecessary."
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
