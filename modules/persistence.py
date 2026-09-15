import os


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]


def persistence_enumeration():
    results = []
    findings = []

    results.append("[+] CRON & PERSISTENCE ENUMERATION")
    results.append("-" * 60)

    for path in CRON_PATHS:

        if not os.path.exists(path):
            continue

        if os.path.isfile(path):
            try:
                with open(
                    path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:
                    lines = file.readlines()

                results.append(f"\n[FILE] {path}")

                for line in lines:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    results.append(f"  └── {line}")

            except PermissionError:
                results.append(f"\n[DENIED] {path}")
                findings.append(
                    ("LOW", f"Permission denied while reading {path}")
                )

        elif os.path.isdir(path):
            results.append(f"\n[DIRECTORY] {path}")

            try:
                entries = os.listdir(path)

                if not entries:
                    results.append("  └── Empty")

                for entry in entries:
                    full_path = os.path.join(path, entry)
                    results.append(f"  └── {full_path}")

            except PermissionError:
                results.append("  └── Permission denied")
                findings.append(
                    ("LOW", f"Permission denied while reading {path}")
                )

    if len(results) == 2:
        results.append("No accessible cron locations found.")

    return "\n".join(results), findings
