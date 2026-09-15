import os
import subprocess


def get_running_services():
    """Return currently running systemd service names."""
    try:
        result = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        if result.returncode != 0:
            return []

        services = []

        for line in result.stdout.splitlines():
            parts = line.split()

            if parts:
                services.append(parts[0])

        return services

    except (FileNotFoundError, OSError):
        return []


def get_service_exec(service):
    """Get the executable path configured for a service."""
    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                service,
                "--property=ExecStart",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except (FileNotFoundError, OSError):
        return ""


def service_security_analysis():
    """Analyze running services for basic security concerns."""

    findings = []
    results = []

    results.append("[+] SERVICE SECURITY ANALYSIS")
    results.append("-" * 60)

    services = get_running_services()

    if not services:
        results.append("No running systemd services found.")
        return "\n".join(results), findings

    results.append(f"Running services found: {len(services)}")

    for service in services:

        executable = get_service_exec(service)

        if not executable:
            continue

        results.append(
            f"\n[INFO] {service}"
        )
        results.append(
            f"  └── ExecStart: {executable}"
        )

        # Extract possible executable paths
        possible_paths = []

        for part in executable.split():
            if part.startswith("/"):
                possible_paths.append(part)

        for path in possible_paths:

            # Remove common systemd command prefixes
            path = path.strip()

            if not os.path.isfile(path):
                continue

            try:
                mode = os.stat(path).st_mode

                # World-writable executable
                if mode & 0o002:
                    findings.append(
                        (
                            "HIGH",
                            f"Running service executable is "
                            f"world-writable: {path}"
                        )
                    )

                # Group-writable executable
                elif mode & 0o020:
                    findings.append(
                        (
                            "MEDIUM",
                            f"Running service executable is "
                            f"group-writable: {path}"
                        )
                    )

            except OSError:
                continue

    if not findings:
        results.append(
            "\nNo obvious service executable permission "
            "issues detected."
        )

    return "\n".join(results), findings
