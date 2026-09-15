import subprocess


def process_enumeration():
    results = []

    results.append("[+] PROCESS ENUMERATION")
    results.append("-" * 60)

    try:
        result = subprocess.run(
            ["ps", "-eo", "user,pid,ppid,comm,args", "--sort=user"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        if result.returncode != 0:
            results.append("Unable to enumerate running processes.")
            return "\n".join(results)

        output = result.stdout.strip()

        if output:
            results.append(output)
        else:
            results.append("No running processes found.")

    except FileNotFoundError:
        results.append("ps command was not found.")

    except OSError as e:
        results.append(f"Process enumeration failed: {e}")

    return "\n".join(results)


def service_enumeration():
    results = []

    results.append("[+] SERVICE ENUMERATION")
    results.append("-" * 60)

    try:
        result = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        if result.returncode != 0:
            results.append(
                "Unable to enumerate services. "
                "systemd may not be available."
            )
            return "\n".join(results)

        output = result.stdout.strip()

        if output:
            results.append(output)
        else:
            results.append("No running services found.")

    except FileNotFoundError:
        results.append("systemctl command was not found.")

    except OSError as e:
        results.append(f"Service enumeration failed: {e}")

    return "\n".join(results)


def processes_scan():
    results = []

    results.append(process_enumeration())
    results.append("")
    results.append(service_enumeration())

    return "\n".join(results)
