import subprocess

from modules.analyzer import (
    analyze_suid,
    analyze_world_writable,
    analyze_orphaned
)


def format_findings(findings):
    output = []

    for severity, message in findings:
        output.append(f"[{severity}] {message}")

    return output


def suid_enumeration():
    output = []

    output.append("\n[+] SUID BINARY ENUMERATION")
    output.append("-" * 60)

    try:
        result = subprocess.run(
            [
                "find",
                "/",
                "-perm",
                "-4000",
                "-type",
                "f"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        suid_files = result.stdout.splitlines()

        if not suid_files:
            output.append("[+] No SUID binaries found.")
            return "\n".join(output), []

        output.append(
            f"[+] Found {len(suid_files)} SUID binaries:\n"
        )

        for file in suid_files:
            output.append(f"  └── {file}")

        findings = analyze_suid(suid_files)

        output.append("\n[+] ANALYSIS")

        for finding in format_findings(findings):
            output.append(f"  └── {finding}")

        return "\n".join(output), findings

    except FileNotFoundError:
        output.append("[!] 'find' command not found.")
        return "\n".join(output), []


def world_writable_enumeration():
    output = []

    output.append("\n[+] WORLD-WRITABLE FILES & DIRECTORIES")
    output.append("-" * 60)

    try:
        result = subprocess.run(
            [
                "find",
                "/",
                "-xdev",
                "-perm",
                "-0002"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        writable_items = result.stdout.splitlines()

        if not writable_items:
            output.append("[+] No world-writable items found.")
            return "\n".join(output), []

        output.append(
            f"[+] Found {len(writable_items)} "
            "world-writable items:\n"
        )

        for item in writable_items:
            output.append(f"  └── {item}")

        findings = analyze_world_writable(writable_items)

        output.append("\n[+] ANALYSIS")

        for finding in format_findings(findings):
            output.append(f"  └── {finding}")

        return "\n".join(output), findings

    except FileNotFoundError:
        output.append("[!] 'find' command not found.")
        return "\n".join(output), []


def orphaned_files_enumeration():
    output = []

    output.append("\n[+] ORPHANED FILES ENUMERATION")
    output.append("-" * 60)

    try:
        result = subprocess.run(
            [
                "find",
                "/",
                "-xdev",
                "(",
                "-nouser",
                "-o",
                "-nogroup",
                ")"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        orphaned_files = result.stdout.splitlines()

        if not orphaned_files:
            output.append("[+] No orphaned files found.")
            return "\n".join(output), []

        output.append(
            f"[+] Found {len(orphaned_files)} orphaned files:\n"
        )

        for file in orphaned_files:
            output.append(f"  └── {file}")

        findings = analyze_orphaned(orphaned_files)

        output.append("\n[+] ANALYSIS")

        for finding in format_findings(findings):
            output.append(f"  └── {finding}")

        return "\n".join(output), findings

    except FileNotFoundError:
        output.append("[!] 'find' command not found.")
        return "\n".join(output), []
