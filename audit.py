import argparse
import time
from datetime import datetime

from modules.system import system_info
from modules.network import network_info, listening_ports
from modules.permissions import (
    suid_enumeration,
    world_writable_enumeration,
    orphaned_files_enumeration
)
from modules.ui import (
    info,
    success,
    error,
    low,
    medium,
    high
)


def banner():
    return (
        "=" * 60 + "\n"
        "          LinuxSentry - Security Audit Tool\n"
        + "=" * 60
    )


def permissions_scan():
    results = []
    all_findings = []

    result, findings = suid_enumeration()
    results.append(result)
    all_findings.extend(findings)

    result, findings = world_writable_enumeration()
    results.append(result)
    all_findings.extend(findings)

    result, findings = orphaned_files_enumeration()
    results.append(result)
    all_findings.extend(findings)

    return "\n".join(results), all_findings


def findings_summary(findings):
    low_count = 0
    medium_count = 0
    high_count = 0

    for severity, message in findings:
        if severity == "LOW":
            low_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "HIGH":
            high_count += 1

    return (
        "\n"
        + "=" * 60 + "\n"
        + "          SECURITY FINDINGS SUMMARY\n"
        + "=" * 60 + "\n\n"
        + f"LOW     : {low_count}\n"
        + f"MEDIUM  : {medium_count}\n"
        + f"HIGH    : {high_count}"
    )


def calculate_security_score(findings):
    score = 100

    for severity, message in findings:
        if severity == "LOW":
            score -= 2
        elif severity == "MEDIUM":
            score -= 5
        elif severity == "HIGH":
            score -= 10

    score = max(score, 0)

    if score >= 80:
        risk_level = "LOW"
    elif score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return score, risk_level


def security_score_display(findings):
    score, risk_level = calculate_security_score(findings)

    return (
        "\n"
        + "=" * 60 + "\n"
        + "              SECURITY SCORE\n"
        + "=" * 60 + "\n\n"
        + f"Score      : {score}/100\n"
        + f"Risk Level : {risk_level}"
    )


def print_colored_findings(findings):
    for severity, message in findings:
        if severity == "LOW":
            print(low(message))
        elif severity == "MEDIUM":
            print(medium(message))
        elif severity == "HIGH":
            print(high(message))


def print_colored_risk_level(findings):
    score, risk_level = calculate_security_score(findings)

    print("\n[+] OVERALL RISK LEVEL")

    if risk_level == "LOW":
        print(low(f"Risk Level: {risk_level} ({score}/100)"))
    elif risk_level == "MEDIUM":
        print(medium(f"Risk Level: {risk_level} ({score}/100)"))
    else:
        print(high(f"Risk Level: {risk_level} ({score}/100)"))


def save_report(filename, content, duration):
    try:
        with open(filename, "w") as file:
            file.write("=" * 60 + "\n")
            file.write("          LinuxSentry Security Audit Report\n")
            file.write("=" * 60 + "\n\n")

            file.write(
                f"Generated : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            file.write(f"Scan Time : {duration:.2f} seconds\n")

            file.write("\n" + "=" * 60 + "\n")
            file.write("                    RESULTS\n")
            file.write("=" * 60 + "\n")

            file.write(content)

        print(success(
            f"Report saved successfully: {filename}"
        ))

    except OSError as e:
        print(error(
            f"Could not save report: {e}"
        ))


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description="LinuxSentry - Linux Security Audit Tool"
    )

    parser.add_argument(
        "--system",
        action="store_true",
        help="Run system information scan"
    )

    parser.add_argument(
        "--network",
        action="store_true",
        help="Run network interface scan"
    )

    parser.add_argument(
        "--ports",
        action="store_true",
        help="Show listening ports"
    )

    parser.add_argument(
        "--permissions",
        action="store_true",
        help="Run permission security checks"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all security checks"
    )

    parser.add_argument(
        "--output",
        type=str,
        help="Save results to a text file"
    )

    args = parser.parse_args()

    if not any([
        args.system,
        args.network,
        args.ports,
        args.permissions,
        args.all
    ]):
        print(banner())
        parser.print_help()
        return

    results = []
    all_findings = []

    print(banner())
    results.append(banner())

    if args.system or args.all:
        print(info("Running system information scan..."))

        result = system_info()
        print(result)
        results.append(result)

    if args.network or args.all:
        print(info("Running network interface scan..."))

        result = network_info()
        print(result)
        results.append(result)

    if args.ports or args.all:
        print(info("Checking listening ports..."))

        result = listening_ports()
        print(result)
        results.append(result)

    if args.permissions or args.all:
        print(info(
            "Running permission security checks..."
        ))

        result, findings = permissions_scan()

        print(result)
        results.append(result)

        print("\n[+] COLORED SECURITY FINDINGS")
        print("-" * 60)

        print_colored_findings(findings)

        all_findings.extend(findings)

        summary = findings_summary(all_findings)
        print(summary)
        results.append(summary)

        score_display = security_score_display(
            all_findings
        )
        print(score_display)
        results.append(score_display)

        print_colored_risk_level(all_findings)

    duration = time.time() - start_time

    completion = (
        "\n"
        + "=" * 60 + "\n"
        + "             Scan Completed\n"
        + "=" * 60
        + f"\nScan Duration: {duration:.2f} seconds"
    )

    print(completion)
    print(success("All selected scans completed."))

    results.append(completion)

    if args.output:
        save_report(
            args.output,
            "\n\n".join(results),
            duration
        )


if __name__ == "__main__":
    main()
