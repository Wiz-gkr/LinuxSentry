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
from modules.persistence import persistence_enumeration
from modules.processes import processes_scan
from modules.service_analyzer import service_security_analysis
from modules.findings import Finding
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


def finding_values(finding):
    """
    Support both the new Finding object and
    the older (severity, message) tuple format.
    """

    if isinstance(finding, Finding):
        return (
            finding.severity,
            finding.message,
            finding.confidence
        )

    if isinstance(finding, tuple):
        severity = finding[0]
        message = finding[1]

        return (
            severity,
            message,
            "MEDIUM"
        )

    return (
        "LOW",
        str(finding),
        "LOW"
    )


def findings_summary(findings):
    low_count = 0
    medium_count = 0
    high_count = 0

    for finding in findings:

        severity, message, confidence = finding_values(
            finding
        )

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

    severity_points = {
        "LOW": 2,
        "MEDIUM": 5,
        "HIGH": 10
    }

    confidence_multiplier = {
        "LOW": 0.5,
        "MEDIUM": 1.0,
        "HIGH": 1.25
    }

    for finding in findings:

        severity, message, confidence = finding_values(
            finding
        )

        deduction = severity_points.get(
            severity,
            0
        )

        multiplier = confidence_multiplier.get(
            confidence,
            1.0
        )

        score -= deduction * multiplier

    score = max(
        0,
        round(score)
    )

    if score >= 80:
        risk_level = "LOW"

    elif score >= 50:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    return score, risk_level


def security_score_display(findings):

    score, risk_level = calculate_security_score(
        findings
    )

    return (
        "\n"
        + "=" * 60 + "\n"
        + "              SECURITY SCORE\n"
        + "=" * 60 + "\n\n"
        + f"Score      : {score}/100\n"
        + f"Risk Level : {risk_level}"
    )


def print_colored_findings(findings):

    for finding in findings:

        severity, message, confidence = finding_values(
            finding
        )

        if severity == "LOW":
            print(low(message))

        elif severity == "MEDIUM":
            print(medium(message))

        elif severity == "HIGH":
            print(high(message))


def print_detailed_findings(findings):

    for finding in findings:

        if isinstance(finding, Finding):

            print(
                f"\n[{finding.severity}] "
                f"{finding.category}"
            )

            print(
                f"  Finding      : "
                f"{finding.message}"
            )

            print(
                f"  Confidence   : "
                f"{finding.confidence}"
            )

            print(
                f"  Recommendation: "
                f"{finding.recommendation}"
            )

        else:

            severity, message, confidence = (
                finding_values(finding)
            )

            print(
                f"\n[{severity}] Security Finding"
            )

            print(
                f"  Finding      : "
                f"{message}"
            )

            print(
                f"  Confidence   : "
                f"{confidence}"
            )

            print(
                "  Recommendation: "
                "Review this finding."
            )


def print_colored_risk_level(findings):

    score, risk_level = calculate_security_score(
        findings
    )

    print("\n[+] OVERALL RISK LEVEL")

    if risk_level == "LOW":

        print(
            low(
                f"Risk Level: "
                f"{risk_level} "
                f"({score}/100)"
            )
        )

    elif risk_level == "MEDIUM":

        print(
            medium(
                f"Risk Level: "
                f"{risk_level} "
                f"({score}/100)"
            )
        )

    else:

        print(
            high(
                f"Risk Level: "
                f"{risk_level} "
                f"({score}/100)"
            )
        )


def save_report(
    filename,
    content,
    duration,
    findings
):

    try:

        score, risk_level = calculate_security_score(
            findings
        )

        low_count = 0
        medium_count = 0
        high_count = 0

        for finding in findings:

            severity, message, confidence = (
                finding_values(finding)
            )

            if severity == "LOW":
                low_count += 1

            elif severity == "MEDIUM":
                medium_count += 1

            elif severity == "HIGH":
                high_count += 1

        with open(filename, "w") as file:

            # -------------------------------------------------
            # REPORT HEADER
            # -------------------------------------------------

            file.write(
                "=" * 70 + "\n"
            )

            file.write(
                "              LINUXSENTRY SECURITY AUDIT REPORT\n"
            )

            file.write(
                "=" * 70 + "\n\n"
            )

            file.write(
                "Generated   : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            file.write(
                f"Scan Time   : {duration:.2f} seconds\n"
            )

            # -------------------------------------------------
            # SECURITY OVERVIEW
            # -------------------------------------------------

            file.write(
                "\n"
                + "=" * 70
                + "\n"
            )

            file.write(
                "                     SECURITY OVERVIEW\n"
            )

            file.write(
                "=" * 70
                + "\n\n"
            )

            file.write(
                f"Security Score : "
                f"{score}/100\n"
            )

            file.write(
                f"Risk Level     : "
                f"{risk_level}\n\n"
            )

            file.write(
                f"LOW Findings   : "
                f"{low_count}\n"
            )

            file.write(
                f"MEDIUM Findings: "
                f"{medium_count}\n"
            )

            file.write(
                f"HIGH Findings  : "
                f"{high_count}\n"
            )

            # -------------------------------------------------
            # DETAILED FINDINGS
            # -------------------------------------------------

            file.write(
                "\n"
                + "=" * 70
                + "\n"
            )

            file.write(
                "                   DETAILED FINDINGS\n"
            )

            file.write(
                "=" * 70
                + "\n"
            )

            if findings:

                for number, finding in enumerate(
                    findings,
                    start=1
                ):

                    file.write(
                        f"\nFinding #{number}\n"
                    )

                    file.write(
                        "-" * 70
                        + "\n"
                    )

                    if isinstance(
                        finding,
                        Finding
                    ):

                        file.write(
                            f"Severity       : "
                            f"{finding.severity}\n"
                        )

                        file.write(
                            f"Category       : "
                            f"{finding.category}\n"
                        )

                        file.write(
                            f"Confidence     : "
                            f"{finding.confidence}\n"
                        )

                        file.write(
                            f"Finding        : "
                            f"{finding.message}\n"
                        )

                        file.write(
                            f"Recommendation : "
                            f"{finding.recommendation}\n"
                        )

                    else:

                        severity, message, confidence = (
                            finding_values(finding)
                        )

                        file.write(
                            f"Severity       : "
                            f"{severity}\n"
                        )

                        file.write(
                            f"Confidence     : "
                            f"{confidence}\n"
                        )

                        file.write(
                            f"Finding        : "
                            f"{message}\n"
                        )

                        file.write(
                            "Recommendation : "
                            "Review this finding.\n"
                        )

            else:

                file.write(
                    "\nNo security findings detected.\n"
                )

            # -------------------------------------------------
            # SCAN RESULTS
            # -------------------------------------------------

            file.write(
                "\n"
                + "=" * 70
                + "\n"
            )

            file.write(
                "                     SCAN RESULTS\n"
            )

            file.write(
                "=" * 70
                + "\n\n"
            )

            file.write(content)

            # -------------------------------------------------
            # REPORT FOOTER
            # -------------------------------------------------

            file.write(
                "\n\n"
                + "=" * 70
                + "\n"
            )

            file.write(
                "                       END OF REPORT\n"
            )

            file.write(
                "=" * 70
                + "\n"
            )

        print(
            success(
                f"Report saved successfully: "
                f"{filename}"
            )
        )

    except OSError as e:

        print(
            error(
                f"Could not save report: {e}"
            )
        )


def main():

    start_time = time.time()

    parser = argparse.ArgumentParser(
        description=(
            "LinuxSentry - "
            "Linux Security Audit Tool"
        )
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
        "--persistence",
        action="store_true",
        help="Run cron and persistence checks"
    )

    parser.add_argument(
        "--processes",
        action="store_true",
        help="Run process and service enumeration"
    )

    parser.add_argument(
        "--service-analysis",
        action="store_true",
        help=(
            "Analyze running services "
            "for security issues"
        )
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

    # ---------------------------------------------------------
    # ARGUMENT VALIDATION
    # ---------------------------------------------------------

    if not any([
        args.system,
        args.network,
        args.ports,
        args.permissions,
        args.persistence,
        args.processes,
        args.service_analysis,
        args.all
    ]):

        print(banner())
        parser.print_help()
        return

    results = []
    all_findings = []

    print(banner())
    results.append(banner())

    # ---------------------------------------------------------
    # SYSTEM SCAN
    # ---------------------------------------------------------

    if args.system or args.all:

        print(
            info(
                "Running system information scan..."
            )
        )

        result = system_info()

        print(result)
        results.append(result)

    # ---------------------------------------------------------
    # NETWORK SCAN
    # ---------------------------------------------------------

    if args.network or args.all:

        print(
            info(
                "Running network interface scan..."
            )
        )

        result = network_info()

        print(result)
        results.append(result)

    # ---------------------------------------------------------
    # LISTENING PORTS
    # ---------------------------------------------------------

    if args.ports or args.all:

        print(
            info(
                "Checking listening ports..."
            )
        )

        result = listening_ports()

        print(result)
        results.append(result)

    # ---------------------------------------------------------
    # PERMISSIONS
    # ---------------------------------------------------------

    if args.permissions or args.all:

        print(
            info(
                "Running permission security checks..."
            )
        )

        result, findings = permissions_scan()

        print(result)
        results.append(result)

        if findings:

            print(
                "\n[+] SECURITY FINDINGS"
            )

            print(
                "-" * 60
            )

            print_colored_findings(
                findings
            )

            all_findings.extend(
                findings
            )

    # ---------------------------------------------------------
    # PERSISTENCE
    # ---------------------------------------------------------

    if args.persistence or args.all:

        print(
            info(
                "Running cron and persistence checks..."
            )
        )

        result, findings = (
            persistence_enumeration()
        )

        print(result)
        results.append(result)

        if findings:

            print(
                "\n[+] PERSISTENCE FINDINGS"
            )

            print(
                "-" * 60
            )

            print_colored_findings(
                findings
            )

            all_findings.extend(
                findings
            )

    # ---------------------------------------------------------
    # PROCESSES
    # ---------------------------------------------------------

    if args.processes or args.all:

        print(
            info(
                "Running process and service "
                "enumeration..."
            )
        )

        result = processes_scan()

        print(result)
        results.append(result)

    # ---------------------------------------------------------
    # SERVICE SECURITY ANALYSIS
    # ---------------------------------------------------------

    if args.service_analysis or args.all:

        print(
            info(
                "Running service security analysis..."
            )
        )

        result, findings = (
            service_security_analysis()
        )

        print(result)
        results.append(result)

        if findings:

            print(
                "\n[+] SERVICE SECURITY FINDINGS"
            )

            print(
                "-" * 60
            )

            print_colored_findings(
                findings
            )

            all_findings.extend(
                findings
            )

    # ---------------------------------------------------------
    # DETAILED FINDINGS
    # ---------------------------------------------------------

    print(
        "\n[+] DETAILED SECURITY FINDINGS"
    )

    print(
        "-" * 60
    )

    if all_findings:

        print_detailed_findings(
            all_findings
        )

    else:

        print(
            "No security findings detected."
        )

    # ---------------------------------------------------------
    # FINAL SUMMARY
    # ---------------------------------------------------------

    summary = findings_summary(
        all_findings
    )

    print(summary)
    results.append(summary)

    score_display = security_score_display(
        all_findings
    )

    print(score_display)
    results.append(score_display)

    print_colored_risk_level(
        all_findings
    )

    # ---------------------------------------------------------
    # COMPLETION
    # ---------------------------------------------------------

    duration = time.time() - start_time

    completion = (
        "\n"
        + "=" * 60 + "\n"
        + "             Scan Completed\n"
        + "=" * 60
        + f"\nScan Duration: "
        f"{duration:.2f} seconds"
    )

    print(completion)

    print(
        success(
            "All selected scans completed."
        )
    )

    results.append(completion)

    # ---------------------------------------------------------
    # REPORT OUTPUT
    # ---------------------------------------------------------

    if args.output:

        save_report(
            args.output,
            "\n\n".join(results),
            duration,
            all_findings
        )


if __name__ == "__main__":
    main()
