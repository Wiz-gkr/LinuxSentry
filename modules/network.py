import socket
import subprocess


def network_info():
    output = []

    output.append("\n[+] NETWORK INFORMATION")
    output.append("-" * 60)

    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        interfaces = {}

        for line in result.stdout.splitlines():
            parts = line.split()

            if len(parts) < 4:
                continue

            interface = parts[1]
            address_type = parts[2]
            address = parts[3]

            if interface not in interfaces:
                interfaces[interface] = []

            if address_type == "inet":
                interfaces[interface].append(
                    f"IPv4: {address}"
                )

            elif address_type == "inet6":
                interfaces[interface].append(
                    f"IPv6: {address}"
                )

        if not interfaces:
            output.append("[!] No network interfaces found.")

        else:
            for interface, addresses in interfaces.items():
                output.append(f"\n  Interface: {interface}")

                for address in addresses:
                    output.append(f"  └── {address}")

    except FileNotFoundError:
        output.append("[!] 'ip' command not found.")

    return "\n".join(output)


def get_service_name(port, protocol):
    try:
        return socket.getservbyport(
            port,
            protocol.lower()
        )

    except (OSError, ValueError):
        return "Unknown"


def listening_ports():
    output = []

    output.append("\n[+] LISTENING PORTS")
    output.append("-" * 60)

    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        lines = result.stdout.splitlines()

        if len(lines) <= 1:
            output.append("[!] No listening ports found.")

        else:
            for line in lines[1:]:
                parts = line.split()

                if len(parts) < 5:
                    continue

                protocol = parts[0]
                local_address = parts[4]

                try:
                    port = int(
                        local_address.rsplit(":", 1)[1]
                    )

                    service = get_service_name(
                        port,
                        protocol
                    )

                    output.append("")
                    output.append(
                        f"  Protocol : {protocol.upper()}"
                    )
                    output.append(
                        f"  Address  : {local_address}"
                    )
                    output.append(
                        f"  Port     : {port}"
                    )
                    output.append(
                        f"  Service  : {service}"
                    )

                    if len(parts) > 6:
                        process = " ".join(parts[6:])
                        output.append(
                            f"  Process  : {process}"
                        )

                except (ValueError, IndexError):
                    continue

    except FileNotFoundError:
        output.append("[!] 'ss' command not found.")

    return "\n".join(output)
