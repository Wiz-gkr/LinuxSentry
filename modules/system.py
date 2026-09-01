import socket
import platform
import getpass


def system_info():
    output = []

    output.append("\n[+] SYSTEM INFORMATION")
    output.append("-" * 60)

    output.append(f"User         : {getpass.getuser()}")
    output.append(f"Hostname     : {socket.gethostname()}")
    output.append(f"Operating OS : {platform.system()}")
    output.append(f"OS Release   : {platform.release()}")
    output.append(f"Architecture : {platform.machine()}")

    return "\n".join(output)
