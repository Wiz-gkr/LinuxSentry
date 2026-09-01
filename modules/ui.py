class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


def info(message):
    return f"{Colors.BLUE}[INFO]{Colors.RESET} {message}"


def success(message):
    return f"{Colors.GREEN}[+]{Colors.RESET} {message}"


def warning(message):
    return f"{Colors.YELLOW}[!]{Colors.RESET} {message}"


def error(message):
    return f"{Colors.RED}[-]{Colors.RESET} {message}"


def low(message):
    return f"{Colors.CYAN}[LOW]{Colors.RESET} {message}"


def medium(message):
    return f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} {message}"


def high(message):
    return f"{Colors.RED}{Colors.BOLD}[HIGH]{Colors.RESET} {message}"
