import ipaddress
import re
import socket
import nmap


def validate_target(target):
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please enter a target IP address or hostname.")

    target = target.strip()
    if target.lower() == "localhost":
        return "127.0.0.1"

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(target)
            address = ipaddress.ip_address(resolved_ip)
            target = resolved_ip
        except (socket.gaierror, ValueError):
            raise ValueError("Invalid hostname or IP address.")

    if not (address.is_private or address.is_loopback):
        raise ValueError("Only localhost and private network targets are allowed.")

    return str(address)


def validate_ports(ports):
    if ports is None or str(ports).strip() == "":
        return None

    ports = str(ports).strip()
    if not re.fullmatch(r"[0-9,\- ]+", ports):
        raise ValueError("Use port numbers, commas, and ranges only. Example: 80,443,8000-8100")

    for item in ports.replace(" ", "").split(","):
        if not item:
            raise ValueError("Invalid port list.")
        if "-" in item:
            parts = item.split("-")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise ValueError("Invalid port range.")
            start, end = map(int, parts)
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Ports must be between 1 and 65535, with start <= end.")
        else:
            if not item.isdigit() or not 1 <= int(item) <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")

    return ports.replace(" ", "")


def get_security_note(service):
    service = (service or "").lower()
    notes = {
        "telnet": "Telnet is unencrypted. Prefer SSH where possible.",
        "ftp": "FTP may transmit credentials without encryption. Prefer SFTP or FTPS.",
        "microsoft-ds": "SMB should be restricted to trusted networks and kept patched.",
        "netbios-ssn": "NetBIOS should not be exposed to untrusted networks.",
        "rdp": "Restrict Remote Desktop to trusted hosts and use strong authentication.",
        "ms-wbt-server": "Restrict Remote Desktop to trusted hosts and use strong authentication.",
        "mysql": "Restrict database access to trusted hosts and require strong credentials.",
        "redis": "Restrict Redis access and enable appropriate authentication.",
        "mongodb": "Restrict database access and enable authentication.",
        "vnc": "Restrict remote desktop access and use secure tunnelling."
    }
    return notes.get(service, "No basic service-specific warning identified.")


def scan_network(target, scan_type="tcp", ports=None):
    target = validate_target(target)
    ports = validate_ports(ports)

    scan_options = {
        "tcp": "-sT",
        "udp": "-sU",
        "full": "-sT"
    }
    if scan_type not in scan_options:
        raise ValueError("Invalid scan type selected.")
    if scan_type == "full" and ports:
        raise ValueError("Full TCP scan uses all TCP ports. Leave custom ports empty for this scan type.")

    if scan_type == "full":
        port_option = "-p-"
    elif ports:
        port_option = f"-p {ports}"
    else:
        port_option = "-F"

    arguments = f"{scan_options[scan_type]} -sV --version-light -Pn -n {port_option}"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=arguments)

    results = []
    if target not in scanner.all_hosts():
        return results

    for protocol in scanner[target].all_protocols():
        for port in sorted(scanner[target][protocol].keys()):
            info = scanner[target][protocol][port]
            service = info.get("name", "unknown")
            results.append({
                "ip": target,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "status": info.get("state", "unknown"),
                "security_note": get_security_note(service)
            })
    return results
