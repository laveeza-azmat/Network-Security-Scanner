import ipaddress
import database


def add_rule(ip, port, protocol, action, priority=100):
    ip = str(ip or "").strip()
    port = str(port or "").strip()
    protocol = str(protocol or "").upper()
    action = str(action or "").upper()

    if ip.upper() != "ANY":
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("Enter a valid IP address or ANY.")
    if port.upper() != "ANY":
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Enter a port from 1 to 65535 or ANY.")
    if protocol not in ("TCP", "UDP", "ANY"):
        raise ValueError("Protocol must be TCP, UDP, or ANY.")
    if action not in ("ALLOW", "DENY"):
        raise ValueError("Action must be ALLOW or DENY.")
    try:
        priority = int(priority)
    except (TypeError, ValueError):
        raise ValueError("Priority must be a number.")
    if not 1 <= priority <= 10000:
        raise ValueError("Priority must be between 1 and 10000.")

    rule_id = database.add_firewall_rule(ip, port, protocol, action, priority)
    return {"id": rule_id, "ip": ip, "port": port,
            "protocol": protocol, "action": action, "priority": priority}


def get_rules():
    rules = database.get_firewall_rules()
    for rule in rules:
        rule["id"] = rule.pop("rule_id")
    return rules


def delete_rule(rule_id):
    database.delete_firewall_rule(rule_id)


def check_traffic(source_ip, destination_ip, port, protocol):
    protocol = str(protocol).upper()
    port = str(port)
    rules = get_rules()  # Already ordered by priority: lowest number first.

    for rule in rules:
        ip_match = rule["ip"] == "ANY" or rule["ip"] == source_ip or rule["ip"] == destination_ip
        port_match = rule["port"] == "ANY" or rule["port"] == port
        protocol_match = rule["protocol"] == "ANY" or rule["protocol"] == protocol
        if ip_match and port_match and protocol_match:
            action = rule["action"]
            database.save_traffic(source_ip, destination_ip, port, protocol, action, rule["id"])
            return {"action": action, "matched_rule": rule,
                    "message": f"Traffic {action.lower()} by priority {rule['priority']} rule.",
                    "flow": ["Source", "Firewall", action]}

    database.save_traffic(source_ip, destination_ip, port, protocol, "ALLOW", None)
    return {"action": "ALLOW", "matched_rule": None,
            "message": "No matching rule. Traffic allowed by default.",
            "flow": ["Source", "Firewall", "ALLOW"]}


def get_firewall_stats():
    stats = database.get_dashboard_stats()
    return {"total_rules": stats["firewall_rules"],
            "blocked_traffic": stats["blocked_traffic"],
            "allowed_traffic": stats["allowed_traffic"]}
