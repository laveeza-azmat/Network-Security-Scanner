import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "network_scanner.db")


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS scan_history (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip TEXT NOT NULL,
        scan_date TEXT NOT NULL,
        total_ports INTEGER NOT NULL,
        scan_type TEXT DEFAULT 'tcp'
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS scan_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        ip TEXT, port INTEGER, service TEXT, protocol TEXT, status TEXT,
        product TEXT, version TEXT,
        security_note TEXT DEFAULT '',
        FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id)
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS firewall_rules (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL, port TEXT NOT NULL, protocol TEXT NOT NULL,
        action TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now', 'localtime')),
        priority INTEGER NOT NULL DEFAULT 100
    )""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS traffic_logs (
        traffic_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
        port TEXT NOT NULL, protocol TEXT NOT NULL, action TEXT NOT NULL,
        matched_rule_id INTEGER,
        log_date TEXT DEFAULT (datetime('now', 'localtime'))
    )""")

    # Add columns to databases created by earlier versions.
    scan_columns = [row[1] for row in cursor.execute("PRAGMA table_info(scan_history)").fetchall()]
    if "scan_type" not in scan_columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN scan_type TEXT DEFAULT 'tcp'")
    result_columns = [row[1] for row in cursor.execute("PRAGMA table_info(scan_results)").fetchall()]
    if "security_note" not in result_columns:
        cursor.execute("ALTER TABLE scan_results ADD COLUMN security_note TEXT DEFAULT ''")
    rule_columns = [row[1] for row in cursor.execute("PRAGMA table_info(firewall_rules)").fetchall()]
    if "priority" not in rule_columns:
        cursor.execute("ALTER TABLE firewall_rules ADD COLUMN priority INTEGER NOT NULL DEFAULT 100")

    conn.commit()
    conn.close()


def save_scan(target, results, scan_type="tcp"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO scan_history (target_ip, scan_date, total_ports, scan_type)
        VALUES (?, datetime('now', 'localtime'), ?, ?)""", (target, len(results), scan_type))
    scan_id = cursor.lastrowid
    for result in results:
        cursor.execute("""INSERT INTO scan_results
            (scan_id, ip, port, service, protocol, status, product, version, security_note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, result.get("ip"), result.get("port"), result.get("service"),
             result.get("protocol"), result.get("status"), result.get("product"),
             result.get("version"), result.get("security_note", "")))
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM scan_history ORDER BY scan_id DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_details(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM scan_history WHERE scan_id = ?", (scan_id,)).fetchone()
    if scan is None:
        conn.close()
        return None
    results = conn.execute("SELECT * FROM scan_results WHERE scan_id = ? ORDER BY protocol, port", (scan_id,)).fetchall()
    conn.close()
    data = dict(scan)
    data["results"] = [dict(row) for row in results]
    return data


def delete_scan(scan_id):
    conn = get_connection()
    conn.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()


def add_firewall_rule(ip, port, protocol, action, priority):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO firewall_rules (ip, port, protocol, action, priority)
        VALUES (?, ?, ?, ?, ?)""", (ip, port, protocol, action, priority))
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rule_id


def get_firewall_rules():
    conn = get_connection()
    rows = conn.execute("""SELECT * FROM firewall_rules
        ORDER BY priority ASC, rule_id DESC""").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def delete_firewall_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM firewall_rules WHERE rule_id = ?", (rule_id,))
    conn.commit()
    conn.close()


def save_traffic(source_ip, destination_ip, port, protocol, action, matched_rule_id):
    conn = get_connection()
    conn.execute("""INSERT INTO traffic_logs
        (source_ip, destination_ip, port, protocol, action, matched_rule_id)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (source_ip, destination_ip, str(port), protocol, action, matched_rule_id))
    conn.commit()
    conn.close()


def get_traffic_logs():
    conn = get_connection()
    rows = conn.execute("""SELECT traffic_logs.*, firewall_rules.priority
        FROM traffic_logs LEFT JOIN firewall_rules
        ON traffic_logs.matched_rule_id = firewall_rules.rule_id
        ORDER BY traffic_id DESC LIMIT 100""").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()
    total_scans = cursor.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    open_ports = cursor.execute("SELECT COALESCE(SUM(total_ports), 0) FROM scan_history").fetchone()[0]
    total_rules = cursor.execute("SELECT COUNT(*) FROM firewall_rules").fetchone()[0]
    blocked = cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'DENY'").fetchone()[0]
    allowed = cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'ALLOW'").fetchone()[0]
    conn.close()
    return {"total_scans": total_scans, "open_ports": open_ports,
            "firewall_rules": total_rules, "blocked_traffic": blocked,
            "allowed_traffic": allowed}
