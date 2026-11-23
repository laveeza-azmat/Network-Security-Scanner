from flask import Flask, render_template, request, jsonify
import scanner
import firewall
import database

app = Flask(__name__)
database.create_tables()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/scanner")
def scanner_page():
    return render_template("scanner.html")


@app.route("/firewall")
def firewall_page():
    return render_template("firewall.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/api/scan", methods=["POST"])
def run_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    scan_type = data.get("scan_type", "tcp")
    ports = data.get("ports", "")
    try:
        normalized_target = scanner.validate_target(target)
        results = scanner.scan_network(normalized_target, scan_type, ports)
        scan_id = database.save_scan(normalized_target, results, scan_type)
        return jsonify({"success": True, "scan_id": scan_id,
                        "target": normalized_target, "scan_type": scan_type,
                        "results": results, "total_ports": len(results)})
    except Exception as error:
        return jsonify({"success": False, "message": str(error)}), 400


@app.route("/api/history", methods=["GET"])
def scan_history():
    return jsonify(database.get_scan_history())


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def scan_details(scan_id):
    scan = database.get_scan_details(scan_id)
    if scan is None:
        return jsonify({"message": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def remove_scan(scan_id):
    database.delete_scan(scan_id)
    return jsonify({"success": True, "message": "Scan deleted successfully"})


@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify(firewall.get_rules())


@app.route("/api/rules", methods=["POST"])
def create_rule():
    data = request.get_json(silent=True) or {}
    try:
        rule = firewall.add_rule(data.get("ip"), data.get("port"),
                                 data.get("protocol"), data.get("action"),
                                 data.get("priority", 100))
        return jsonify({"success": True, "rule": rule})
    except ValueError as error:
        return jsonify({"success": False, "message": str(error)}), 400


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def remove_rule(rule_id):
    firewall.delete_rule(rule_id)
    return jsonify({"success": True, "message": "Rule deleted successfully"})


@app.route("/api/traffic", methods=["POST"])
def simulate_traffic():
    data = request.get_json(silent=True) or {}
    required = ["source_ip", "destination_ip", "port", "protocol"]
    if any(not data.get(key) for key in required):
        return jsonify({"message": "Please complete all traffic fields."}), 400
    try:
        port = int(data["port"])
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"message": "Port must be between 1 and 65535."}), 400
    if data["protocol"].upper() not in ("TCP", "UDP"):
        return jsonify({"message": "Protocol must be TCP or UDP."}), 400
    return jsonify(firewall.check_traffic(data["source_ip"], data["destination_ip"],
                                          port, data["protocol"]))


@app.route("/api/traffic-logs", methods=["GET"])
def traffic_logs():
    return jsonify(database.get_traffic_logs())


@app.route("/api/stats", methods=["GET"])
def dashboard_stats():
    return jsonify(database.get_dashboard_stats())


if __name__ == "__main__":
    app.run(debug=True)
