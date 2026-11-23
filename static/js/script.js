// NetGuard frontend scripts

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, function (char) {
        return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char];
    });
}

async function getJSON(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Request failed.");
    return data;
}

// Scanner
const scanForm = document.getElementById("scanForm");
if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const target = document.getElementById("target").value.trim();
        const scanType = document.getElementById("scanType").value;
        const customPorts = document.getElementById("customPorts").value.trim();
        const message = document.getElementById("scanMessage");
        const summary = document.getElementById("scanSummary");
        const resultsBody = document.getElementById("scanResults");
        message.textContent = "Scanning... This may take some time.";
        resultsBody.innerHTML = "";
        try {
            const data = await getJSON("/api/scan", {
                method: "POST", headers: {"Content-Type": "application/json"},
                body: JSON.stringify({target: target, scan_type: scanType, ports: customPorts})
            });
            message.textContent = "Scan completed successfully!";
            summary.textContent = `Scan ID: ${data.scan_id} | Target: ${data.target} | Type: ${data.scan_type} | Open ports: ${data.total_ports}`;
            if (!data.results.length) {
                resultsBody.innerHTML = '<tr><td colspan="6" class="empty">No open ports found.</td></tr>';
            } else {
                data.results.forEach(result => {
                    resultsBody.innerHTML += `<tr>
                        <td>${escapeHTML(result.ip)}</td><td>${escapeHTML(result.port)}</td>
                        <td>${escapeHTML(result.service)} ${escapeHTML(result.product)} ${escapeHTML(result.version)}</td>
                        <td>${escapeHTML(result.protocol)}</td><td>${escapeHTML(result.status)}</td>
                        <td>${escapeHTML(result.security_note)}</td></tr>`;
                });
            }
            loadDashboardStats();
        } catch (error) {
            message.textContent = error.message;
            console.error("Scanner error:", error);
        }
    });
}

// Firewall rules
async function loadRules() {
    const table = document.getElementById("rulesTable");
    if (!table) return;
    try {
        const rules = await getJSON("/api/rules");
        table.innerHTML = "";
        if (!rules.length) {
            table.innerHTML = '<tr><td colspan="7" class="empty">No firewall rules added yet.</td></tr>';
            return;
        }
        rules.forEach(rule => {
            table.innerHTML += `<tr>
                <td>${escapeHTML(rule.id)}</td><td>${escapeHTML(rule.priority)}</td>
                <td>${escapeHTML(rule.ip)}</td><td>${escapeHTML(rule.port)}</td>
                <td>${escapeHTML(rule.protocol)}</td><td>${escapeHTML(rule.action)}</td>
                <td><button type="button" class="deleteRule" data-id="${Number(rule.id)}">Delete</button></td></tr>`;
        });
    } catch (error) { console.error("Could not load rules:", error); }
}

const ruleForm = document.getElementById("ruleForm");
if (ruleForm) {
    ruleForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const message = document.getElementById("ruleMessage");
        message.textContent = "Adding rule...";
        try {
            await getJSON("/api/rules", {
                method: "POST", headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    ip: document.getElementById("ruleIP").value.trim(),
                    port: document.getElementById("rulePort").value.trim(),
                    protocol: document.getElementById("ruleProtocol").value,
                    action: document.getElementById("ruleAction").value,
                    priority: document.getElementById("rulePriority").value
                })
            });
            message.textContent = "Firewall rule added successfully!";
            ruleForm.reset();
            document.getElementById("rulePriority").value = 100;
            await loadRules();
            loadDashboardStats();
        } catch (error) { message.textContent = error.message; }
    });
}

document.addEventListener("click", async function (event) {
    if (event.target.classList.contains("deleteRule")) {
        const id = event.target.dataset.id;
        if (!confirm("Delete this firewall rule?")) return;
        try {
            await getJSON(`/api/rules/${id}`, {method: "DELETE"});
            await loadRules();
            loadDashboardStats();
        } catch (error) { alert(error.message); }
    }
    if (event.target.classList.contains("viewScan")) viewScan(event.target.dataset.id);
    if (event.target.classList.contains("deleteScan")) deleteScan(event.target.dataset.id);
});

// Traffic simulator and visual flow
const trafficForm = document.getElementById("trafficForm");
if (trafficForm) {
    trafficForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const resultBox = document.getElementById("trafficResult");
        const flow = document.getElementById("trafficFlow");
        resultBox.textContent = "Simulating traffic...";
        try {
            const result = await getJSON("/api/traffic", {
                method: "POST", headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    source_ip: document.getElementById("sourceIP").value.trim(),
                    destination_ip: document.getElementById("destinationIP").value.trim(),
                    port: document.getElementById("trafficPort").value,
                    protocol: document.getElementById("trafficProtocol").value
                })
            });
            resultBox.className = result.action === "DENY" ? "traffic-blocked" : "traffic-allowed";
            resultBox.innerHTML = `<h3>${escapeHTML(result.action)}</h3><p>${escapeHTML(result.message)}</p>`;
            const finalLabel = result.action === "DENY" ? "BLOCKED" : "ALLOWED";
            flow.innerHTML = `<div class="flow-box">Source<br>${escapeHTML(document.getElementById("sourceIP").value)}</div>
                <div class="flow-arrow">→</div><div class="flow-box">Firewall<br>Priority rules</div>
                <div class="flow-arrow">→</div><div class="flow-box ${result.action === "DENY" ? "flow-denied" : "flow-allowed"}">${finalLabel}</div>`;
            await loadTrafficLogs();
            loadDashboardStats();
        } catch (error) {
            resultBox.className = "traffic-result";
            resultBox.textContent = error.message;
            console.error("Traffic simulation error:", error);
        }
    });
}

async function loadTrafficLogs() {
    const table = document.getElementById("trafficLogs");
    if (!table) return;
    try {
        const logs = await getJSON("/api/traffic-logs");
        table.innerHTML = "";
        if (!logs.length) {
            table.innerHTML = '<tr><td colspan="7">No traffic logs yet.</td></tr>';
            return;
        }
        logs.forEach(log => {
            table.innerHTML += `<tr><td>${escapeHTML(log.log_date)}</td>
                <td>${escapeHTML(log.source_ip)}</td><td>${escapeHTML(log.destination_ip)}</td>
                <td>${escapeHTML(log.port)}</td><td>${escapeHTML(log.protocol)}</td>
                <td>${escapeHTML(log.action)}</td><td>${escapeHTML(log.matched_rule_id ?? "Default")}</td></tr>`;
        });
    } catch (error) { console.error("Traffic logs error:", error); }
}

// Scan history
async function loadHistory() {
    const table = document.getElementById("historyTable");
    if (!table) return;
    try {
        const history = await getJSON("/api/history");
        table.innerHTML = "";
        if (!history.length) {
            table.innerHTML = '<tr><td colspan="6">No scan history available.</td></tr>';
            return;
        }
        history.forEach(scan => {
            table.innerHTML += `<tr><td>${escapeHTML(scan.scan_id)}</td>
                <td>${escapeHTML(scan.target_ip)}</td><td>${escapeHTML(scan.scan_date)}</td>
                <td>${escapeHTML(scan.scan_type || "tcp")}</td><td>${escapeHTML(scan.total_ports)}</td>
                <td><button type="button" class="viewScan" data-id="${Number(scan.scan_id)}">View</button>
                <button type="button" class="deleteScan" data-id="${Number(scan.scan_id)}">Delete</button></td></tr>`;
        });
    } catch (error) { console.error("History loading error:", error); }
}

async function viewScan(scanID) {
    const details = document.getElementById("historyDetails");
    if (!details) return;
    try {
        const scan = await getJSON(`/api/history/${scanID}`);
        let html = `<h3>Scan Details</h3><p><strong>Target:</strong> ${escapeHTML(scan.target_ip)}</p>
            <p><strong>Date:</strong> ${escapeHTML(scan.scan_date)} | <strong>Type:</strong> ${escapeHTML(scan.scan_type || "tcp")}</p>
            <h3>Results</h3><div class="table-wrapper"><table><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Protocol</th><th>Status</th><th>Security Note</th></tr></thead><tbody>`;
        if (!scan.results.length) html += '<tr><td colspan="6">No open ports found.</td></tr>';
        scan.results.forEach(result => {
            html += `<tr><td>${escapeHTML(result.ip)}</td><td>${escapeHTML(result.port)}</td>
                <td>${escapeHTML(result.service)} ${escapeHTML(result.product)} ${escapeHTML(result.version)}</td>
                <td>${escapeHTML(result.protocol)}</td><td>${escapeHTML(result.status)}</td>
                <td>${escapeHTML(result.security_note || "")}</td></tr>`;
        });
        details.innerHTML = html + '</tbody></table></div>';
    } catch (error) { details.textContent = error.message; }
}

async function deleteScan(scanID) {
    if (!confirm("Delete this scan from history?")) return;
    try {
        await getJSON(`/api/history/${scanID}`, {method: "DELETE"});
        await loadHistory();
        const details = document.getElementById("historyDetails");
        if (details) details.innerHTML = "";
        loadDashboardStats();
    } catch (error) { alert(error.message); }
}

// Dashboard statistics
async function loadDashboardStats() {
    try {
        const stats = await getJSON("/api/stats");
        const ids = {totalScans: "total_scans", openPorts: "open_ports",
            firewallRules: "firewall_rules", blockedTraffic: "blocked_traffic"};
        Object.entries(ids).forEach(([elementId, key]) => {
            const element = document.getElementById(elementId);
            if (element) element.textContent = stats[key];
        });
    } catch (error) { console.error("Dashboard statistics error:", error); }
}

document.addEventListener("DOMContentLoaded", function () {
    loadRules();
    loadHistory();
    loadTrafficLogs();
    loadDashboardStats();
    setInterval(loadDashboardStats, 5000);
});
