# Network Security Scanner & Firewall Visualizer

A Flask-based academic project for scanning authorized private-network hosts, viewing open ports and services, and simulating priority-based firewall rules.

## Features
- Target input with localhost/private-IP restriction.
- TCP Connect, UDP, and full TCP Connect scan options.
- Custom ports and ranges, such as `80,443,8000-8100`.
- Nmap service/version detection with basic informational service warnings.
- SQLite scan history and persistent firewall rules.
- ALLOW/DENY firewall simulator with numeric priorities (1 is highest).
- Traffic decision flow visualization and traffic logs.
- Dashboard statistics.

## Requirements
- Python 3.10 or newer
- Nmap installed and available on PATH
- Python packages in `requirements.txt`

## Run on Windows
1. Install Nmap from the official Nmap website and ensure `nmap` works in Command Prompt.
2. Open this folder in VS Code.
3. Create/activate a virtual environment if desired:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   ```
4. Install packages:
   ```powershell
   pip install -r requirements.txt
   ```
5. Start the application:
   ```powershell
   python app.py
   ```
6. Open `http://127.0.0.1:5000`.

## Scan notes
- Only scan systems you own or have explicit permission to test.
- The app restricts targets to localhost and private IP addresses.
- UDP scans and full TCP scans can take longer. UDP scanning may require administrator/root privileges depending on the operating system and Nmap setup.
- Service-based notes are general security reminders, not proof that a vulnerability exists.

## Firewall simulator note
The firewall module simulates decisions inside this application. It does not configure Windows Firewall or block real network traffic. Rules are evaluated by ascending priority number; equal-priority rules use newest-first order. If no rule matches, traffic is allowed by default.

## Database
SQLite creates `network_scanner.db` automatically. The database contains scan history, scan results, firewall rules, and traffic logs. The database file is ignored by Git to avoid publishing local scan data.
