Advanced Network Scanner & Vulnerability Dashboard
An automated network reconnaissance tool that bridges the gap between raw Nmap data and actionable security intelligence. This project features a dual-phase scanning workflow and a high-performance Flask web dashboard for real-time risk assessment.

🚀 Key Features
Two-Phase Reconnaissance:

Discovery Phase: Fast host identification and device fingerprinting.

Deep Scan Phase: Targeted service versioning, script scanning, and vulnerability mapping.

Firewall Evasion: Implements the -Pn flag to bypass ICMP-blocking firewalls, ensuring accurate results on modern operating systems.

Vulnerability Analysis: Integrates with the NVD API to fetch real-time CVE data for identified services.

Interactive Dashboard: Visualizes risk severity distribution (Critical to Info) using Chart.js and Tailwind CSS.

🛠️ Tech Stack
Language: Python 3.13

Backend: Flask Web Framework

Engine: Nmap (Network Mapper)

Frontend: Tailwind CSS & Chart.js

Data: NVD (National Vulnerability Database) REST API

⚙️ Installation & Setup
1. Prerequisites
Ensure you have Nmap installed on your system (Kali Linux comes with this pre-installed).

2. Clone and Initialize
Bash
git clone https://github.com/CyberVortexX/advanced-network-scanner.git
cd advanced-network-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
3. Run the Application
Note: Root privileges are required for Nmap to perform advanced service versioning (-sV) and stealth scans.

Bash
sudo ./venv/bin/python web/app.py
🛡️ Responsible Use & Disclaimer
This tool is developed for educational and authorized security testing purposes only. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical. The developer is not responsible for any misuse of this software.

📂 Project Structure
web/app.py: The Flask server handling routing and data processing.

fingerprint/nmap_scan.py: Backend Nmap engine with custom scan profiles.

analysis/port_explainer.py: Logic for mapping ports to risks and remediation tips.

templates/: Jinja2 templates for the interactive dashboard and discovery selection.
