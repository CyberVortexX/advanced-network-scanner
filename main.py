from fingerprint.nmap_scan import nmap_service_scan
from vuln.nvd import fetch_cves
from vuln.cvss import extract_cvss

def scan_target(ip):
    print(f"\n[+] Scanning target: {ip}\n")

    # Phase 3 + 4: Port & Service Detection
    services = nmap_service_scan(ip)

    if not services:
        print("[-] No open services detected.")
        return

    for svc in services:
        port = svc["port"]
        service = svc["service"]

        print(f"[+] Port {port} | Service: {service}")

        # Phase 5: Vulnerability Mapping
        try:
            data = fetch_cves(service)
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                print("    No known CVEs found.")
                continue

            for item in vulns[:3]:  # limit output
                cve = item["cve"]
                score, severity = extract_cvss(cve)
                print(f"    {cve['id']} | CVSS {score} | {severity}")

        except Exception as e:
            print("    CVE lookup failed:", e)

if __name__ == "__main__":
    target_ip = input("Enter target IP: ").strip()
    scan_target(target_ip)
