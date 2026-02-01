import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vuln.nvd import fetch_cves
from vuln.cvss import calculate_severity, get_severity_label

def explain_ports(ports_list):
    analyzed_results = []
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    
    # Priority risks with remediation tips
    PRIORITY_RISKS = {
        445: {
            "risk": "Critical", 
            "desc": "SMB/Samba - File Sharing.", 
            "exploit": "EternalBlue/RCE potential.", 
            "remediation": "Disable SMBv1; apply MS17-010 patches."
        },
        135: {
            "risk": "Informational", 
            "desc": "Microsoft RPC Service.", 
            "exploit": "Endpoint mapping exploits.", 
            "remediation": "Block RPC ports at the firewall."
        },
        139: {
            "risk": "Informational", 
            "desc": "NetBIOS Session Service.", 
            "exploit": "Null session attacks.", 
            "remediation": "Disable NetBIOS over TCP/IP."
        }
    }

    for p in ports_list:
        p_num = int(p['port'])
        service = p['name']
        version = f"{p['product']} {p['version']}".strip()
        
        cves = fetch_cves(service, version)
        api_score = calculate_severity(cves)
        api_label = get_severity_label(api_score)
        
        if p_num in PRIORITY_RISKS:
            risk = PRIORITY_RISKS[p_num]['risk']
            description = PRIORITY_RISKS[p_num]['desc']
            exploit = PRIORITY_RISKS[p_num]['exploit']
            remediation = PRIORITY_RISKS[p_num]['remediation']
            if api_label == "Critical": risk = "Critical"
        else:
            risk = api_label
            description = f"Detected {service}."
            exploit = f"Identified {len(cves)} vulnerabilities." if cves else "General service detected."
            remediation = "Update software to the latest version."

        summary[risk] += 1
        analyzed_results.append({
            "port": p_num, "service": service, "version": version or "Unknown",
            "risk": risk, "description": description, "exploit": exploit,
            "remediation": remediation, "cves": cves
        })
    
    return analyzed_results, summary
