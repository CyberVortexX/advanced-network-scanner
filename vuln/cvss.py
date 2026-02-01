def calculate_severity(cve_data):
    if not cve_data: return 0.0
    return max([cve['score'] for cve in cve_data])

def get_severity_label(score):
    if score >= 9.0: return "Critical"
    elif score >= 7.0: return "High"
    elif score >= 4.0: return "Medium"
    elif score > 0: return "Low"
    return "Informational"
