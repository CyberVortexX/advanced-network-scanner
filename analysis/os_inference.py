def infer_os(open_ports):
    ports = {p["port"] for p in open_ports}

    if {135, 139, 445}.issubset(ports):
        return "Windows (Inferred via SMB/RPC ports)"

    if 3389 in ports:
        return "Windows (RDP detected)"

    if 22 in ports and not ports.intersection({135, 139, 445}):
        return "Linux / Unix (SSH detected)"

    if ports == {80} or ports == {443}:
        return "Web Server (OS not exposed)"

    return "Unknown (Insufficient fingerprinting data)"
