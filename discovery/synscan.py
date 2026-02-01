from scapy.all import IP, TCP, sr1

def syn_scan(ip, ports, iface=None):
    open_ports = []

    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=0.5, iface=iface, verbose=False)

        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                open_ports.append(port)

    return open_ports
