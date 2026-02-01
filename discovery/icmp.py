from scapy.all import IP, ICMP, sr1

def icmp_ping(ip):
    packet = IP(dst=ip) / ICMP()
    reply = sr1(packet, timeout=1, verbose=False)

    if reply:
        return {
            "ip": ip,
            "ttl": reply.ttl
        }
    return None
