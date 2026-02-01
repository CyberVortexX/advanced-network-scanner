from scapy.all import ARP, Ether, srp

def arp_scan(subnet, iface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(
        packet,
        timeout=2,
        iface=iface,
        verbose=False
    )

    hosts = []
    for _, recv in answered:
        hosts.append({
            "ip": recv.psrc,
            "mac": recv.hwsrc
        })

    return hosts

