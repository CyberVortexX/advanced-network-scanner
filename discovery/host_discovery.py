import subprocess
import ipaddress

def discover_hosts(target):
    """
    Discover live hosts using:
    - ARP scan for local networks
    - ICMP ping for single IPs

    Returns ONLY confirmed alive hosts.
    """

    alive_hosts = []

    try:
        # ---------- CASE 1: CIDR / RANGE ----------
        if "/" in target:
            # ARP scan (most reliable on LAN)
            cmd = ["nmap", "-sn", "-PR", target]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()

            current_ip = None
            for line in output.splitlines():
                if line.startswith("Nmap scan report for"):
                    current_ip = line.split()[-1]
                elif "Host is up" in line and current_ip:
                    alive_hosts.append(current_ip)
                    current_ip = None

        # ---------- CASE 2: SINGLE IP ----------
        else:
            cmd = ["nmap", "-sn", "-PE", target]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()

            if "Host is up" in output:
                alive_hosts.append(target)

    except Exception as e:
        return []

    return alive_hosts
