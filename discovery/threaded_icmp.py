from concurrent.futures import ThreadPoolExecutor
from discovery.icmp import icmp_ping

def threaded_icmp_scan(ips, workers=50):
    live_hosts = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(icmp_ping, ips)

    for res in results:
        if res:
            live_hosts.append(res)

    return live_hosts
