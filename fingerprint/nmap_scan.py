import nmap

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def discover_hosts(self, target_range):
        """Phase 1: Discovery. OS scanning (-O) has been removed."""
        try:
            # Removed -O flag. Now using -sn for simple ping sweep
            # If -Pn is needed for firewalls, use: '-sn -Pn'
            discovery_args = '-sn'
            
            self.nm.scan(hosts=target_range, arguments=discovery_args)
            active_hosts = []
            
            for host in self.nm.all_hosts():
                active_hosts.append({
                    "ip": host,
                    "hostname": self.nm[host].hostname() or "Unknown Device",
                    "os": "Disabled" # Placeholder to avoid breaking the UI
                })
            return active_hosts
        except Exception as e:
            return {"error": str(e)}

    def run_deep_scan(self, target_ip, mode):
        """Phase 2: Deep Scan. Ensuring OS detection is not triggered."""
        # Removed all -O flags from scan modes
        scan_modes = {
            "quick": "-T4 -F -sV -Pn --open",
            "full": "-T3 -p 1-65535 -sV -Pn --open",
            "stealth": "-T2 -sS -Pn -sV --open"
        }
        args = scan_modes.get(mode, "-T3 -sV -Pn --open")
        
        try:
            self.nm.scan(hosts=target_ip, arguments=args)
            if target_ip in self.nm.all_hosts():
                return [self.nm[target_ip]]
            return []
        except Exception as e:
            return {"error": str(e)}
