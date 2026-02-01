import subprocess

COMMON_PORTS = ["22", "80", "443", "445", "3389"]

def is_real_host(ip):
    """
    A host is considered REAL only if:
    - It responds on at least one common TCP port
    This filters out ARP-only / fake VM responses
    """

    try:
        cmd = [
            "nmap",
            "-p", ",".join(COMMON_PORTS),
            "--open",
            "-T4",
            ip
        ]

        output = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True
        )

    except subprocess.CalledProcessError:
        return False

    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            return True

    return False
