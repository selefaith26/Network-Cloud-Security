"""
Network and Cloud Security Assignment

How to run:
    python network_scanner.py

"""

import socket
import datetime
import concurrent.futures

#  NMAP IMPORT

try:
    import nmap
    NMAP_AVAILABLE = True
    print("[+] python-nmap loaded successfully.")
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] python-nmap not found. Run: pip install python-nmap")
    print("    Falling back to socket scanning.\n")


#  KNOWN SERVICES

KNOWN_SERVICES = {
    20:    "FTP Data",
    21:    "FTP Control",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "MS RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MS SQL Server",
    1521:  "Oracle DB",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP Alternate",
    8443:  "HTTPS Alternate",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}


#  VULNERABILITY HINTS

VULNERABILITY_HINTS = {
    21:    ("MEDIUM",   "FTP transmits credentials in plaintext. Replace with SFTP."),
    22:    ("LOW",      "SSH is secure but enforce key-based auth and disable passwords."),
    23:    ("HIGH",     "Telnet transmits all data in plaintext. Should be disabled."),
    25:    ("MEDIUM",   "SMTP open relay can be exploited for spam."),
    80:    ("LOW",      "HTTP is unencrypted. Use HTTPS on port 443 instead."),
    135:   ("HIGH",     "MS RPC has a history of critical vulnerabilities."),
    139:   ("HIGH",     "NetBIOS is outdated and exposes system information."),
    445:   ("HIGH",     "SMB is the attack vector for EternalBlue and WannaCry."),
    1433:  ("HIGH",     "MS SQL Server exposed to network. Restrict to trusted IPs."),
    3306:  ("HIGH",     "MySQL exposed to network. Restrict to localhost only."),
    3389:  ("HIGH",     "RDP is a frequent ransomware entry point. Use a VPN."),
    4444:  ("CRITICAL", "Port 4444 is the default Metasploit listener - possible compromise."),
    5432:  ("HIGH",     "PostgreSQL exposed to network. Restrict to trusted IPs."),
    5900:  ("HIGH",     "VNC is often unencrypted. Use SSH tunneling."),
    6379:  ("HIGH",     "Redis exposed to network - full data access possible."),
    8080:  ("LOW",      "HTTP alternate port. Verify no sensitive services are exposed."),
    9200:  ("HIGH",     "Elasticsearch exposed - often misconfigured with no authentication."),
    27017: ("HIGH",     "MongoDB exposed to network. Verify authentication is enabled."),
}

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 1521, 3306, 3389, 4444,
    5432, 5900, 6379, 8080, 8443, 9200, 27017
]


#  CORE FUNCTIONS

def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port_socket(ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(ip, port, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()
        return banner.split("\n")[0][:100] if banner else None
    except Exception:
        return None


def get_service(port):
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "Unknown"


def socket_scan(ip, ports, timeout=1.0):
    open_ports = []

    def check(port):
        if scan_port_socket(ip, port, timeout):
            open_ports.append(port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(check, ports)

    return sorted(open_ports)


def nmap_scan(ip, ports):
    try:
        nm = nmap.PortScanner()
        port_range = ",".join(str(p) for p in ports)
        print(f"  Running nmap scan on {ip}...")
        nm.scan(ip, port_range, arguments="-sV --open -T4")
        return nm
    except Exception as e:
        print(f"  [!] Nmap error: {e}")
        print("  [!] Make sure nmap is installed from https://nmap.org/download.html")
        return None


#  OUTPUT FUNCTIONS

def print_result(port, service, banner, vuln_severity, vuln_message):
    print(f"\n  Port     : {port}")
    print(f"  Service  : {service}")
    print(f"  Status   : OPEN")
    if banner:
        print(f"  Banner   : {banner}")
    if vuln_severity:
        print(f"  Risk     : [{vuln_severity}] {vuln_message}")
    else:
        print(f"  Risk     : No known vulnerability hints for this port")
    print(f"  ----------")


def print_summary(target, ip, open_ports, scan_time):
    print(f"\n  {'='*54}")
    print(f"  SCAN SUMMARY")
    print(f"  {'='*54}")
    print(f"  Target     : {target}")
    print(f"  IP Address : {ip}")
    print(f"  Open Ports : {len(open_ports)}")
    print(f"  Scan Time  : {scan_time:.2f} seconds")
    print(f"  Timestamp  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {'─'*54}")

    if open_ports:
        print(f"  {'Port':<10} {'Service':<20} {'Risk'}")
        print(f"  {'─'*54}")
        for port in open_ports:
            service = get_service(port)
            sev, _ = VULNERABILITY_HINTS.get(port, (None, None))
            risk = sev if sev else "Clean"
            print(f"  {str(port):<10} {service:<20} {risk}")
    else:
        print(f"  No open ports found in the scanned range.")

    print(f"  {'='*54}\n")


#  MAIN SCAN FUNCTION

def run_scan(target, ports):
    print(f"\n  Resolving {target}...")
    ip = resolve_host(target)

    if not ip:
        print(f"  [!] Could not resolve '{target}'.")
        return

    print(f"  Resolved to: {ip}")
    print(f"  Scanning {len(ports)} ports...")
    print(f"  ----------")

    start = datetime.datetime.now()
    open_ports = []

    if NMAP_AVAILABLE:
        nm = nmap_scan(ip, ports)
        if nm and ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in sorted(nm[ip][proto].keys()):
                    if nm[ip][proto][port]["state"] == "open":
                        open_ports.append(port)
                        product = nm[ip][proto][port].get("product", "")
                        version = nm[ip][proto][port].get("version", "")
                        service = f"{product} {version}".strip() or get_service(port)
                        sev, msg = VULNERABILITY_HINTS.get(port, (None, None))
                        print_result(port, service, None, sev, msg)
        else:
            print("  [!] Nmap binary not found. Falling back to socket scan.")
            print("  Install nmap from https://nmap.org/download.html\n")
            open_ports = socket_scan(ip, ports)
            for port in open_ports:
                service = get_service(port)
                banner = grab_banner(ip, port)
                sev, msg = VULNERABILITY_HINTS.get(port, (None, None))
                print_result(port, service, banner, sev, msg)
    else:
        open_ports = socket_scan(ip, ports)
        for port in open_ports:
            service = get_service(port)
            banner = grab_banner(ip, port)
            sev, msg = VULNERABILITY_HINTS.get(port, (None, None))
            print_result(port, service, banner, sev, msg)

    end = datetime.datetime.now()
    scan_time = (end - start).total_seconds()
    print_summary(target, ip, open_ports, scan_time)


#  MAIN

def main():
    print("\n  NETWORK SCANNER TOOL")
    print("  Network and Cloud Security Assignment")
    print("  ----------")
    print(f"  nmap library : {'READY' if NMAP_AVAILABLE else 'NOT INSTALLED'}")
    print(f"  ----------\n")

    while True:
        print("  MENU")
        print("  ----------")
        print("  1. Scan a target (common ports)")
        print("  2. Scan a target (custom port range)")
        print("  3. Scan localhost (your own machine)")
        print("  4. Exit")
        print()

        choice = input("  Enter choice: ").strip()

        if choice == "1":
            target = input("  Enter target IP or hostname: ").strip()
            run_scan(target, COMMON_PORTS)

        elif choice == "2":
            target = input("  Enter target IP or hostname: ").strip()
            try:
                start_port = int(input("  Start port: ").strip())
                end_port   = int(input("  End port:   ").strip())
                run_scan(target, list(range(start_port, end_port + 1)))
            except ValueError:
                print("  [!] Invalid port number. Please enter integers only.")

        elif choice == "3":
            print("\n  Scanning localhost (127.0.0.1)...")
            run_scan("127.0.0.1", list(range(1, 1025)))

        elif choice == "4":
            print("\n  Exiting. Goodbye.\n")
            break

        else:
            print("  [!] Invalid choice. Please enter 1-4.")
        print()


if __name__ == "__main__":
    main()