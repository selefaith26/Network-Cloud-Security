# Network Scanner Tool
## Network and Cloud Security Assignment
### Grand Canyon University
#### By Ortasele Aisuan
---

## Overview

This tool scans a target host or network for open ports, identifies the
services running on those ports, and flags potential vulnerabilities based
on known security risks associated with each service.

Network scanning is a fundamental skill in cybersecurity. Security
professionals use port scanning to audit their own systems, identify
exposed services, and prioritize remediation efforts before attackers
can exploit them (Pfleeger, Pfleeger, & Coles-Kemp, 2024). Every open
port that does not need to be open is an attack surface that must be
identified and closed.

---

## Files Included

| File | Purpose |
|---|---|
| network_scanner.py | Main scanner tool — run this |
| README.md | This file |

---

## Requirements

**Step 1 — Install the Python library:**
```
pip install python-nmap
```

**Step 2 — Install nmap binary:**
- Windows: https://nmap.org/download.html (download the installer)
- Mac: brew install nmap
- Linux: sudo apt install nmap

The tool uses python-nmap as the assignment recommends. If the nmap
binary is not installed it automatically falls back to Python's
built-in socket library so it will always run.

---

## How to Run

```
python network_scanner.py
```

An interactive menu will appear:

```
  MENU
  ----------
  1. Scan a target (common ports)
  2. Scan a target (custom port range)
  3. Scan localhost (your own machine)
  4. Exit
```

- Option 1 — scans 25 common ports on any IP or hostname you enter
- Option 2 — scans a custom port range you define
- Option 3 — scans your own machine (127.0.0.1) on ports 1-1024
- Option 4 — exits the program

For a safe legal demo target use: scanme.nmap.org
This is a server Nmap provides specifically for practice scanning.

---

## What the Output Shows

For each open port the tool displays:
- Port number
- Service name (HTTP, SSH, RDP, MySQL, etc.)
- Banner (service version if detectable)
- Risk level and remediation guidance

Summary table at the end shows all open ports and their risk levels.

---

## Risk Levels

| Level | Meaning |
|---|---|
| CRITICAL | Immediate threat — possible active compromise |
| HIGH | Serious misconfiguration requiring urgent attention |
| MEDIUM | Moderate risk that should be reviewed |
| LOW | Low risk but worth monitoring |
| Clean | No known vulnerability hints for this port |

---

## About the Known Services

Service names for each port number are based on the official IANA
Service Name and Transport Protocol Port Number Registry (IANA, n.d.),
which maintains the globally recognized standard mapping of port
numbers to their assigned services. For example port 80 is officially
assigned to HTTP, port 443 to HTTPS, and port 22 to SSH — all defined
and maintained by IANA as the authoritative global standard.

---

## About the Vulnerability Hints

The vulnerability risk levels and remediation guidance in this tool
are based on well-documented security risks associated with each
service and port. Specific risks such as SMB being the attack vector
for WannaCry, RDP being a common ransomware entry point, and Telnet
transmitting credentials in plaintext are widely documented in
cybersecurity literature and vulnerability databases.

Sources used for vulnerability information:

- IANA Service Name and Port Number Registry (IANA, n.d.)
- NIST National Vulnerability Database (NIST, n.d.)
- SANS Institute common port security references (SANS Institute, n.d.)
- Pfleeger, Pfleeger, and Coles-Kemp (2024) — Security in Computing
- Stallings (2020) — Computer Security: Principles and Practice
- Nmap Project (n.d.) — Nmap: The Network Mapper

---

## Important Note

Only scan systems you own or have explicit written permission to scan.
This tool is for educational purposes as part of a university course assignment.

---

## Academic References

Internet Assigned Numbers Authority. (n.d.). Service name and transport
    protocol port number registry.
    https://www.iana.org/assignments/service-names-port-numbers/
    service-names-port-numbers.xhtml

National Institute of Standards and Technology. (n.d.). National
    Vulnerability Database. U.S. Department of Commerce.
    https://nvd.nist.gov

Pfleeger, C., Lawrence Pfleeger, S., & Coles-Kemp, L. (2024).
    Security in computing (6th ed.). Pearson.

SANS Institute. (n.d.). Common ports reference.
    https://www.sans.org/security-resources/sec560/
    netcat_cheat_sheet_v1.pdf

Stallings, W. (2020). Computer security: Principles and practice
    (4th ed.). Pearson.
    https://lopes.idm.oclc.org/login?url=https://www.pearson.com/en-us/
    subject-catalog/p/computer-security-principles-and-practice/P200000003293

Nmap Project. (n.d.). Nmap: The network mapper.
    https://nmap.org