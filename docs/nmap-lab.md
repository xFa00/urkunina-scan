# Nmap Reconnaissance Lab

## Objective

The objective of this laboratory is to understand the fundamentals of network reconnaissance with Nmap and document how Urkunina Scan uses Nmap as its initial network discovery engine.

This lab focuses on:

- Host discovery
- Port scanning
- Port states
- Service detection
- Version detection
- XML output
- Structured security data

The goal is not only to execute commands, but to understand the information produced by Nmap and how that information can later be processed by Urkunina.

---

## Environment

Operating system:

```text
macOS
```
Authorized public target provided by the Nmap project.

## Commands:

### Basic scan

nmap scanme.nmap.org

### Service and version detection

nmap -sV scanme.nmap.org

### Scan selected ports

nmap -p 22,80,443 -sV scanme.nmap.org

### Export XML

nmap -sV -oX scan.xml scanme.nmap.org

### Results

22/tcp   open      ssh         OpenSSH
80/tcp   open      http        Apache httpd
161/tcp  filtered  snmp
9929/tcp open      nping-echo  Nping echo

### Urkunina Integration

Target
  ↓
Nmap
  ↓
XML
  ↓
Python parser
  ↓
JSON

The parser extracts information such as:
- IP
- Host status
- Ports
- Protocol
- State
- Service
- Product
- Version

### Example JSON

{
  "target": "scanme.nmap.org",
  "host": {
    "ip": "45.33.32.156",
    "status": "up"
  },
  "summary": {
    "open": 3,
    "filtered": 1,
    "closed": 996,
    "total_ports_scanned": 1000
  }
}

## Security

Only scan systems that you own or have explicit authorization to test. 