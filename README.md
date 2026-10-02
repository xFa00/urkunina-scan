# Urkunina Scan

Urkunina Scan is the first component of the Urkunina project.

Its goal is to provide a simple and accessible way to perform authorized
network discovery and transform raw security scanner output into structured,
usable data.

> Current version: v0.1 — Network Discovery

## Current Features

- Accepts an IPv4, IPv6 address, or domain as a target
- Validates user input before scanning
- Executes Nmap automatically
- Performs service and version detection
- Parses Nmap XML output
- Extracts:
  - Host status
  - IP address
  - Ports
  - Protocols
  - Port states
  - Services
  - Products
  - Versions
- Generates structured JSON output
- Provides scan metadata
- Provides a summary of:
  - Open ports
  - Filtered ports
  - Closed ports
  - Total ports scanned
- Basic error handling

## Requirements

- Python 3
- Nmap

Check Nmap installation:

```bash
nmap --version