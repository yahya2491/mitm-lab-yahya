# MITM Lab Submission - ARP & DNS Spoofing Attack Demo

This repository demonstrates a complete Man-in-the-Middle (MITM) attack implementation using network namespaces, combining ARP poisoning and DNS spoofing techniques.

## Repository Structure

###  **scripts/**
Network attack tools implemented in Python with Scapy:
- `arp_spoof.py` - ARP cache poisoning tool for MITM positioning
- `dns_spoof.py` - Selective DNS spoofing server with configurable targets
- `web_server.py` - HTTP server for serving spoofed content with request logging

###  **config/**
Attack configuration files:
- `dns_targets.txt` - Target domains for DNS spoofing (supports wildcards)

###  **pcaps/**
Network traffic captures demonstrating the attacks:
- `attack_run_br0.pcap` - Complete attack scenario traffic
- `attacker_attack_run.pcap` - Attacker-side traffic capture
- `dns_spoof_demo.pcap` - DNS spoofing demonstration
- `filtered_victim_gw.pcap` - Victim-gateway filtered traffic

###  **evidence/**
Attack demonstration artifacts:
- `arp_lines.txt` - ARP table modifications evidence
- `victim_dig_example.txt` - DNS query results from victim perspective

###  **parses/**
Traffic analysis and extracted data:
- `dns_queries.csv` - Parsed DNS query logs
- `extracted_urls.csv` - HTTP URLs intercepted during attack
- `top_talkers.txt` - Network communication statistics

###  **www/**
Web content served by spoofed server:
- `index.html` - Fake webpage content

## Requirements
```
Python3
scapy
```

## Usage
Run attack scripts with appropriate network interface and target configurations. See individual script help for detailed options.

**Note:** This is for educational/research purposes in controlled environments only.
