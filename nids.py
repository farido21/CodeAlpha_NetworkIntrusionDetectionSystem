#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 4
Network Intrusion Detection System (NIDS)

A lightweight, rule-based NIDS built with Scapy. It sniffs live traffic (or
reads a pcap file), applies a set of detection rules (port scan, SYN flood,
ICMP flood, blacklisted IPs, suspicious payload signatures), raises alerts,
and logs them to a JSON-lines file that dashboard.py can visualize.

IMPORTANT / LEGAL NOTICE
-------------------------
Only run this on networks and systems you own or have explicit written
permission to monitor. Unauthorized packet capture may be illegal.

Usage:
    sudo python3 nids.py --iface eth0
    sudo python3 nids.py --pcap sample_traffic.pcap
"""

import argparse
import json
import time
import sys
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, TCP, ICMP, Raw
except ImportError:
    print("Scapy is required. Install with: pip install scapy")
    sys.exit(1)


class AlertLogger:
    """Writes structured alerts to console and a JSON-lines log file."""

    def __init__(self, log_path="alerts.log"):
        self.log_path = log_path

    def raise_alert(self, alert_type, source_ip, details, severity="medium"):
        record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "type": alert_type,
            "source_ip": source_ip,
            "details": details,
            "severity": severity,
        }
        line = json.dumps(record)
        print(f"[ALERT] {record['timestamp']} | {severity.upper():6} | "
              f"{alert_type} | src={source_ip} | {details}")
        with open(self.log_path, "a") as f:
            f.write(line + "\n")


class RuleEngine:
    """Holds sliding-window state and evaluates each packet against the
    rules defined in rules.json."""

    def __init__(self, rules_path, logger: AlertLogger):
        with open(rules_path) as f:
            self.rules = json.load(f)
        self.logger = logger

        # sliding-window trackers: ip -> deque of timestamps / ports
        self.port_hits = defaultdict(lambda: deque())      # port scan
        self.syn_hits = defaultdict(lambda: deque())        # syn flood
        self.icmp_hits = defaultdict(lambda: deque())       # icmp flood

        self.blacklist = set(self.rules.get("blacklisted_ips", []))
        self.signatures = [s.lower() for s in
                            self.rules.get("suspicious_payload_signatures", [])]

        # avoid re-alerting every single packet once a threshold is hit
        self._cooldown = defaultdict(lambda: 0.0)
        self._cooldown_seconds = 10

    def _on_cooldown(self, key, now):
        if now - self._cooldown[key] < self._cooldown_seconds:
            return True
        self._cooldown[key] = now
        return False

    def _prune(self, dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()

    def process(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        now = time.time()

        # --- Blacklisted IP ---
        if src in self.blacklist:
            key = ("blacklist", src)
            if not self._on_cooldown(key, now):
                self.logger.raise_alert(
                    "Blacklisted IP traffic", src,
                    f"Traffic seen from blacklisted address {src}",
                    severity="high",
                )

        # --- Port scan detection (distinct destination ports per source) ---
        if self.rules["port_scan"]["enabled"] and TCP in pkt:
            dport = pkt[TCP].dport
            dq = self.port_hits[src]
            dq.append((now, dport))
            window = self.rules["port_scan"]["time_window_seconds"]
            while dq and now - dq[0][0] > window:
                dq.popleft()
            distinct_ports = {p for _, p in dq}
            if len(distinct_ports) >= self.rules["port_scan"]["distinct_ports_threshold"]:
                key = ("portscan", src)
                if not self._on_cooldown(key, now):
                    self.logger.raise_alert(
                        "Possible port scan", src,
                        f"{len(distinct_ports)} distinct ports probed in "
                        f"{window}s",
                        severity="high",
                    )

        # --- SYN flood detection ---
        if self.rules["syn_flood"]["enabled"] and TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02 and not flags & 0x10:  # SYN set, ACK not set
                dq = self.syn_hits[src]
                dq.append(now)
                window = self.rules["syn_flood"]["time_window_seconds"]
                self._prune(dq, now, window)
                if len(dq) >= self.rules["syn_flood"]["syn_count_threshold"]:
                    key = ("synflood", src)
                    if not self._on_cooldown(key, now):
                        self.logger.raise_alert(
                            "Possible SYN flood", src,
                            f"{len(dq)} SYN packets in {window}s",
                            severity="high",
                        )

        # --- ICMP flood detection ---
        if self.rules["icmp_flood"]["enabled"] and ICMP in pkt:
            dq = self.icmp_hits[src]
            dq.append(now)
            window = self.rules["icmp_flood"]["time_window_seconds"]
            self._prune(dq, now, window)
            if len(dq) >= self.rules["icmp_flood"]["icmp_count_threshold"]:
                key = ("icmpflood", src)
                if not self._on_cooldown(key, now):
                    self.logger.raise_alert(
                        "Possible ICMP flood / ping sweep", src,
                        f"{len(dq)} ICMP packets in {window}s",
                        severity="medium",
                    )

        # --- Suspicious payload signature match ---
        if Raw in pkt and self.signatures:
            try:
                payload = bytes(pkt[Raw].load).decode(errors="ignore").lower()
            except Exception:
                payload = ""
            for sig in self.signatures:
                if sig in payload:
                    key = ("payload", src, sig)
                    if not self._on_cooldown(key, now):
                        self.logger.raise_alert(
                            "Suspicious payload signature", src,
                            f"Matched signature: '{sig}'",
                            severity="medium",
                        )
                    break


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Task 4 - NIDS")
    parser.add_argument("--iface", help="Network interface to sniff live traffic from")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze instead of live sniffing")
    parser.add_argument("--rules", default="rules.json", help="Path to rules JSON file")
    parser.add_argument("--log", default="alerts.log", help="Path to alerts output log")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    logger = AlertLogger(args.log)
    engine = RuleEngine(args.rules, logger)

    print("=" * 60)
    print(" CodeAlpha Task 4 - Network Intrusion Detection System")
    print("=" * 60)

    if args.pcap:
        print(f"[*] Reading packets from pcap file: {args.pcap}")
        packets = rdpcap(args.pcap)
        for pkt in packets:
            engine.process(pkt)
        print(f"[*] Done. Processed {len(packets)} packets. "
              f"See {args.log} for alerts.")
    else:
        iface = args.iface
        print(f"[*] Sniffing live traffic on interface: {iface or 'default'}")
        print("[*] Press Ctrl+C to stop.")
        try:
            sniff(iface=iface, prn=engine.process, store=False, count=args.count)
        except PermissionError:
            print("[!] Permission denied. Try running with sudo/administrator rights.")
        except KeyboardInterrupt:
            print("\n[*] Stopped by user.")


if __name__ == "__main__":
    main()
