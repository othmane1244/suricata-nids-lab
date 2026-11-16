#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 4
Automated Response Mechanism for detected intrusions

Tails Suricata's eve.json log in real time, and when the same source IP
triggers a high-severity alert repeatedly within a short window, blocks
that IP with iptables (Linux) — implementing the "response mechanism for
detected intrusions" required by the task.

Runs in --dry-run mode by default so you can validate behaviour safely
before actually blocking traffic.

Usage:
    sudo python3 auto_block.py --eve /var/log/suricata/eve.json
    sudo python3 auto_block.py --eve /var/log/suricata/eve.json --no-dry-run
    sudo python3 auto_block.py --eve /var/log/suricata/eve.json --threshold 3 --window 60
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict, deque

# Severity 1 = highest priority in Suricata's classtype scoring.
# We only auto-respond to severity 1/2 alerts to avoid over-blocking on noise.
RESPOND_TO_SEVERITY = {1, 2}

blocked_ips = set()


def follow(filepath):
    """Generator that yields new lines appended to a file (like `tail -f`)."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def block_ip(ip, dry_run=True):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)

    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        print(f"[DRY-RUN] Would block {ip}: {' '.join(cmd)}")
        return

    try:
        subprocess.run(cmd, check=True)
        print(f"[BLOCKED] {ip} added to iptables DROP rules")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block {ip}: {e}", file=sys.stderr)
    except FileNotFoundError:
        print("[!] iptables not found. Run this on a Linux sensor with root.", file=sys.stderr)


def unblock_ip(ip, dry_run=True):
    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        print(f"[DRY-RUN] Would unblock {ip}: {' '.join(cmd)}")
        return
    subprocess.run(cmd, check=False)
    blocked_ips.discard(ip)
    print(f"[UNBLOCKED] {ip}")


def main():
    parser = argparse.ArgumentParser(description="Auto-response to Suricata alerts (eve.json)")
    parser.add_argument("--eve", required=True, help="Path to Suricata's eve.json")
    parser.add_argument("--threshold", type=int, default=3, help="Alerts from same IP before blocking")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds for the threshold")
    parser.add_argument("--no-dry-run", action="store_true", help="Actually run iptables (default: simulate only)")
    args = parser.parse_args()

    dry_run = not args.no_dry_run
    mode = "DRY-RUN (simulation)" if dry_run else "LIVE (will modify iptables)"
    print(f"=== CodeAlpha NIDS Auto-Response ===")
    print(f"Watching: {args.eve}")
    print(f"Mode: {mode}")
    print(f"Threshold: {args.threshold} alerts / {args.window}s per source IP\n")

    # source_ip -> deque of alert timestamps (as floats)
    alert_history = defaultdict(deque)

    try:
        for line in follow(args.eve):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            severity = alert.get("severity", 3)
            src_ip = event.get("src_ip")
            signature = alert.get("signature", "unknown")

            if not src_ip or severity not in RESPOND_TO_SEVERITY:
                continue

            now = time.time()
            history = alert_history[src_ip]
            history.append(now)

            # Drop timestamps outside the sliding window
            while history and now - history[0] > args.window:
                history.popleft()

            print(f"[ALERT] {src_ip} -> {signature} (severity={severity}, "
                  f"{len(history)}/{args.threshold} in window)")

            if len(history) >= args.threshold:
                block_ip(src_ip, dry_run=dry_run)

    except FileNotFoundError:
        print(f"[!] File not found: {args.eve}. Is Suricata running and eve.json enabled?", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
        if blocked_ips:
            print(f"[*] IPs blocked this session: {', '.join(blocked_ips)}")
            print("[*] To unblock manually: sudo iptables -D INPUT -s <ip> -j DROP")


if __name__ == "__main__":
    main()
