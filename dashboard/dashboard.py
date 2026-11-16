#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 4
Simple alert visualization dashboard for Suricata's eve.json

Parses eve.json and generates 4 charts:
  1. Alerts over time
  2. Alerts by signature (top 10)
  3. Top source IPs
  4. Alerts by severity

Usage:
    python3 dashboard.py --eve /var/log/suricata/eve.json
    python3 dashboard.py --eve sample_eve.json -o report.png    # test with sample data
"""

import argparse
import json
from collections import Counter
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # safe for headless/server use; switch to default backend if you want a live window
import matplotlib.pyplot as plt


def load_alerts(eve_path):
    """Parse an eve.json file (JSON Lines format) and return only alert events."""
    alerts = []
    with open(eve_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def build_dashboard(alerts, output_path):
    if not alerts:
        print("[!] No alerts found in the eve.json file. Nothing to plot.")
        return

    timestamps = []
    signatures = []
    src_ips = []
    severities = []

    for ev in alerts:
        ts_raw = ev.get("timestamp")
        if ts_raw:
            # Suricata timestamps look like 2026-06-25T14:32:01.123456+0000
            try:
                ts = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")
                timestamps.append(ts)
            except ValueError:
                pass
        alert = ev.get("alert", {})
        signatures.append(alert.get("signature", "unknown"))
        severities.append(alert.get("severity", 3))
        if ev.get("src_ip"):
            src_ips.append(ev["src_ip"])

    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle("CodeAlpha NIDS — Suricata Alert Dashboard", fontsize=16, fontweight="bold")

    # --- 1. Alerts over time (binned by minute) ---
    ax = axes[0][0]
    if timestamps:
        timestamps.sort()
        bins = Counter(ts.strftime("%H:%M") for ts in timestamps)
        labels = list(bins.keys())
        values = list(bins.values())
        ax.bar(labels, values, color="#e74c3c")
        ax.set_title("Alerts Over Time")
        ax.set_xlabel("Time (HH:MM)")
        ax.set_ylabel("Alert count")
        ax.tick_params(axis="x", rotation=45)
    else:
        ax.text(0.5, 0.5, "No timestamp data", ha="center")

    # --- 2. Top 10 alert signatures ---
    ax = axes[0][1]
    sig_counts = Counter(signatures).most_common(10)
    if sig_counts:
        labels = [s[:35] for s, _ in sig_counts]
        values = [c for _, c in sig_counts]
        ax.barh(labels[::-1], values[::-1], color="#3498db")
        ax.set_title("Top Alert Signatures")
        ax.set_xlabel("Count")

    # --- 3. Top source IPs ---
    ax = axes[1][0]
    ip_counts = Counter(src_ips).most_common(10)
    if ip_counts:
        labels = [ip for ip, _ in ip_counts]
        values = [c for _, c in ip_counts]
        ax.barh(labels[::-1], values[::-1], color="#e67e22")
        ax.set_title("Top Source IPs")
        ax.set_xlabel("Alert count")
    else:
        ax.text(0.5, 0.5, "No source IP data", ha="center")

    # --- 4. Alerts by severity ---
    ax = axes[1][1]
    sev_counts = Counter(severities)
    sev_labels = {1: "1 - High", 2: "2 - Medium", 3: "3 - Low"}
    labels = [sev_labels.get(s, str(s)) for s in sorted(sev_counts)]
    values = [sev_counts[s] for s in sorted(sev_counts)]
    colors = {"1 - High": "#c0392b", "2 - Medium": "#f39c12", "3 - Low": "#27ae60"}
    bar_colors = [colors.get(l, "#7f8c8d") for l in labels]
    ax.pie(values, labels=labels, autopct="%1.0f%%", colors=bar_colors, startangle=90)
    ax.set_title("Alerts by Severity")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(output_path, dpi=150)
    print(f"[*] Dashboard saved to {output_path}")

    # --- Console summary ---
    print(f"\n=== Summary ===")
    print(f"Total alerts       : {len(alerts)}")
    print(f"Unique signatures  : {len(set(signatures))}")
    print(f"Unique source IPs  : {len(set(src_ips))}")
    print(f"Top signature      : {sig_counts[0][0] if sig_counts else 'n/a'}")
    print(f"Most active source : {ip_counts[0][0] if ip_counts else 'n/a'}")


def main():
    parser = argparse.ArgumentParser(description="Visualize Suricata eve.json alerts.")
    parser.add_argument("--eve", required=True, help="Path to eve.json")
    parser.add_argument("-o", "--output", default="dashboard.png", help="Output image file")
    args = parser.parse_args()

    alerts = load_alerts(args.eve)
    build_dashboard(alerts, args.output)


if __name__ == "__main__":
    main()
