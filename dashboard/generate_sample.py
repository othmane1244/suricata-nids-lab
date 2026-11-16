import json, random
from datetime import datetime, timedelta
from pathlib import Path

signatures = [
    ("NIDS - Possible TCP Port Scan Detected (Nmap-like)", 1),
    ("NIDS - SSH Brute Force Attempt Detected", 1),
    ("NIDS - ICMP Flood Detected (possible DoS)", 2),
    ("NIDS - Suspicious User-Agent (Scanning Tool)", 2),
    ("NIDS - Stealth Scan Detected (NULL/FIN/Xmas flags)", 1),
    ("NIDS - FTP Anonymous Login Attempt", 3),
    ("NIDS - Possible Web Login Brute Force", 2),
]
ips = ["192.168.56.10", "192.168.56.10", "192.168.56.10", "192.168.56.15", "192.168.56.99"]

start = datetime(2026, 6, 25, 14, 0, 0)
events = []
for i in range(80):
    ts = start + timedelta(seconds=random.randint(0, 900))
    sig, sev = random.choice(signatures)
    ip = random.choice(ips)
    events.append({
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "event_type": "alert",
        "src_ip": ip,
        "dest_ip": "192.168.56.20",
        "proto": "TCP",
        "alert": {"signature": sig, "severity": sev, "category": "Attempted Recon"}
    })

events.sort(key=lambda e: e["timestamp"])
out_path = Path(__file__).resolve().with_name("sample_eve.json")
with open(out_path, "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"Generated {len(events)} sample alert events -> {out_path}")
