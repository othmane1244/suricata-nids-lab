# Attack Scenarios — Test Plan for NIDS Validation

CodeAlpha Cybersecurity Internship — Task 4: NIDS

Lab topology: one attacker VM (Kali), one victim/sensor VM running Suricata in AF_PACKET mode,
both on an **isolated** VirtualBox internal network (`192.168.56.0/24`, no internet-facing
interface).

> ⚠️ **Lab only.** Every command below targets `192.168.56.20`, the lab victim VM. Never run
> these scans, brute-force or flood tests against systems you do not own or are not explicitly
> authorized to test.

For each scenario: run the attack from the **attacker VM**, then check
`/var/log/suricata/eve.json` on the **sensor VM** for the corresponding alert.

```bash
# On the sensor VM, watch alerts live in another terminal:
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

## Scenario 1 — TCP Port Scan (sid 1000001)

```bash
# On Kali (attacker):
nmap -sS -p 1-1000 192.168.56.20
```
**Expected alert:** `NIDS - Possible TCP Port Scan Detected (Nmap-like)`

## Scenario 2 — Stealth Scan (sid 1000002)

```bash
nmap -sN -p 1-200 192.168.56.20    # NULL scan
nmap -sX -p 1-200 192.168.56.20    # Xmas scan
```
**Expected alert:** `NIDS - Stealth Scan Detected (NULL/FIN/Xmas flags)`

## Scenario 3 — SSH Brute Force (sid 1000003)

With Hydra (lab VM, test account only):
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20
```
**Expected alert:** `NIDS - SSH Brute Force Attempt Detected` (after 5 SYN/min to port 22 from the same source)

## Scenario 4 — ICMP Flood (sid 1000004)

```bash
sudo hping3 --icmp -i u1000 192.168.56.20    # ~1000 pings/sec, lab only!
```
**Expected alert:** `NIDS - ICMP Flood Detected (possible DoS)`

⚠️ Run this for a few seconds only — it's a denial-of-service test, even on your own lab VM it can make the victim briefly unresponsive.

## Scenario 5 — Suspicious User-Agent (sid 1000005, 1000006)

```bash
nmap --script http-title 192.168.56.20 -p 80     # Nmap's HTTP probe sets its own User-Agent
curl http://192.168.56.20/                        # default curl User-Agent
```
**Expected alert:** `NIDS - Suspicious User-Agent (Scanning Tool)` or `(curl/wget automated tool)`

## Scenario 6 — Web Login Brute Force (sid 1000007)

If the victim VM runs a simple web login form (or use a quick `python3 -m http.server` + a small test script that POSTs repeatedly):
```bash
for i in $(seq 1 20); do
  curl -s -X POST http://192.168.56.20/login -d "user=admin&pass=test$i" > /dev/null
done
```
**Expected alert:** `NIDS - Possible Web Login Brute Force`

## Scenario 7 — FTP Anonymous Login (sid 1000008)

```bash
ftp 192.168.56.20
# Username: anonymous
```
**Expected alert:** `NIDS - FTP Anonymous Login Attempt`

## Scenario 8 — ARP scan (sid 1000010, currently disabled)

> The ARP rule is commented out in `suricata/custom.rules`: Suricata 7.0.3 rejects its
> `ether` / `ether.hdr` syntax. This scenario is kept for reference until the rule is rewritten.

```bash
sudo nmap -sn -PR 192.168.56.0/24    # ARP ping sweep
# or
sudo arp-scan --localnet
```
**Expected alert (once the rule is fixed):** `NIDS - Abnormal ARP Traffic Volume`. See also the caveat in `suricata/custom.rules` about `track by_src` on non-IP traffic.

---

## Validation checklist

| Scenario | sid | Triggered? | Notes |
|---|---|---|---|
| TCP Port Scan | 1000001 | ☐ | |
| Stealth Scan | 1000002 | ☐ | |
| SSH Brute Force | 1000003 | ☐ | |
| ICMP Flood | 1000004 | ☐ | |
| Suspicious UA | 1000005/6 | ☐ | |
| Web Login Brute Force | 1000007 | ☐ | |
| FTP Anonymous | 1000008 | ☐ | |
| ARP Scan | 1000010 | — | rule disabled (see above) |

Results are **not recorded yet** in this repository. Fill this table with your own lab results,
and keep screenshots of the matching `eve.json` alerts as evidence.
