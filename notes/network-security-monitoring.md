# Network Security Monitoring

Monitoring the network perimeter and traffic for the footprints of attacks: network discovery, data exfiltration, man-in-the-middle, and detecting them with an IDS (Snort).

## Network Security Essentials

- **Defence in depth:** no single control stops everything; layer perimeter, network, host and data controls.
- Key perimeter devices: **firewall** (allow/deny by rule), **proxy** (inspects and logs web traffic), **IDS/IPS** (detects / blocks known-bad patterns), **VPN** (encrypted remote access).
- A SOC analyst reads the logs these devices produce, so knowing what each one records is the point.

## Network Discovery Detection

How attackers map a network before attacking, and the traffic it leaves.

- **Host discovery:** ICMP (ping) sweeps, ARP scans — many requests to sequential IPs from one source.
- **Port scanning (Nmap):** many connection attempts to different ports on a host.
  - **SYN scan:** lots of SYN packets with no completed handshake (`tcp.flags.syn == 1 && tcp.flags.ack == 0`).
  - A single source touching many ports or many hosts in a short time is the signature.
- Detection idea: one internal or external IP generating an unusual fan-out of connections is reconnaissance (maps to **Reconnaissance** in Kill Chain / ATT&CK).

## Data Exfiltration Detection

How stolen data leaves the network, and the channels to watch.

| Channel | What to look for |
|---|---|
| **DNS tunnelling** | Unusually long or high-entropy subdomains, many TXT queries, high volume of DNS to one domain |
| **HTTP/HTTPS** | Large POST uploads to an unusual destination, odd User-Agent, data in the URL |
| **ICMP tunnelling** | Ping packets with large or data-filled payloads |
| **Cloud / web services** | Large transfers to Dropbox, Google Drive, pastebin, etc. |

- Baseline matters: exfiltration is usually **outbound volume that is abnormal for that host or time**.
- Maps to **Exfiltration** (ATT&CK TA0010): e.g. Exfiltration Over C2 Channel, Exfiltration Over Web Service.

## Man-in-the-Middle (MITM) Detection

- An attacker sits between two hosts and intercepts/alters traffic.
- Most common on a LAN via **ARP spoofing / poisoning**: the attacker tells victims that the attacker's MAC owns the gateway's IP.
- **Footprint in traffic:** two different MAC addresses claiming the same IP, a flood of unsolicited ARP replies, duplicate-IP warnings. Wireshark: `arp.duplicate-address-detected`.
- Result: the attacker can read/modify traffic, strip TLS, or harvest credentials.

## IDS Fundamentals + Snort

- **IDS (Intrusion Detection System):** detects and alerts on suspicious traffic. **IPS** also blocks it.
- **Detection methods:**
  - **Signature-based:** matches known-bad patterns (fast, misses new attacks).
  - **Anomaly-based:** flags deviations from a baseline (catches new attacks, more false positives).
- **Placement:** NIDS watches network traffic; HIDS watches a single host.
- **Snort** is an open-source signature-based IDS/IPS. It reads rules and alerts when traffic matches.
  - Modes: sniffer, packet logger, and NIDS (rules).
  - A rule has an **action**, protocol, source/dest, and **options** (`msg`, `content`, `sid`, etc.).

## Connections to my own work

- The signature-vs-substring lesson is real: in a [LetsDefend alert I triaged](../README.md), a rule fired on `ls` inside the word "ski**ls**" — a **false positive** from a signature matching a plain substring. Good detection rules match a command *pattern* (`?cmd=ls`, `;ls`, `/bin/ls`), not the bare string.
- The POST-to-C2 pattern in my [FormBook investigation](../report.md) is exactly the kind of HTTP exfiltration/C2 footprint this module teaches to spot.

## Takeaways

1. Every attack phase leaves a traffic footprint; monitoring is about knowing the normal baseline so the abnormal stands out.
2. Signature IDS is fast but literal — it needs tuning, and the analyst decides whether a match is a real threat.
3. The analyst's edge over the tool is **context**: a match is not a verdict.
