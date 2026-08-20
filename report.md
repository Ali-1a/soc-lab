# Incident Report: FormBook Malware Detection

## Summary
On 2026-08-09, SIEM alerts flagged repeated FormBook C2 checkin activity from
an internal host. Packet capture analysis confirmed the infection and
identified the affected user and device.

## Indicators of Compromise (IOCs)
| Field | Value |
|---|---|
| Infected IP | 172.16.8.49 |
| MAC Address | 00:12:f0:28:d4:34 |
| Hostname | DESKTOP-5NLV63K |
| Username | rvance (Raymond Vance) |

## C2 Servers Contacted
| Path | Destination IP |
|---|---|
| /ujvq/ | 172.64.155.76 |
| /irpw/ | 146.59.71.167 |
| /lqjm/ | 38.182.168.246 |

## Methodology
1. Filtered traffic with `http.request` and identified repeated POST
   requests to randomized, non-human-readable URL paths — a known FormBook
   C2 pattern used to evade static blocklists.
2. Extracted the source IP (172.16.8.49) and MAC address from the Ethernet
   layer of the malicious POST packets.
3. Identified the hostname via NBNS registration broadcasts
   (`nbns` filter), distinguishing the device-specific name
   (DESKTOP-5NLV63K) from the shared AD environment name (FIRSTTOLAST).
4. Identified the logged-in user via Kerberos AS-REQ packets
   (`kerberos.msg_type == 10`), reading the CNameString field.

## Tools Used
Wireshark, Malware-Traffic-Analysis.net sample pcap

## Analyst Notes
Full name resolution (Raymond Vance) required cross-referencing beyond
the pcap alone — a reminder that not all IOC enrichment is available from
network traffic in isolation.
