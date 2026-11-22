# Wireshark & Snort Cheatsheet

A short, practical reference for network traffic analysis. The goal is not to memorise everything — it is to know the core filters and the *logic* to build the rest.

## Wireshark display filters

### By address
```
ip.addr == 10.0.0.5          # anything to or from this IP
ip.src == 10.0.0.5           # from this IP only
ip.dst == 10.0.0.5           # to this IP only
```

### By port / protocol
```
tcp.port == 443              # traffic on a port (either direction)
udp.port == 53
http                         # all HTTP
dns                          # all DNS
tls                          # all TLS/SSL
arp                          # all ARP
```

### Useful for investigations
```
http.request.method == "POST"      # uploads — watch for exfiltration
http.request.method == "GET"
dns.qry.name contains "evil"       # DNS queries for a domain
frame contains "password"          # any packet containing a string
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scan footprint
arp.duplicate-address-detected     # possible MITM / ARP spoofing
icmp                               # ping sweeps / ICMP tunnelling
```

### Combine conditions
```
&&   and        ||   or        !   not
ip.addr == 10.0.0.5 && tcp.port == 443
http && !(ip.addr == 10.0.0.5)
```

### The logic (so you never memorise the whole list)
- A filter is `protocol.field == value`.
- Forgot a field name? Click the field inside a packet — Wireshark shows the exact filter name at the bottom, ready to copy.
- Start from the **question** ("who talked to this malicious IP?"), then build the filter to answer it.

## Reading traffic in an investigation

| I want to know… | Do this |
|---|---|
| Who contacted a bad IP | `ip.addr == <bad_ip>` |
| Was data uploaded | `http.request.method == "POST"`, check payload size |
| What domains were resolved | `dns`, read `dns.qry.name` |
| Follow one conversation | right-click a packet → **Follow → TCP Stream** |
| A port scan | `tcp.flags.syn == 1 && tcp.flags.ack == 0`, one src → many ports |
| Possible MITM | `arp` — two MACs claiming one IP |

## Snort rule anatomy

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

Example:
```
alert tcp any any -> 10.0.0.0/24 80 (msg:"HTTP to internal web"; sid:1000001; rev:1;)
```

| Part | Meaning |
|---|---|
| `alert` | action (also: `log`, `drop`, `reject`) |
| `tcp` | protocol (`tcp`, `udp`, `icmp`, `ip`) |
| `any any` | source IP and port |
| `->` | direction (`<>` = both ways) |
| `10.0.0.0/24 80` | destination IP range and port |
| `msg:` | alert text shown to the analyst |
| `content:` | the bytes/string to match in the packet |
| `sid:` | unique rule id (≥ 1000000 for custom rules) |
| `rev:` | rule revision number |

Common options: `content:"..."`, `nocase` (case-insensitive), `offset`/`depth` (where to look), `flow:to_server,established`, `pcre:` (regex).

### Running Snort
```
snort -r capture.pcap -c snort.conf        # analyse a saved pcap against rules
snort -q -A console -i eth0 -c snort.conf  # live, alerts to console
```

## The rule-writing lesson (learned the hard way)
A rule that matches a bare substring produces false positives. `content:"ls"` fires on the word "ski**ls**". A good rule matches a real command pattern — `content:"?cmd=ls"` or `content:";ls"` — not a letter sequence that appears in ordinary words. **A signature match is not a verdict; the analyst confirms intent.**
