# Pyramid of Pain

## What it is

A model by David Bianco (2013) that ranks indicators by how much **pain** it causes an attacker when defenders detect and block them. The higher the level, the harder it is for the attacker to change it.

```
            /\
           /  \         TTPs                      Tough
          /----\
         / Tools \                                Challenging
        /--------\
       / Network & \    Host / Network Artifacts  Annoying
      /  Host Artif. \
     /----------------\
    /   Domain Names   \                          Simple
   /--------------------\
  /     IP Addresses     \                        Easy
 /------------------------\
/       Hash Values        \                      Trivial
```

## The levels

| Level | Example | Why it does or does not hurt the attacker |
|---|---|---|
| **Hash values** | SHA256 of a malicious file | Changing one byte produces a new hash. Blocking it costs the attacker nothing |
| **IP addresses** | C2 server IP | A new IP is cheap and quick. With **Fast Flux**, one domain rotates through many IPs every few minutes |
| **Domain names** | `micros0ft-support.co` | A new domain costs a little time and money. Attackers use **Punycode** look-alike characters, typosquatting and **URL shorteners** to hide them |
| **Host artifacts** | Dropped files, registry keys, Word spawning PowerShell | The attacker has to change how the tool behaves |
| **Network artifacts** | Unusual User-Agent, fixed URI patterns in C2 traffic | The attacker has to modify the tool's network behaviour |
| **Tools** | A specific credential stealer or phishing kit | The attacker has to find or build a new tool |
| **TTPs** | Phishing with look-alike domains, exfiltration over a web service | The attacker has to change the way they operate. Mapped in **MITRE ATT&CK** |

## Detecting higher up the pyramid

- **Fuzzy hashing (ssdeep)** finds files that are similar even when their exact hashes differ.
- **YARA rules** match patterns inside files, so they catch a tool across many builds.
- **Sigma rules** describe detection logic once and convert to any SIEM (Splunk, Elastic).
- **MITRE ATT&CK** gives a shared language for TTPs, so detections can target behaviour instead of single indicators.

Useful tricks from the room: look up hashes in VirusTotal, read sandbox reports (Any.run) to see what a sample connects to, and append `+` to a bit.ly link to preview its destination without opening it.

## How it maps to my own work

- In my [FormBook investigation](../report.md), repeated POST requests to random-looking URI paths were a **network artifact**. Detecting that pattern catches the malware even after it moves to new C2 IPs.
- In my [phishing case study](../incident-reports/phishing-blocked-vs-allowed.md), the blocklist stopped a known URL (bottom of the pyramid) but missed a new typosquatted domain. Detecting the **technique** (look-alike domain plus urgency plus a login page) would have caught both.

## Takeaway

Blocking hashes and IPs is fast and still worth doing, but it only buys time. Real defensive value comes from detecting artifacts, tools and behaviour, because those force the attacker to change how they work.
