# Cyber Kill Chain

## What it is

A model from Lockheed Martin that describes a cyber attack as a chain of seven ordered phases. The core idea: break any link in the chain and you stop the whole attack. Defenders use it to decide where they can detect and disrupt an intrusion.

## The seven phases

| # | Phase | What the attacker does | Example |
|---|---|---|---|
| 1 | **Reconnaissance** | Gather information about the target | OSINT, harvesting employee emails, scanning sites |
| 2 | **Weaponization** | Build the malicious payload | Pair malware with a Word or PDF document |
| 3 | **Delivery** | Get the weapon to the victim | Phishing email, USB drop, compromised website |
| 4 | **Exploitation** | Trigger the code via a vulnerability or human error | Victim opens the attachment and it executes |
| 5 | **Installation** | Establish a persistent foothold | Backdoor, autorun/registry persistence |
| 6 | **Command & Control (C2)** | Open a remote control channel | Infected host beacons to the attacker's server |
| 7 | **Actions on Objectives** | Achieve the final goal | Data exfiltration, encryption, destruction |

## Key terms from the room

- **OSINT:** intelligence gathered from publicly available sources.
- **Phishing / spear phishing:** delivery over email; spear phishing is targeted at a specific person.
- **Persistence:** the attacker survives reboots and stays on the host.
- **Privilege escalation:** moving from a normal user to admin/SYSTEM.
- **C2 (C&C):** server that issues commands to infected hosts.
- **Exfiltration:** moving stolen data out of the network.

## How it connects to my work

The Pyramid of Pain tells you *which indicator* matters most; the Kill Chain tells you *which phase* of the attack you are in. Together they frame an incident.

Mapped onto my [phishing case study](../incident-reports/phishing-blocked-vs-allowed.md):

1. Attacker harvested the recipient's email — **Reconnaissance**.
2. Built a malicious shortened link — **Weaponization**.
3. Sent it in a spoofed delivery email — **Delivery**.
4. The user clicked — **Exploitation** — but the firewall blocked it here.

Because the chain broke early (delivery/exploitation), the attack never reached Installation or C2, so no escalation was needed. In the case where the connection was *allowed*, the attack moved closer to the dangerous later phases, which is why that one was escalated.

## Limitations (worth knowing)

The Kill Chain is malware- and perimeter-focused. It covers external intrusions well but handles these poorly:

- Insider threats.
- Web attacks that use no malware.
- Lateral movement once inside the network.

Newer models such as the **Unified Kill Chain** were created to close these gaps.
