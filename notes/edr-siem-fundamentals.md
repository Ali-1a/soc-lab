# EDR & SIEM Fundamentals

The two tools a Tier 1 analyst lives in. One watches the **endpoint**, the other watches **everything, correlated**. Knowing what each sees — and what each misses — is the core of the Core SOC Solutions module. (SOAR, the automation layer on top, has its [own note](intro-to-soar.md).)

## SIEM — Security Information and Event Management

A SIEM collects logs from across the environment (firewalls, servers, endpoints, proxies, AD) into **one searchable place**, normalises them, and alerts on correlation rules.

- **What it is good at:** seeing the *whole picture* — tying a firewall block, a login, and a process together across different machines.
- **What it needs:** log sources must actually be forwarded to it. A SIEM only knows what it is fed.
- **The analyst's core loop:** an alert fires → search the SIEM for the indicator across the full time range → decide normal vs suspicious → check the outcome.
- **Tools I've used:** **Splunk** ([notes](splunk-basics.md), query language **SPL**) and **Elastic/Kibana** ([notes](elastic-stack-basics.md), query language **KQL**). Both compared in my [SPL vs KQL cheatsheet](../cheatsheets/siem-queries.md).

## EDR — Endpoint Detection and Response

An EDR agent runs **on the endpoint** and records deep host activity: process creation, parent/child process trees, command lines, file writes, registry changes, network connections per process.

- **What it is good at:** the *detail* a network/SIEM view can't give — exactly which process spawned what, with which command line.
- **Response, not just detection:** EDR can **isolate** a host from the network, kill a process, or quarantine a file remotely. That "R" is what separates it from plain antivirus.
- **Why it matters for detection:** techniques like "living off the land" (abusing built-in tools such as `powershell`, `cmd`, `wmic`) look like normal admin activity in a firewall log but show their intent in the **process tree and command line** — which is exactly what EDR captures.

## SIEM vs EDR — how I keep them straight

| | SIEM | EDR |
|---|---|---|
| **Scope** | the whole environment | a single endpoint |
| **Data** | normalised logs from many sources | deep host telemetry (processes, commands) |
| **Strength** | correlation across systems | detail and context on one host |
| **Response** | alerts / dashboards | can isolate, kill, quarantine |
| **Blind spot** | only sees what's forwarded to it | only sees that one host |

They are complementary: the **SIEM** tells me *something is wrong and where*, the **EDR** tells me *exactly what the process did on the box*. A good investigation pivots between them.

## Where this connects to ATT&CK

- EDR's process + command-line data is the main source for **Execution** and **Persistence** techniques.
- SIEM correlation catches multi-stage activity that spans **Initial Access → Lateral Movement → Exfiltration**, because it sees more than one host.
- See [MITRE ATT&CK note](mitre-attack.md): every technique lists the **Data Source** that detects it, and most of those sources are things the SIEM or EDR collects.

## Takeaways

1. SIEM = breadth (everything, correlated). EDR = depth (one host, in detail). Use both.
2. A SIEM only knows what it's fed; an EDR only sees its own host. Know each blind spot.
3. The "R" in EDR — isolate, kill, quarantine — is the response power a SIEM alone doesn't have.
