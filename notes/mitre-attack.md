# MITRE ATT&CK

A knowledge base of **real** adversary behaviour, observed in the wild and organised so a defender can map detection and response to it. For a SOC analyst it answers one question about any alert: *"what is the attacker trying to do, and what do they usually do next?"*

## The core structure

| Term | What it is | Example |
|---|---|---|
| **Tactic** | the attacker's *goal* — the "why" | Initial Access, Execution, Persistence, Exfiltration |
| **Technique** | *how* they reach that goal | Phishing (T1566), Valid Accounts (T1078) |
| **Sub-technique** | a more specific variant | Spearphishing Attachment (T1566.001) |
| **Procedure** | the concrete way a group used it | APT group X sends a .docx with a macro |

The **ATT&CK Matrix** lays tactics across the top (columns, left→right roughly follows an intrusion) and techniques down each column. Reading an alert's technique tells you which column you are in, so you know what to look for before *and* after it.

## How I find things myself (so I don't guess)

The lesson I keep relearning: **read the source table, don't guess the name.**

- **Technique → data source:** open the technique page on attack.mitre.org and read the **Detection** and **Data Sources** sections. That tells you *which log* catches it (e.g. Process Creation, Network Traffic, Authentication logs).
- **Technique → mitigation:** the technique page has a **Mitigations** table. Each mitigation has an `M####` id (e.g. **M1018 — User Account Management**). I pick the mitigation from that table — I never invent one.
- **Who uses a technique:** the **Groups** section lists named adversaries (e.g. APT33) and the techniques attributed to them, each with a citation. To answer "which tool does group X use for Y", I open the group page and read its **Software** table rather than recalling a name.
- **Field name I forgot:** every technique, group and software entry has a stable id — searching the id on the site is faster and exact.

## Related projects inside ATT&CK

| Thing | What it does | When I reach for it |
|---|---|---|
| **ATT&CK Navigator** | a colour-codable matrix layer | map which techniques I can detect vs can't (coverage gaps) |
| **Groups** | adversary profiles + their TTPs | threat intel: "who behaves like this incident?" |
| **Software** | malware/tools and their techniques | pivot from a sample to likely behaviour |
| **Mitigations (M####)** | preventive controls per technique | the "what do we change" half of a report |
| **D3FEND** | MITRE's *defensive* companion matrix | map a defensive action (e.g. monitoring Network Traffic) to the offensive technique it counters |

## Why D3FEND matters to me

ATT&CK describes the attack; **D3FEND** describes the defence and links the two. When a report asks *which digital artifact* to monitor to catch a technique, the honest method is: find the technique's data source in ATT&CK (e.g. **Network Traffic**), then the D3FEND countermeasure that watches that artifact. The artifact is chosen because the technique *produces* it, not because it sounds right.

## Where ATT&CK sits with my other frameworks

- **Pyramid of Pain** tells me *how much it hurts* the adversary to block an indicator. The top of the pyramid is **TTPs** — and TTPs *are* ATT&CK techniques. So ATT&CK is the vocabulary for the hardest-to-change, most valuable detections.
- **Cyber Kill Chain** is the high-level 7-stage story; **ATT&CK** is the detailed technique list underneath each stage. Kill Chain for the narrative, ATT&CK for the specifics.

## Takeaways

1. Tactic = goal, Technique = method. Name the technique and you know what comes next.
2. Every answer (data source, mitigation, group, tool) lives in a table on the technique or group page — read it, don't recall it.
3. ATT&CK (offence) + D3FEND (defence) together turn an alert into a report: what happened, how to detect it, what to change.
