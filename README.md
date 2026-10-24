# SOC Lab

My hands-on work while training to become a **SOC Tier 1 Analyst**: investigations, incident reports and study notes, written in my own words.

I am working through the TryHackMe **SOC Level 1** path and practising alert triage in simulated SOC environments.

> These are personal study notes. They do not contain room answers or flags. Data in practice reports is fictional unless it comes from a public sample.

## Investigations

| Report | Summary |
|---|---|
| [FormBook malware detection](report.md) | PCAP analysis of FormBook C2 check-ins: infected host, user and C2 servers identified in Wireshark |
| [TCP handshake breakdown](task2-tcp-handshake.md) | Field-by-field breakdown of a TCP handshake from the same capture, and what the RST close says about the malware |
| [Phishing: blocked vs allowed](incident-reports/phishing-blocked-vs-allowed.md) | Two phishing clicks with different outcomes, and why only one needed escalation |

## Notes

| Topic | File |
|---|---|
| Splunk: The Basics | [notes/splunk-basics.md](notes/splunk-basics.md) |
| Elastic Stack: The Basics | [notes/elastic-stack-basics.md](notes/elastic-stack-basics.md) |
| Introduction to SOAR | [notes/intro-to-soar.md](notes/intro-to-soar.md) |
| Pyramid of Pain | [notes/pyramid-of-pain.md](notes/pyramid-of-pain.md) |
| Cyber Kill Chain | [notes/cyber-kill-chain.md](notes/cyber-kill-chain.md) |
| SPL vs KQL cheatsheet | [cheatsheets/siem-queries.md](cheatsheets/siem-queries.md) |

## Tools

- **[IOC Triage](https://github.com/Ali-1a/ioc-triage)** *(own repo)* — extract, defang, de-duplicate and rank indicators of compromise by the Pyramid of Pain. Browser page + Python CLI, tested on real CISA IOC data.
- **[SOC Alert Report Builder](tools/soc-report-builder.html)** — a single-page form that turns triage findings into a structured incident report (5W summary, defanged IOCs, recommended next steps).

## Progress

- [x] Splunk: The Basics
- [x] Elastic Stack: The Basics
- [x] Introduction to SOAR
- [x] Pyramid of Pain
- [x] Cyber Kill Chain
- [x] SOC Simulator: phishing scenario (passed, all true positives identified)

## My triage method

1. **Read the alert** and pick one unique indicator (IP, domain, URL, email address).
2. **Search the SIEM** for that indicator across the full time range.
3. **Ask one question:** is this normal or suspicious? Use asset/identity lookups and threat intelligence.
4. **Check the outcome:** was the connection blocked or allowed? This decides escalation.
5. **Write the report:** only what I verified, with the reason behind every decision.

## Skills

`Wireshark` · `Splunk` · `Elastic Stack / Kibana` · `SPL` · `KQL` · `MITRE ATT&CK` · `Python` · `Phishing analysis` · `Alert triage` · `Incident reporting`

## License

MIT — see [LICENSE](LICENSE).
