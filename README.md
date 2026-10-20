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
| SPL vs KQL cheatsheet | [cheatsheets/siem-queries.md](cheatsheets/siem-queries.md) |

## Tools

- [SOC Alert Report Builder](tools/soc-report-builder.html): a single-page form that turns triage findings into a structured incident report (5W summary, defanged IOCs, recommended next steps). Download the file and open it in a browser.

## Progress

- [x] Splunk: The Basics
- [x] Elastic Stack: The Basics
- [x] SOC Simulator: phishing scenario (passed, all true positives identified)

## My triage method

1. **Read the alert** and pick one unique indicator (IP, domain, URL, email address).
2. **Search the SIEM** for that indicator across the full time range.
3. **Ask one question:** is this normal or suspicious? Use asset/identity lookups and threat intelligence.
4. **Check the outcome:** was the connection blocked or allowed? This decides escalation.
5. **Write the report:** only what I verified, with the reason behind every decision.

## Skills

`Wireshark` · `Splunk` · `Elastic Stack / Kibana` · `SPL` · `KQL` · `Phishing analysis` · `Alert triage` · `Incident reporting`
