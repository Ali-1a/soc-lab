# Introduction to SOAR

## What it is

**SOAR** (Security Orchestration, Automation and Response) connects the security tools a SOC already uses and runs the repetitive parts of an investigation automatically, so analysts can spend their time on decisions.

## The problems it solves

- **Alert fatigue:** thousands of alerts a day, most of them false positives. Tired analysts miss real ones.
- **Too many tools:** SIEM, EDR, firewall, email gateway, threat intel. Each has its own console, and analysts lose time switching and copy-pasting between them.
- **Not enough analysts** to cover the volume of work.

## The three capabilities

| Capability | Meaning | Example |
|---|---|---|
| **Orchestration** | Tools work together through integrations | SIEM raises an alert, SOAR queries threat intel, then tells the firewall to block |
| **Automation** | Repetitive steps run without a human | Every URL in a reported email is checked against reputation services |
| **Response** | Actions that contain the threat | Block an IP, isolate a host, disable an account |

## Playbooks

A SOAR playbook is a workbook that a machine can execute. Example for a phishing alert:

1. Extract sender, URLs and attachments from the email.
2. Enrich them with threat intelligence.
3. Clean: close the alert with the evidence attached.
4. Malicious: remove the email from all mailboxes, block the domain, open a ticket.
5. Unclear: hand the case to an analyst with all the enrichment already collected.

## SIEM vs SOAR

| | SIEM | SOAR |
|---|---|---|
| Main job | Collect logs and **detect** | **Investigate and respond** to alerts |
| Output | Alerts | Enriched cases and automated actions |
| Works on | Raw log data | Alerts coming from the SIEM and other tools |

They complement each other: the SIEM finds the problem, SOAR acts on it.

## My takeaways

- SOAR does not replace analysts. It removes the repetitive work so analysts can focus on context and judgement.
- In my own phishing triage practice I searched the SIEM, checked the URL reputation and confirmed the firewall action by hand. A SOAR playbook would run all of those lookups in seconds and leave me only the decision.
- Automation needs care: an automated block on a wrong verdict can disrupt legitimate users, so high-impact actions often keep a human approval step.
