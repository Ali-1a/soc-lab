# Phishing Analysis

How I take a reported email apart, decide if it is malicious, and turn it into a safe, defanged report. The companion practical case is [Phishing: blocked vs allowed](../incident-reports/phishing-blocked-vs-allowed.md).

## What I look at, in order

| Layer | What I check | Red flag |
|---|---|---|
| **Headers** | `From`, `Return-Path`, `Reply-To`, `Received` chain, SPF/DKIM/DMARC result | display name ≠ real domain; auth = fail/softfail; Reply-To on a different domain |
| **Sender domain** | is it the real brand's domain? | **typosquatting** (`m1crosoft`, `paypa1`), look-alike TLDs, newly registered |
| **Subject / body** | urgency, threats, "verify now", reward bait | pressure to act fast or in secret |
| **Links** | hover the real target, not the text | text says one domain, href points to another; URL shorteners (`bit.ly`) hiding the destination |
| **Attachments** | type and intent | macro docs, `.html` login pages, double extensions (`invoice.pdf.exe`) |

## Common techniques I name

- **Typosquatting / look-alike domain** — a domain one character off the real one, trusting a fast reader.
- **Credential harvesting** — a link to a fake login page that captures the password. The page often mirrors the real brand pixel-for-pixel.
- **Display-name spoofing** — the friendly name says "IT Support" while the actual address is random.
- **Link redirection / shorteners** — the visible link and the real destination differ; a shortener hides the destination until clicked.

Maps to **ATT&CK Phishing (T1566)** — Spearphishing Attachment, Link, or via Service.

## Defanging IOCs (so the report is safe to open)

I never put a live, clickable indicator in a report. I **defang** it:

| Live | Defanged |
|---|---|
| `http://` / `https://` | `hxxp://` / `hxxps://` |
| `.` in a domain | `[.]` |
| `@` in an email | `[at]` |
| full dot in email | `[dot]` |

Example: `https://login.m1crosoft-support.com` → `hxxps://login[.]m1crosoft-support[.]com`. This is exactly what my [IOC Triage tool](https://github.com/Ali-1a/ioc-triage) automates.

## The decision that drives escalation

The single question that changes everything in triage:

> **Was the malicious action blocked or did it succeed?**

- **Blocked / sandboxed / email quarantined** → a successful control. True positive, but no breach — document and close.
- **Delivered, clicked, credentials entered, attachment opened** → potential compromise → **escalate** (reset credentials, isolate host, hunt for follow-on activity).

A block is a *win*, not an incident. That distinction is the whole point of the [blocked vs allowed case](../incident-reports/phishing-blocked-vs-allowed.md).

## What goes in the report

1. **Verdict:** phishing / not phishing, and confidence.
2. **Evidence:** the specific red flags I found (defanged).
3. **Outcome:** blocked or delivered — this sets the severity.
4. **IOCs:** sender, domains, URLs, hashes — all defanged.
5. **Recommended action:** block the domain, reset affected users, add a detection, user awareness.

## Takeaways

1. Work top-down: headers → domain → body → links → attachments. The domain usually gives it away first.
2. Defang every indicator before it touches a report. Nothing clickable.
3. Blocked vs delivered is the escalation switch — verify the outcome before you decide severity.
