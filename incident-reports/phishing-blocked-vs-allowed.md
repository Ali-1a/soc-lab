# Case Study: Two Phishing Clicks, Two Different Decisions

Practice triage based on a simulated SOC exercise. All names, domains and IPs below are **fictional**.

Both cases are phishing emails where the user clicked the link. One click was blocked and one was allowed. That single difference changed the escalation decision.

---

## Case A: Delivery scam, click blocked

**Alert:** Inbound email containing suspicious external link
**Verdict:** True Positive · **Escalation:** No

### Findings
- Sender `alerts@parcel-delivery.biz` impersonates a delivery company. The domain is not the company's real domain.
- Generic greeting ("Dear Customer"), a 48-hour deadline, and a shortened URL that hides the destination.
- The URL is on the organisation's blocklist.
- Firewall logs show host `10.0.5.17` requested the URL **74 seconds** after delivery, so the user clicked.
- The request was **blocked**. A review of all traffic from the host found no allowed connection to the URL.

### Impact
- **Confirmed:** the user clicked the link.
- **Not observed:** any successful connection, download, or credential submission.

### Decision
No escalation. The control worked and the threat was contained.

**Optional preventive actions:** remove the email from the mailbox, block the sender domain at the email gateway, and remind the user how to spot phishing.

---

## Case B: Fake account alert, click allowed

**Alert:** Inbound email containing suspicious external link
**Verdict:** True Positive · **Escalation:** Yes

### Findings
- Sender `no-reply@micros0ft-support.co` is a typosquatted domain (zero instead of "o", `.co` instead of the real domain).
- Uses fear (a fake sign-in from abroad) to push the user to act fast.
- The link points to a `/login` page built to steal credentials.
- Threat intelligence classifies the URL as **malicious**.
- Firewall logs show host `10.0.5.25` reached the page **69 seconds** after delivery. The connection was **allowed**, because the domain was new and not on the blocklist.

### Impact
- **Confirmed:** the user reached a credential harvesting page.
- **Not confirmed yet:** whether credentials were submitted or the account was used by the attacker.

### Decision
Escalate to Tier 2. The account must be treated as potentially compromised.

**Required actions:**
1. Reset the user's password and revoke active sessions.
2. Review MFA devices, sign-in logs and mailbox rules after the click.
3. Block the domain and its IP on the firewall, proxy and email gateway.
4. Remove the email and contact the user.

---

## Takeaway

| | Case A | Case B |
|---|---|---|
| Phishing | Yes | Yes |
| User clicked | Yes | Yes |
| Firewall action | **Blocked** | **Allowed** |
| Escalation | No | **Yes** |
| Remediation | Optional | Required |

**A block is a success, not a breach.** For phishing triage, the key question is whether the connection succeeded. The blocklist only covers known threats, which is why Case B got through.
