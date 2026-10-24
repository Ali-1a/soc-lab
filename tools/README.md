# IOC Triage

A single-page, offline tool that extracts indicators of compromise (IOCs) from any text — logs, a phishing email, a threat report — then defangs them, removes duplicates, and ranks them by the **Pyramid of Pain** so an analyst knows what to block first and how much it hurts the adversary.

**No install, no upload.** Download [`ioc-triage.html`](ioc-triage.html) and open it in a browser, or run it from source. Everything runs client-side, so it is safe for sensitive text — nothing leaves the page.

## What it does

- **Extracts** IPs (public vs internal), domains, URLs, email addresses, file names, hashes (MD5 / SHA1 / SHA256) and CVEs.
- **Re-fangs input** automatically (`hxxp`, `[.]`, `[at]`, `[dot]`, `(.)`) so it accepts messy, defanged text.
- **Validates** as it parses: rejects impossible IPs (`999.999.999.999`), hashes of the wrong length, version numbers that look like IPs (`version 4.2.1.0`), and file extensions that aren't indicators.
- **De-duplicates** case-insensitively and never double-counts a domain that is already inside a URL or email.
- **Ranks** every indicator on the Pyramid of Pain (David Bianco, 2013) with a per-type rationale.
- **Defangs output** and offers copy-per-indicator or copy-all.

## Pyramid of Pain mapping

| Indicator | Tier | Why |
|---|---|---|
| Hash values | Trivial | One byte change = a new hash |
| IP addresses | Easy | A new IP is cheap and quick |
| Domains / emails | Simple | A new domain costs a little time and money |
| URLs / file names | Annoying (host & network artifacts) | Changing them means modifying the tool |
| CVEs | context | A vulnerability to patch, not a blockable indicator |

The two top tiers (Tools, TTPs) are intentionally left to analysis — they can't be parsed from raw text.

## Validation

The extraction engine is covered by an automated suite ([`test/ioc-triage.test.mjs`](test/ioc-triage.test.mjs)) that pulls the live code straight out of the page and runs **41 checks**, including a real published IOC set — the CISA **#StopRansomware: Medusa** advisory (AA25-071A). On that real data the tool recovered an IP the advisory's own IP list missed (hidden inside a malformed URL), kept only the six correctly-formed hashes while rejecting five malformed ones, and reclassified a domain the advisory had filed under "IP addresses".

Run it with Node (no dependencies):

```bash
node test/ioc-triage.test.mjs
```

## License

MIT — see [LICENSE](../LICENSE).
