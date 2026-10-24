# IOC Triage

Extracts indicators of compromise (IOCs) from any text — logs, a phishing email, a threat report — then defangs them, removes duplicates, and ranks them by the **Pyramid of Pain** so an analyst knows what to block first and how much it hurts the adversary.

Two front-ends share the same extraction logic:

| | Use it when |
|---|---|
| **[`ioc-triage.html`](ioc-triage.html)** — browser page | You want to paste text and read the result. No install, nothing leaves the page, safe for sensitive data. |
| **[`ioc_triage.py`](ioc_triage.py)** — command-line tool | You want to automate it, pipe logs into it, or export JSON/CSV into another tool. Pure standard library, no dependencies. |

### Command-line usage

```bash
python3 ioc_triage.py report.txt            # ranked table
cat firewall.log | python3 ioc_triage.py    # read from a pipe
python3 ioc_triage.py *.log --json          # export JSON
python3 ioc_triage.py report.txt --csv      # export CSV
python3 ioc_triage.py report.txt --raw      # keep indicators fanged
```

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

Both front-ends are covered by automated tests, run against a real published IOC set — the CISA **#StopRansomware: Medusa** advisory (AA25-071A). On that real data the tool recovered an IP the advisory's own IP list missed (hidden inside a malformed URL), kept only the six correctly-formed hashes while rejecting five malformed ones, and reclassified a domain the advisory had filed under "IP addresses".

```bash
python3 test/test_ioc_triage.py      # Python tool — 12 test classes
node    test/ioc-triage.test.mjs     # HTML page engine — 41 checks
```

The Node test pulls the extraction code straight out of the published page, so it tests exactly what ships.

## License

MIT — see [LICENSE](../LICENSE).
