# Web Security Monitoring

Monitoring the web layer — the ecosystem every organisation uses to deliver its services. For a SOC analyst this means reading **web server logs and traffic** to spot attacks against public-facing applications, and knowing the footprint each attack leaves.

## How the web works (the monitoring angle)

- A request is a **method + URL + headers**; a response is a **status code + body**.
- The fields I read in every access log line: **source IP, timestamp, method, URL (with query string), status code, bytes, user-agent, referer**.
- **Status code families** are my first filter:
  - `2xx` success — the request worked (for an attack, that can be bad news).
  - `3xx` redirect.
  - `4xx` client error — `401/403` denied, `404` not found (lots of 404s = scanning).
  - `5xx` server error — `500` can mean an injection broke the app.

## Common web attacks and their log footprint

Maps to **ATT&CK T1190 — Exploit Public-Facing Application**.

| Attack | What I look for in the URL / payload |
|---|---|
| **SQL injection** | `' OR 1=1`, `UNION SELECT`, `--`, `information_schema` in a query string |
| **XSS** | `<script>`, `onerror=`, `%3Cscript%3E` (URL-encoded) in parameters |
| **Path traversal / LFI** | `../../`, `..%2f`, `/etc/passwd`, `boot.ini` |
| **Command injection** | `;id`, `|whoami`, `` `cat ...` ``, `&&` in a parameter |
| **Brute force / credential stuffing** | many `401/403` to a login endpoint, then a `200` (success) |
| **Scanning / enumeration** | a burst of `404`s across many paths from one IP, odd user-agents (`sqlmap`, `nikto`) |

The key skill is reading the **query string**: a payload in the URL plus a `500` or an unexpected `200` is the signature.

## Web shells

A **web shell** is a malicious script an attacker uploads into the web root to get remote command execution. Maps to **ATT&CK T1505.003 — Web Shell**.

Detection across three sources:
- **Logs:** `POST` requests to an unusual file (e.g. an "image" that takes POST data), repeated requests to a file that didn't exist last week, commands passed as parameters (`?cmd=whoami`).
- **File system:** a new `.php`/`.aspx`/`.jsp` file in an upload or web directory; files containing `eval(`, `base64_decode(`, `system(`, `exec(`.
- **Process tree:** the web server process spawning a shell — `w3wp.exe`/`apache`/`nginx` launching `cmd.exe`, `powershell`, or `/bin/sh`. This is the strongest signal (and exactly what EDR captures — see [EDR & SIEM note](edr-siem-fundamentals.md)).

## Web DDoS (denial of service)

- **Volumetric:** overwhelm bandwidth with sheer traffic volume.
- **Application-layer (L7):** many "legitimate-looking" requests to an expensive endpoint (search, login) to exhaust the server.
- **Detection:** a sharp spike in request rate against the baseline, an abnormal number of requests to one endpoint, many requests from few IPs (or few requests from many IPs in a distributed attack), rising `5xx` as the server falls over.
- The analyst's job: separate a **real traffic surge** (a campaign, a sale) from an **attack** — baseline and intent decide it.

## Connections to my own work

- The log-reading method is the same discipline as my [SIEM work](splunk-basics.md): pick an indicator (IP, URL, status), search across the full range, decide normal vs suspicious.
- The web-shell "web server spawns a shell" signal is a textbook EDR process-tree detection — see [EDR & SIEM note](edr-siem-fundamentals.md).
- A signature in a URL is **not a verdict** — the same lesson as the Snort `ls`-inside-"skills" false positive in my [Wireshark/Snort cheatsheet](../cheatsheets/wireshark-snort.md).

## Takeaways

1. Read the access-log line as a sentence: who, what method, what URL, what status. The payload lives in the query string.
2. Status-code patterns are triage gold — a wall of 404s is scanning; a 500 after a weird parameter is possible injection.
3. For web shells, the process tree (web server → shell) beats any log signature.
