#!/usr/bin/env python3
"""
IOC Triage — extract, defang, de-duplicate and rank indicators of compromise
by the Pyramid of Pain.

Reads from a file, several files, or stdin; prints a ranked table, or exports
JSON / CSV. Pure standard library, no dependencies.

Examples:
    python3 ioc_triage.py report.txt
    cat firewall.log | python3 ioc_triage.py
    python3 ioc_triage.py report.txt --json > iocs.json
    python3 ioc_triage.py *.log --csv > iocs.csv

MIT License. Part of the soc-lab project.
"""
import argparse
import csv
import io
import json
import re
import sys

# --- Pyramid of Pain tiers, low pain -> high pain -------------------------
TIERS = {
    "trivial":  ("Hash Values",            "Trivial"),
    "easy":     ("IP Addresses",           "Easy"),
    "simple":   ("Domain Names",           "Simple"),
    "annoying": ("Host & Network Artifacts", "Annoying"),
    # Tools / TTPs are left to analysis — they can't be parsed from raw text.
}
TIER_ORDER = ["annoying", "simple", "easy", "trivial"]  # most pain first

TYPES = {
    "sha256": ("SHA256 hash",   "trivial"),
    "sha1":   ("SHA1 hash",     "trivial"),
    "md5":    ("MD5 hash",      "trivial"),
    "ip":     ("IP address",    "easy"),
    "ip_priv":("Internal IP",   "easy"),
    "email":  ("Email address", "simple"),
    "domain": ("Domain",        "simple"),
    "url":    ("URL",           "annoying"),
    "file":   ("File name",     "annoying"),
    "cve":    ("CVE",           None),
}

_TLD = re.compile(
    r"\.(com|net|org|io|co|gov|edu|mil|info|biz|ru|cn|uk|de|ir|xyz|top|site|"
    r"online|pro|me|tv|cc|us|eu|dev|app|zip|mov|th|jp|kr|in|br|ca|au|nl|fr|"
    r"se|pl)$", re.I)

_FILE_EXT = ("exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|hta|scr|jar|msi|lnk|sys|elf|"
             "apk|sh|py|docm|xlsm|pptm|iso|img")


def refang(text: str) -> str:
    """Turn defanged indicators back into parseable ones."""
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = text.replace("[:]", ":")
    text = re.sub(r"\[@\]|\(at\)|\[at\]", "@", text, flags=re.I)
    text = re.sub(r"h[xX]{2}p(s?)", r"http\1", text)
    text = re.sub(r"\[dot\]", ".", text, flags=re.I)
    text = re.sub(r"\s*\.\s*", ".", text)
    return text


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(
        p.isdigit() and 0 <= int(p) <= 255 and str(int(p)) == p for p in parts
    )


def _is_private(ip: str) -> bool:
    p = [int(x) for x in ip.split(".")]
    return (p[0] == 10 or p[0] == 127
            or (p[0] == 172 and 16 <= p[1] <= 31)
            or (p[0] == 192 and p[1] == 168)
            or (p[0] == 169 and p[1] == 254))


def extract(raw: str):
    """Return a list of {type, value} dicts, de-duplicated, in discovery order."""
    text = refang(raw)
    found, seen = [], set()

    def add(ty, val):
        key = ("ip" if ty == "ip_priv" else ty) + "|" + val.lower()
        if key in seen:
            return
        seen.add(key)
        found.append({"type": ty, "value": val})

    def consume(pattern, handler):
        """Replace every match with spaces so later patterns don't re-match it."""
        nonlocal text
        def repl(m):
            handler(m.group(0))
            return " " * len(m.group(0))
        text = re.sub(pattern, repl, text, flags=re.I)

    consume(r"\bCVE-\d{4}-\d{4,7}\b", lambda m: add("cve", m.upper()))
    consume(r"\b[a-fA-F0-9]{64}\b", lambda m: add("sha256", m.lower()))
    consume(r"\b[a-fA-F0-9]{40}\b", lambda m: add("sha1", m.lower()))
    consume(r"\b[a-fA-F0-9]{32}\b", lambda m: add("md5", m.lower()))
    consume(r"\bhttps?://[^\s\"'<>()\[\]]+",
            lambda m: add("url", m.rstrip(".,;:)")))
    consume(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            lambda m: add("email", m))
    consume(r"\b[A-Za-z0-9][A-Za-z0-9._\-]*\.(?:" + _FILE_EXT + r")\b",
            lambda m: add("file", m.lower()))

    # IPs with a version/build guard (skip "version 4.2.1.0" and "1.2.3.4.5")
    def ip_repl(m):
        start, s = m.start(), text
        before = s[max(0, start - 12):start]
        after = s[m.end():m.end() + 2]
        is_version = bool(re.search(r"(?:\bv|\bver|version|build|rev|release)\.?\s*$",
                                    before, re.I)) or re.match(r"\.\d", after)
        ip = m.group(0)
        if _valid_ip(ip) and not is_version:
            add("ip_priv" if _is_private(ip) else "ip", ip)
        return " " * len(ip)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip_repl, text)

    def dom_repl(m):
        d = m.group(0)
        if _TLD.search("." + d.split(".")[-1]) or _TLD.search(d):
            add("domain", d.lower())
        return " " * len(d)
    text = re.sub(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
                  dom_repl, text, flags=re.I)

    return found


def defang(value: str, ty: str) -> str:
    if ty in ("md5", "sha1", "sha256", "ip_priv", "cve", "file"):
        return value
    if ty == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    s = re.sub(r"^http", lambda m: "hxxp", value)
    return s.replace(".", "[.]")


def _rank(item):
    tier = TYPES[item["type"]][1]
    return (TIER_ORDER.index(tier) if tier in TIER_ORDER else -1, item["value"])


def enrich(items, fanged=True):
    """Attach label, tier and pain, sorted most-painful first."""
    out = []
    for it in sorted(items, key=_rank):
        label, tier = TYPES[it["type"]]
        out.append({
            "value": it["value"] if fanged is False else defang(it["value"], it["type"]),
            "type": label,
            "tier": TIERS[tier][0] if tier else "context",
            "pain": TIERS[tier][1] if tier else "context",
        })
    return out


# --- output formats -------------------------------------------------------
def print_table(rows):
    if not rows:
        print("No indicators found.", file=sys.stderr)
        return
    wv = max(len(r["value"]) for r in rows)
    wt = max(len(r["type"]) for r in rows)
    print(f"{'INDICATOR'.ljust(wv)}  {'TYPE'.ljust(wt)}  PAIN")
    print(f"{'-'*wv}  {'-'*wt}  ----")
    for r in rows:
        print(f"{r['value'].ljust(wv)}  {r['type'].ljust(wt)}  {r['pain']}")
    # summary by type
    by = {}
    for r in rows:
        by[r["type"]] = by.get(r["type"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in by.items())
    print(f"\n{len(rows)} indicators: {summary}", file=sys.stderr)


def to_csv(rows) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["value", "type", "tier", "pain"])
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract and triage IOCs by the Pyramid of Pain.")
    ap.add_argument("files", nargs="*",
                    help="input files; omit to read from stdin")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--csv", action="store_true", help="output CSV")
    ap.add_argument("--raw", action="store_true",
                    help="keep indicators fanged (default is defanged)")
    args = ap.parse_args(argv)

    if args.files:
        text = "\n".join(open(f, encoding="utf-8", errors="replace").read()
                         for f in args.files)
    else:
        text = sys.stdin.read()

    rows = enrich(extract(text), fanged=not args.raw)

    if args.json:
        print(json.dumps(rows, indent=2))
    elif args.csv:
        print(to_csv(rows), end="")
    else:
        print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
