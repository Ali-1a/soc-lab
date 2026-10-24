#!/usr/bin/env python3
"""Validation suite for ioc_triage.py. Pure stdlib — run: python3 test_ioc_triage.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ioc_triage import extract, refang, defang  # noqa: E402


def counts(text):
    by = {}
    for d in extract(text):
        base = "ip" if d["type"] == "ip_priv" else d["type"]
        by[base] = by.get(base, 0) + 1
    return by


def values(text):
    return [d["value"] for d in extract(text)]


# Real published IOC appendix: CISA #StopRansomware: Medusa (AA25-071A)
MEDUSA = """http//45.61.150.94:8000/storm.exe
https://3324.requestcatcher.com/hihi
erp.ranasons.com
143.244.47.89 167.88.166.173 143.110.243.154 185.238.231.16 23.234.89.195
146.70.172.247 155.2.215.71 23.234.106.242 23.234.93.112 37.19.21.180
155.2.215.69 185.238.231.98 37.221.66.239 185.135.86.185 83.138.53.139
185.238.231.4 185.238.231.77 185.238.231.85 85.155.186.121 94.156.67.145
2C7F328FEEB94608AAAF99EC70CB0323 D796259C44BE852327623FD2E40C47F2
4D0B6E3C9C33550A005E41663A1977CB eb05429d25fc57b476428cdb0a134b2f
04b13b6cd5e5291b1cde78975a140feea 7fd3bc3777c53caa1ab33426c83bfcc
b29defbbc4ebaa243c1712ccc4943374f 1b6fb864c39ed9f70fceb17eee098db
44370f5c977e415981febf7dbb87a85c 8f11d9067da087cb4185fa804caac2df
2df705c9be0465f1c73a9f5d35147723deb"""


class RealData(unittest.TestCase):
    def test_medusa(self):
        by = counts(MEDUSA)
        self.assertEqual(by["ip"], 21)          # incl. one hidden in broken URL
        self.assertEqual(by["md5"], 6)          # reject 5 malformed hashes
        self.assertEqual(by["domain"], 1)       # reclassified from IP list
        self.assertEqual(by["file"], 1)         # storm.exe
        self.assertIn("45.61.150.94", values(MEDUSA))
        self.assertNotIn("7fd3bc3777c53caa1ab33426c83bfcc", values(MEDUSA))   # 31 chars
        self.assertNotIn("2df705c9be0465f1c73a9f5d35147723deb", values(MEDUSA))  # 35 chars


class Refang(unittest.TestCase):
    def test_styles(self):
        self.assertIn("https://Evil-Domain.COM/a", values("hXXps://Evil-Domain[.]COM/a"))
        self.assertIn("http://test.net", values("hxxp://test(.)net"))
        self.assertIn("bad.user@gmail.com", values("bad.user[at]gmail[dot]com"))


class Hashes(unittest.TestCase):
    def test_lengths(self):
        t = " ".join(["a"*32, "b"*40, "c"*64, "d"*31, "e"*33, "f"*65])
        by = counts(t)
        self.assertEqual((by["md5"], by["sha1"], by["sha256"]), (1, 1, 1))
        for bad in ("d"*31, "e"*33, "f"*65):
            self.assertNotIn(bad, values(t))


class IPs(unittest.TestCase):
    def test_validation(self):
        self.assertNotIn("999.999.999.999", values("999.999.999.999"))
        self.assertNotIn("256.1.1.1", values("256.1.1.1"))

    def test_private_ranges(self):
        self.assertEqual(extract("172.32.0.1")[0]["type"], "ip")        # public
        self.assertEqual(extract("172.16.0.1")[0]["type"], "ip_priv")
        self.assertEqual(extract("169.254.1.1")[0]["type"], "ip_priv")

    def test_version_guard(self):
        self.assertNotIn("4.2.1.0", values("the app version 4.2.1.0 is old"))
        self.assertNotIn("10.20.30.40", values("nightly build 10.20.30.40"))
        self.assertNotIn("1.2.3.4", values("semver 1.2.3.4.5 here"))
        self.assertIn("8.8.8.8", values("connected to 8.8.8.8 ok"))


class Files(unittest.TestCase):
    def test_extraction(self):
        self.assertIn("storm.exe", values("dropped storm.exe to temp"))
        self.assertIn("payload.dll", values("loaded payload.dll"))
        self.assertNotIn("report.pdf", values("see report.pdf"))
        self.assertNotIn("config.ini", values("edit config.ini"))


class DedupAndContext(unittest.TestCase):
    def test_dedup(self):
        by = counts("EVIL.COM evil.com Evil.Com x@MAIL.com x@mail.com 8.8.8.8 8.8.8.8")
        self.assertEqual((by["domain"], by["email"], by["ip"]), (1, 1, 1))

    def test_no_double_count(self):
        by = counts("visit https://paypa1-support.com/v from admin@paypa1-support.com")
        self.assertEqual(by.get("domain", 0), 0)
        self.assertEqual((by["url"], by["email"]), (1, 1))


class CVEandEmpty(unittest.TestCase):
    def test_cve(self):
        by = counts("patch cve-2026-109618 and CVE-2017-0199 but CVE-99-1 is bad")
        self.assertEqual(by["cve"], 2)
        self.assertIn("CVE-2017-0199", values("x cve-2017-0199 y"))

    def test_empty(self):
        self.assertEqual(len(extract("")), 0)
        self.assertEqual(len(extract("The quick brown fox jumps over the lazy dog.")), 0)


class Defang(unittest.TestCase):
    def test_output(self):
        self.assertEqual(defang("evil.com", "domain"), "evil[.]com")
        self.assertEqual(defang("http://x.co/a", "url"), "hxxp://x[.]co/a")
        self.assertEqual(defang("a@b.com", "email"), "a[@]b[.]com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
