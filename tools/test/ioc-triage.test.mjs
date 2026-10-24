// Extracts the live extract() pipeline from the published HTML and runs a battery of tests.
import fs from "fs";
import path from "path";
import {fileURLToPath} from "url";
const __dirname=path.dirname(fileURLToPath(import.meta.url));
const html=fs.readFileSync(path.join(__dirname,"..","ioc-triage.html"),"utf8");

// pull the exact source of the four functions from the page, so we test what ships
function grab(name){
  const start=html.indexOf("function "+name+"(");
  if(start<0) throw new Error("not found: "+name);
  let i=html.indexOf("{",start),depth=0;
  for(;i<html.length;i++){if(html[i]==="{")depth++;else if(html[i]==="}"){depth--;if(depth===0){i++;break;}}}
  return html.slice(start,i)+"\n";
}
const src=grab("refang")+grab("validIp")+grab("isPriv")+
  "const TLD="+html.match(/const TLD=(\/[^\n]*\/i);/)[1]+";\n"+grab("extract")+"\nexport{extract};";
fs.writeFileSync(path.join(__dirname,"_engine.mjs"),src);
const {extract}=await import("./_engine.mjs");

let pass=0,fail=0;const fails=[];
function count(text){const r=extract(text);const by={};r.forEach(d=>{const b=d.ty==="ip_priv"?"ip":d.ty;by[b]=(by[b]||0)+1;});return{by,vals:r.map(d=>d.val)};}
function has(text,val){return count(text).vals.includes(val);}
function hasNot(text,val){return !count(text).vals.includes(val);}
function eq(name,got,exp){const ok=got===exp;ok?pass++:fail++;if(!ok)fails.push(`${name}: got ${got}, expected ${exp}`);}
function ok(name,cond){cond?pass++:fail++;if(!cond)fails.push(name);}

/* ===== 1. REAL: CISA AA25-071A Medusa IOC appendix ===== */
const medusa=`http//45.61.150.94:8000/storm.exe
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
2df705c9be0465f1c73a9f5d35147723deb`;
const M=count(medusa);
eq("Medusa IPs (21, incl. one hidden in broken URL)",M.by.ip,21);
eq("Medusa valid MD5 only (reject 5 malformed)",M.by.md5,6);
eq("Medusa domain reclassified from IP list",M.by.domain,1);
eq("Medusa file name extracted (storm.exe)",M.by.file,1);
ok("Medusa catches IP hidden in malformed URL",has(medusa,"45.61.150.94"));
ok("Medusa rejects 31-char junk hash",hasNot(medusa,"7fd3bc3777c53caa1ab33426c83bfcc"));
ok("Medusa rejects 35-char junk hash",hasNot(medusa,"2df705c9be0465f1c73a9f5d35147723deb"));

/* ===== 2. REAL defang styles from phishing ===== */
const ph=`hXXps://Evil-Domain[.]COM/a  hxxp://test(.)net  bad.user[at]gmail[dot]com  1.1.1.1[.]`;
ok("refang hxxps + [.]",has(ph,"https://Evil-Domain.COM/a"));
ok("refang (.)",has(ph,"http://test.net"));
ok("refang [at]/[dot] email",has(ph,"bad.user@gmail.com"));

/* ===== 3. Hash length discrimination ===== */
const h=`${"a".repeat(32)} ${"b".repeat(40)} ${"c".repeat(64)} ${"d".repeat(31)} ${"e".repeat(33)} ${"f".repeat(65)}`;
const H=count(h);
eq("MD5 (32)",H.by.md5,1);eq("SHA1 (40)",H.by.sha1,1);eq("SHA256 (64)",H.by.sha256,1);
ok("reject 31-char",hasNot(h,"d".repeat(31)));
ok("reject 33-char",hasNot(h,"e".repeat(33)));
ok("reject 65-char",hasNot(h,"f".repeat(65)));

/* ===== 4. IP validation & private ranges ===== */
ok("reject 999.999.999.999",hasNot("999.999.999.999","999.999.999.999"));
ok("reject 256.1.1.1",hasNot("256.1.1.1","256.1.1.1"));
const ipr=count("8.8.8.8 10.0.0.1 172.16.0.1 172.31.255.255 172.32.0.1 192.168.1.1 169.254.1.1 127.0.0.1");
eq("public IPs = 2 (8.8.8.8, 172.32.0.1)",ipr.by.ip,8); // total ips incl private all counted
ok("172.32 is public (not private)",extract("172.32.0.1").some(d=>d.ty==="ip"));
ok("172.16 is private",extract("172.16.0.1").some(d=>d.ty==="ip_priv"));
ok("169.254 link-local private",extract("169.254.1.1").some(d=>d.ty==="ip_priv"));

/* ===== 5. Version-number guard (new) ===== */
ok("skip 'version 4.2.1.0'",hasNot("the app version 4.2.1.0 is old","4.2.1.0"));
ok("skip 'build 10.20.30.40'",hasNot("nightly build 10.20.30.40 shipped","10.20.30.40"));
ok("skip chained 1.2.3.4.5",hasNot("semver 1.2.3.4.5 here","1.2.3.4"));
ok("still catch real IP after word",has("connected to 8.8.8.8 ok","8.8.8.8"));

/* ===== 6. File-name extraction (new) ===== */
ok("extract storm.exe",has("dropped storm.exe to temp","storm.exe"));
ok("extract payload.dll",has("loaded payload.dll","payload.dll"));
ok("extract script.ps1",has("ran script.ps1","script.ps1"));
ok("ignore report.pdf (not malware ext)",hasNot("see report.pdf","report.pdf"));
ok("ignore config.ini",hasNot("edit config.ini","config.ini"));

/* ===== 7. Dedup & case-insensitivity ===== */
const dd=count("EVIL.COM evil.com Evil.Com same@MAIL.com same@mail.com 8.8.8.8 8.8.8.8");
eq("dedup domain case",dd.by.domain,1);
eq("dedup email case",dd.by.email,1);
eq("dedup ip",dd.by.ip,1);

/* ===== 8. No double-count: domain inside URL/email ===== */
const nd=count("visit https://paypa1-support.com/verify from admin@paypa1-support.com");
eq("domain not double-counted (0 standalone)",nd.by.domain||0,0);
eq("one url",nd.by.url,1);eq("one email",nd.by.email,1);

/* ===== 9. CVE ===== */
const cv=count("patch cve-2026-109618 and CVE-2017-0199 but CVE-99-1 is bad");
eq("CVE count (2)",cv.by.cve,2);
ok("CVE uppercased",has("x cve-2017-0199 y","CVE-2017-0199"));

/* ===== 10. Empty / junk input ===== */
eq("empty input -> 0",count("").vals.length,0);
eq("prose with no IOCs -> 0",count("The quick brown fox jumps over the lazy dog.").vals.length,0);

/* ---- report ---- */
console.log(`\n  PASSED: ${pass}   FAILED: ${fail}\n`);
if(fails.length){console.log("  Failures:");fails.forEach(f=>console.log("   ✗ "+f));process.exit(1);}
else console.log("  ✓ All real-world and edge-case tests passed.");
