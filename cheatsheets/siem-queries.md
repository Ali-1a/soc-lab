# SIEM Query Cheatsheet: SPL vs KQL

The same investigation logic in Splunk (SPL) and Elastic/Kibana (KQL).

| Goal | Splunk (SPL) | Kibana (KQL) |
|---|---|---|
| Search everything for a term | `index=* "evil.com"` | `"evil.com"` |
| Field equals value | `Source_ip=10.0.0.5` | `Source_ip : "10.0.0.5"` |
| Value with spaces | `UserName="John Smith"` | `UserName : "John Smith"` |
| Exclude a value | `Source_Country!=France` | `not Source_Country : "France"` |
| Both conditions | `a=x b=y` or `a=x AND b=y` | `a : x and b : y` |
| Either value, same field | `UserName IN (James, Albert)` | `UserName : (James or Albert)` |
| Wildcard | `UserName=Jam*` | `UserName : Jam*` |

## Triage searches I reuse

```spl
# Phishing: find every event that mentions the link or domain
index=* "malicious-domain"

# Did a host reach the destination, and was it blocked or allowed?
index=* "10.0.5.17" "203.0.113.10"
```

After the second search, click the `Action` field and read each event together with its destination. An `allowed` value can belong to unrelated, harmless traffic.

## Before every search

1. Is the search box clear of old text?
2. Is the time range right for the question?
3. Am I searching the right index or data view?
