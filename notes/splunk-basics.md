# Splunk: The Basics

## What it is

Splunk is a SIEM: it collects logs from across an organisation, indexes them, and lets an analyst search, correlate and alert on them.

## Components

| Component | Role |
|---|---|
| **Forwarder** | Agent on each host that sends logs to Splunk |
| **Indexer** | Receives, parses and stores the logs in indexes |
| **Search Head** | The web interface where analysts run searches and build dashboards |

If logs from a host are missing, the forwarder on that host is the first thing to check.

## Navigating

- **Search & Reporting** is the main app for investigations.
- The **time picker** next to the search button controls what you see. A real-time window (`rt-...`) only shows new events, so investigations of past activity need **All time** or a specific range.
- The **field sidebar** lists every extracted field. Clicking one shows its values and counts.

## Adding data

- Data is uploaded or forwarded into an **index** (a named container for events).
- The index must exist before upload. Index names accept only **lowercase letters, numbers, `_` and `-`**: `vpn_logs` works, `VPN_logs` fails.

## SPL essentials

```spl
index=vpn_logs                                   # all events in an index
index=* "suspicious-domain"                      # search every index for a term
index=vpn_logs Source_Country!=France            # exclude a value
index=vpn_logs NOT Source_Country=France         # exclude, also keeps events missing the field
```

`!=` returns events where the field exists and has a different value. `NOT` also returns events that do not have the field at all.

## Lessons for real investigations

- Always confirm the time range before trusting "0 results".
- Check counts two ways: run the filtered search, and compare it with the field's value breakdown in the sidebar.
