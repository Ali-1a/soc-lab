# Elastic Stack: The Basics

## What it is

The Elastic Stack (ELK) collects logs from many sources, stores them in one place, and lets an analyst search and visualise them. It does the same job as Splunk with different components and a different query language.

## Components

| Component | Role | Splunk equivalent |
|---|---|---|
| **Beats** | Lightweight agents that ship logs from hosts | Universal Forwarder |
| **Logstash** | Receives, parses and normalises logs | Indexer (parsing) |
| **Elasticsearch** | Stores and indexes the data, answers searches | Indexer (storage) |
| **Kibana** | Web interface: search, visualisations, dashboards | Search Head |

Data flow:

```
Hosts → Beats → Logstash → Elasticsearch → Kibana → Analyst
```

## Discover tab

- **Data view** (top left) selects which data you search, like `index=` in Splunk.
- **Time picker** (top right) defaults to a short window. Old lab data needs an **Absolute** range.
- **Field list** (left): click a field name to see its top 5 values and their share.
- **⊕ next to a field** adds it as a table column. Fewer columns make an investigation easier to read.
- **Histogram**: a tall bar is a spike. Click it to zoom into that period.

## KQL essentials

```
field : value                          # equals
field : "value with spaces"            # quote values that contain spaces
not field : value                      # exclude
a : x and b : y                        # both conditions
field : (x or y)                       # either value for the same field
field : val*                           # wildcard
```

Field names are case-sensitive. `Source_State` and `source_state` are different fields, so I copy the name from the field list instead of guessing.

## Visualisations and dashboards

- A **table** visualisation with two fields (for example user and source IP) shows the relationship between them at a glance.
- Filtering a visualisation (for example on failed connections) turns it into a quick answer to "who is failing, and from where?"
- Saved visualisations can be grouped into a **dashboard** for daily monitoring.

## Lessons for real investigations

1. **Empty results usually mean a wrong filter, not missing data.** Check three things in order: the search box (leftover text), the time range, and the data view.
2. **Investigate spikes.** Zoom into the spike, then check the top values of the source IP and user fields to find what caused it.
3. **Watch the time zone.** The same event can carry two timestamps in different time zones. Reports should always state the time zone.
4. **Terminated users matter.** VPN activity from an account after the owner left the company points to either a gap in offboarding or a compromised account. Both need escalation.
5. **Many failed logins from one user** can mean brute force. The next question is whether a successful login followed.
