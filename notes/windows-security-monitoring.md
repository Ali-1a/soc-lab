# Windows Security Monitoring

How Windows logging works and how I use it to detect common Windows attacks. Windows is the most common target in enterprise environments, so reading its event logs is a core SOC skill.

## Where Windows logs live

- **Event Viewer** holds separate **channels (logs)**:
  - **Security** — authentication, privilege use, account/policy changes (the SOC workhorse).
  - **System** — services, drivers, OS events.
  - **Application** — app-level events.
  - **PowerShell / Script Block Logging** — what PowerShell actually ran.
  - **Sysmon** — a free Sysinternals tool that adds *much* richer telemetry than the default logs.
- Each event has an **Event ID** — the number is how I search. The skill is knowing which IDs matter.

## Key Event IDs I watch

### Authentication (Security log)
| ID | Meaning |
|---|---|
| **4624** | successful logon |
| **4625** | **failed** logon (many in a row = brute force) |
| **4634 / 4647** | logoff |
| **4672** | special privileges assigned (admin logon) |
| **4648** | logon with explicit credentials (runas — lateral movement hint) |

**Logon Types** on 4624/4625 tell me *how*: `2` interactive (at the keyboard), `3` network (SMB/shares), `10` RemoteInteractive (**RDP**). A Type 10 from an unusual source is worth a look.

### Process & execution
| ID | Meaning |
|---|---|
| **4688** | a new process was created (with the command line, if auditing is on) |
| **Sysmon 1** | process creation with hashes, parent process, full command line |
| **Sysmon 3** | network connection by a process |
| **Sysmon 11** | a file was created |
| **Sysmon 13** | a registry value was set |

### Accounts & persistence
| ID | Meaning |
|---|---|
| **4720** | a user account was created |
| **4728 / 4732 / 4756** | a user added to a (global/local/universal) security group |
| **7045** | a new service was installed (System log) — classic persistence |
| **4697** | a service was installed (Security log) |
| **4698** | a scheduled task was created — classic persistence |

## Mapping to the attack lifecycle

This is why these rooms are grouped by attacker phase, matching **ATT&CK** ([note](mitre-attack.md)):

- **Initial Access** (`Windows Threat Detection 1`): phishing → a document spawns a process. Look for Word/Excel (`winword.exe`, `excel.exe`) as the **parent** of `powershell`/`cmd` (4688 / Sysmon 1). Maps to **T1566 Phishing**.
- **Execution / Discovery** (`Windows Threat Detection 2`): the first commands after breach — `whoami`, `net user`, `ipconfig`, encoded PowerShell. The **parent-child process chain** is the tell.
- **Persistence** (`Windows Threat Detection 3`): staying after reboot — new **service** (7045), **scheduled task** (4698), **Run** registry key (Sysmon 13), or a new admin **account** (4720 + 4732). Maps to **TA0003 Persistence**.

## Why Sysmon matters

Default Windows auditing is thin — 4688 may not even record the command line unless enabled. **Sysmon** records the full command line, the **parent process**, and file/registry/network activity with hashes. The single most valuable field for detection is the **parent-child relationship**: `winword.exe → powershell.exe` is suspicious no matter what the command says.

## Connections to my own work

- The parent-child process logic is pure EDR territory — see [EDR & SIEM note](edr-siem-fundamentals.md). SIEM correlates these IDs across hosts; EDR gives the deep per-process detail.
- "Living off the land" (abusing `powershell`, `wmic`, `certutil`) looks normal until you read the **command line and parent** — a match is not a verdict, the analyst confirms intent.
- Finding the right Event ID is the same discipline as finding the right ATT&CK data source: [read the source, don't guess](mitre-attack.md).

## Takeaways

1. The Event ID is the search key — learn the handful that matter (4624/4625, 4688, 4720, 7045, 4698) rather than memorising all of them.
2. Logon **Type** and the **parent process** turn a raw event into a story.
3. Default logs are thin; Sysmon's command line + parent process is where real detection happens.
