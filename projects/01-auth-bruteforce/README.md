# Project 01 — Authentication Brute-Force Detection (4625/4624)

## Objective
Build Splunk detections that identify **repeated failed logons** against a Windows Server 2022 host, then elevate severity if a **successful logon** occurs after many failures (possible credential compromise).

## Environment
- **Splunk Enterprise** on Ubuntu (SIEM)
- **Windows Server 2022** as the log source (Security logs + Sysmon)
- **Kali Linux** used to generate controlled authentication attempts (lab-only)

## Telemetry
### Windows Security Log
- **4625 — Failed logon**
- **4624 — Successful logon**

Common pivots:
- **User/account** targeted
- **Source IP / workstation**
- **LogonType** (e.g., RemoteInteractive often maps to RDP; Network often maps to SMB/remote auth)

> Field names can vary depending on parsing/add-ons. In searches below, I use `coalesce()` to handle common variants.

---

## Detection 1 — Brute-force threshold by source (fails per time window)

**Purpose:** If a single source generates many 4625 events in a short window, alert.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| eval src=coalesce(Source_Network_Address, IpAddress, src_ip, WorkstationName)
| eval user=coalesce(Account_Name, TargetUserName)
| bin _time span=5m
| stats count AS fails dc(user) AS unique_users values(user) AS users by _time src
| where fails >= 10
| sort -fails
```
## Detection 2 — Reduce noise with LogonType (optional tuning)

**Purpose:** focus on remote/network logons that are more likely to be RDP/SMB-related.
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| eval src=coalesce(Source_Network_Address, IpAddress, src_ip, WorkstationName)
| eval user=coalesce(Account_Name, TargetUserName)
| search LogonType IN (3,10)
| stats count AS fails values(LogonType) AS logon_types values(user) AS users by src
| where fails >= 10
| sort -fails
```

## Detection 3 — “Success after failures” (higher confidence)

**Purpose:** flag when a 4624 successful logon happens after repeated 4625 failures for the same user/source.

```spl
index=wineventlog sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval src=coalesce(Source_Network_Address, IpAddress, src_ip, WorkstationName)
| eval user=coalesce(Account_Name, TargetUserName)
| sort 0 user src _time
| streamstats count(eval(EventCode=4625)) AS prior_fails by user src
| where EventCode=4624 AND prior_fails >= 5
| table _time user src prior_fails
| sort -prior_fails
```

**Validation steps** (what I did to prove it worked)

-Generated repeated failed logons against the Windows Server 2022 host in an isolated lab.
-Verified 4625 events appeared in Splunk and identified the top source + targeted accounts.
-Tested a successful logon after multiple failures and verified Detection 3 behavior.
-Captured screenshots of results for evidence.

## MITRE ATT&CK mapping

T1110 — Brute Force
T1078 — Valid Accounts (only if a success occurs after repeated failures)

