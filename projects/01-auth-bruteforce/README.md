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

**Idea:** If a single source generates many 4625 events in a short window, alert.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| eval src=coalesce(Source_Network_Address, IpAddress, src_ip, WorkstationName)
| eval user=coalesce(Account_Name, TargetUserName)
| bin _time span=5m
| stats count AS fails dc(user) AS unique_users values(user) AS users by _time src
| where fails >= 10
| sort -fails

