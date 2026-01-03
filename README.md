# Splunk SIEM Homelab (Windows Server 2022 + Sysmon) — SOC-Style Detections

This repo contains **two SIEM detection projects** built in a **3-VM lab** using **Splunk** to ingest and analyze Windows telemetry, then validate detections with controlled lab activity.

## Lab Overview
- **Ubuntu Server** — Splunk Enterprise (SIEM)
- **Windows Server 2022** — log source + target host (Security logs + Sysmon)
- **Kali Linux** — attack simulation host (lab-only)

## Data Sources
- **Windows Security Events**
  - **4625** — Failed logon (primary brute-force signal)
  - **4624** — Successful logon (used for “success after failures”)
  - **5156** — Windows Filtering Platform permitted a connection (network visibility)
- **Sysmon** — endpoint telemetry enrichment (process + network context)

## Projects

### 1) Authentication Brute-Force Detection (4625 / 4624)
Detect repeated failed logons, identify source IPs + targeted accounts, and flag suspicious successful logons following bursts of failures.  
➡️ **Project link:** [projects/01-auth-bruteforce/README.md](projects/01-auth-bruteforce/README.md)

### 2) RDP/SMB Network Activity + Correlation (5156 + 4625)
Monitor inbound connections to sensitive services (**RDP/SMB**) using 5156 and correlate with authentication failures for higher-confidence alerting.  
➡️ **Project link:** [projects/02-wfp-5156-correlation/README.md](projects/02-wfp-5156-correlation/README.md)

## Skills Demonstrated
- Splunk ingestion + field-driven search building
- Detection engineering (thresholding, time windows, correlation)
- Windows log analysis (auth + network telemetry)
- Evidence-based validation (queries + screenshots)

## Notes
All activity was performed in an isolated homelab environment for defensive learning and detection validation.
