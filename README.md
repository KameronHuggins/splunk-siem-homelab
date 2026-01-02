# Splunk SIEM Homelab (Windows Server 2022 + Sysmon) — SOC-Style Detections

This repo documents two SIEM detection projects built in a 3-VM lab using **Splunk** to ingest and analyze Windows telemetry.

## Lab Overview
**VMs**
- **Ubuntu Server**: Splunk Enterprise (SIEM)
- **Windows Server 2022**: log source + target host
- **Kali Linux**: attack simulation host (lab-only)

**Data Sources**
- Windows Security Events:
  - **4625** — Failed logon (primary brute-force signal)
  - **4624** — Successful logon (used to detect “success after failures”)
  - **5156** — Windows Filtering Platform allowed connection (network visibility)
- **Sysmon**: installed to enrich endpoint telemetry (process + network context)

## Projects
### 1) Authentication Brute-Force Detection (4625/4624)
Detect repeated failed logons, identify source IPs and targeted accounts, and flag suspicious success events following bursts of failures.

→ `projects/01-auth-bruteforce/README.md`

### 2) RDP/SMB Network Activity + Correlation (5156 + 4625)
Monitor inbound connections to sensitive services (RDP/SMB) and correlate network activity with authentication failures for higher-confidence alerting.

→ `projects/02-wfp-5156-correlation/README.md`

## Skills Demonstrated
- Splunk ingestion and field-driven search building
- Detection engineering (thresholding, time windows, correlation)
- Windows log analysis (auth + network telemetry)
- Dashboarding for SOC triage
- Documentation and evidence-driven validation

## Notes
All activity was performed in an isolated lab environment for defensive learning and detection validation.
