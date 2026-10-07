# SOC Analyst Home Lab
Splunk Enterprise lab built to practice L1 SOC skills: log collection, detection, and alert triage.

## Lab setup
- Splunk Enterprise on an Ubuntu Server VM (VirtualBox, host-only network)
- Splunk Universal Forwarder on a Windows 11 host
- Log sources: Windows Security, System, PowerShell

## Detections
| # | Detection | MITRE ATT&CK | Severity |
|---|-----------|--------------|----------|
| 1 | Brute force: multiple failed logons | T1110 | High |

## Skills practiced
SPL, Windows event log analysis, alert tuning, MITRE ATT&CK mapping, forwarder troubleshooting.
