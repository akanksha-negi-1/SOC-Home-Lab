# SOC Home Lab

An end-to-end Security Operations Center (SOC) home lab built using Splunk Enterprise, Sysmon, Windows Event Logs, and a Windows endpoint.

## Project Overview

This project demonstrates a complete SOC detection and investigation workflow in a controlled lab environment.

Security-relevant activities were intentionally simulated on a Windows endpoint and monitored through Splunk Enterprise. The resulting telemetry was used to build detections, generate real-time alerts, investigate events, map activity to MITRE ATT&CK, and document the results.

## Objective

- Build a functional SOC monitoring environment.
- Collect Windows and Sysmon security telemetry.
- Develop and validate security detections in Splunk.
- Generate and investigate real-time alerts.
- Map detected activity to MITRE ATT&CK.
- Document investigations and incident findings.
- Build a monitoring dashboard.

## Lab Architecture

```text
Controlled Activity
       ↓
Windows 10 VM
       ↓
Splunk Enterprise
       ↓
Detection
       ↓
Real-Time Alert
       ↓
Investigation
       ↓
MITRE ATT&CK Mapping
       ↓
Incident Documentation
       ↓
SOC Dashboard
```

## Tools & Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Windows Event Logs
- Sysmon
- MITRE ATT&CK

## Detections Implemented

| Detection | Telemetry | Event ID |
|---|---|---:|
| Suspicious PowerShell Execution | Sysmon | 1 |
| Windows Service Creation | Windows System | 7045 |
| Scheduled Task Creation | Windows Security | 4698 |
| User Account Creation | Windows Security | 4720 |
| Failed Windows Logon | Windows Security | 4625 |
| PowerShell Encoded Command | Sysmon | 1 |

Each detection was tested using controlled activity and configured to generate a real-time Splunk alert.

Detection queries are documented in [`02-Detections/Detection-SPL-Queries.md`](02-Detections/Detection-SPL-Queries.md).

## Investigation

The generated alerts were investigated using the underlying endpoint telemetry.

Investigation evidence includes relevant process, account, command-line, service, scheduled task, and other event fields depending on the detection.

The investigation results are documented in [`03-Investigations/Investigation-Notes.md`](03-Investigations/Investigation-Notes.md).

## MITRE ATT&CK Mapping

Detected activities were mapped to relevant MITRE ATT&CK techniques and sub-techniques where supported by the available evidence.

The complete mapping is documented in [`04-MITRE-Mapping/MITRE-Mapping.md`](04-MITRE-Mapping/MITRE-Mapping.md).

## Incident Report

The project includes an overall incident report covering:

- Incident summary
- Detection and investigation summary
- Response and containment
- Lessons learned
- Limitations
- Conclusion

The complete report is available in [`05-Incident-Report/Incident-Report.md`](05-Incident-Report/Incident-Report.md).

## Dashboard

A Splunk dashboard was created to provide visibility into the monitored Windows endpoint.

The dashboard includes:

- Relevant security event volume by detection
- Events by telemetry source

The dashboard is available in [`06-Dashboard/`](06-Dashboard/).

## Key Learnings

- Security telemetry should be verified before building detections around it.
- Detection rules should use specific event fields and conditions.
- Alerts must be investigated using the underlying endpoint events.
- MITRE ATT&CK mappings should reflect what the available evidence supports.
- Controlled testing helps validate the complete detection and investigation workflow.

## Limitations

- The lab uses a single Windows endpoint and does not represent a production enterprise environment.
- Simulated activities do not reproduce the complexity of real attacks.
- Some Windows telemetry was available locally but was not ingested into Splunk.
- The failed-logon test generated a single event and therefore could not establish a true brute-force pattern.

## Conclusion

This project demonstrates an end-to-end SOC detection and investigation workflow using Splunk Enterprise, Windows Event Logs, and Sysmon.

The lab provided practical experience with security monitoring, detection engineering, alert investigation, event analysis, MITRE ATT&CK mapping, and security documentation in a controlled environment.
