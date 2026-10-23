# Incident Report

## Incident Summary

This incident report documents a controlled SOC lab exercise conducted on a Windows endpoint monitored by Splunk Enterprise.

Six security-relevant activities were intentionally simulated: PowerShell execution with `ExecutionPolicy Bypass`, Windows service creation, scheduled task creation, local user account creation, a failed Windows logon, and encoded PowerShell execution.

Sysmon and Windows Security telemetry were collected by the Splunk Universal Forwarder and analyzed in Splunk Enterprise. Dedicated detections generated real-time alerts for each activity, which were then investigated using the corresponding Splunk events.

The simulated activities were controlled tests and did not represent actual malicious activity or a real security incident.

---

## Detection & Investigation Summary

### 1. Suspicious PowerShell Execution

| Field | Value |
|---|---|
| **Detection** | Sysmon Event ID `1` |
| **Finding** | PowerShell executed with `-ExecutionPolicy Bypass` under the `SOCUser` account. |
| **MITRE ATT&CK** | `T1059.001 - Command and Scripting Interpreter: PowerShell` |

### 2. Windows Service Creation

| Field | Value |
|---|---|
| **Detection** | Windows Event ID `7045` |
| **Finding** | A Windows service was created on the endpoint. |
| **MITRE ATT&CK** | `T1543.003 - Create or Modify System Process: Windows Service` |

### 3. Scheduled Task Creation

| Field | Value |
|---|---|
| **Detection** | Windows Event ID `4698` |
| **Finding** | A Windows scheduled task was created on the endpoint. |
| **MITRE ATT&CK** | `T1053.005 - Scheduled Task/Job: Scheduled Task` |

### 4. User Account Creation

| Field | Value |
|---|---|
| **Detection** | Windows Event ID `4720` |
| **Finding** | A new local Windows user account was created. |
| **MITRE ATT&CK** | `T1136.001 - Create Account: Local Account` |

### 5. Failed Windows Logon

| Field | Value |
|---|---|
| **Detection** | Windows Event ID `4625` |
| **Finding** | A failed authentication attempt was detected. |
| **MITRE ATT&CK** | `Not mapped` |

### 6. PowerShell Encoded Command

| Field | Value |
|---|---|
| **Detection** | Sysmon Event ID `1` |
| **Finding** | PowerShell executed using the `-EncodedCommand` parameter. |
| **MITRE ATT&CK** | `T1059.001 - Command and Scripting Interpreter: PowerShell` |

---

## Response & Containment

Because all activities were intentionally generated as controlled SOC lab simulations, no real incident response or external containment was required.

The simulated Windows service, scheduled tasks, and test user accounts were removed after validation.

Historical Windows and Sysmon events were retained in Splunk to preserve the detection and investigation evidence.

The Splunk alerts remain configured for future testing and monitoring.

---

## Lessons Learned & Limitations

### Lessons Learned

- Security telemetry must be verified before building detections around it.
- Detection rules should use specific event fields and conditions rather than relying only on broad event searches.
- Real-time, per-result alerting is useful for identifying individual security-relevant events.
- Alert investigation requires correlating the detection with the underlying endpoint event.
- MITRE ATT&CK mapping should reflect what the available evidence actually supports rather than forcing a technique onto every detection.
- Controlled testing helps validate the complete workflow from activity generation through detection, alerting, investigation, and reporting.

### Limitations

- The lab uses a single Windows endpoint and does not represent a production enterprise environment.
- The simulated activities were intentionally generated and therefore do not reproduce the complexity of real attacks.
- Some Windows telemetry was available locally but was not ingested into Splunk, limiting which additional detections could be implemented.
- The failed-logon test generated a single event and therefore could not establish a true brute-force pattern.

---

## Conclusion

This SOC lab demonstrated an end-to-end detection and investigation workflow using Splunk Enterprise, Windows Security logs, and Sysmon.

Six security-relevant activities were simulated and successfully detected through dedicated Splunk alerts. Each alert was investigated using the underlying endpoint telemetry and mapped to relevant MITRE ATT&CK techniques where the available evidence supported the mapping.

The exercise provided practical experience with security monitoring, detection engineering, alert investigation, event analysis, MITRE ATT&CK mapping, and incident documentation in a controlled environment.
