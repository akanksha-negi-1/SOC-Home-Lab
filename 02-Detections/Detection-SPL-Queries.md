# Detection SPL Queries

## 1. Suspicious PowerShell Execution

**Purpose:** Detect PowerShell execution using `-ExecutionPolicy Bypass`.

**Telemetry:** Sysmon Event ID `1`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe*"
| search CommandLine="*-ExecutionPolicy Bypass*"
```

---

## 2. Windows Service Creation

**Purpose:** Detect creation of a Windows service.

**Telemetry:** Windows System Event ID `7045`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:System" EventCode=7045
```

---

## 3. Scheduled Task Creation

**Purpose:** Detect creation of a Windows scheduled task.

**Telemetry:** Windows Security Event ID `4698`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:Security" EventCode=4698
```

---

## 4. User Account Creation

**Purpose:** Detect creation of a local Windows user account.

**Telemetry:** Windows Security Event ID `4720`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:Security" EventCode=4720
```

---

## 5. Failed Windows Logon

**Purpose:** Detect failed Windows authentication attempts.

**Telemetry:** Windows Security Event ID `4625`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:Security" EventCode=4625
```

---

## 6. PowerShell Encoded Command

**Purpose:** Detect PowerShell execution using the `-EncodedCommand` parameter.

**Telemetry:** Sysmon Event ID `1`

```spl
index=main host="DESKTOP-46KJBL7" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe*" CommandLine="*-EncodedCommand*"
```
