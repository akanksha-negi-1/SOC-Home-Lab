# Investigation Notes

## Investigation 1: Suspicious PowerShell Execution

| Field | Value |
|---|---|
| **Time** | `2026-10-22 13:27:05.048` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| **Event ID** | `1` |
| **Process ID** | `2808` |
| **Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Command Line** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-Lab-Detection-Test-02'"` |
| **Current Directory** | `C:\Users\SOCUser\` |
| **User** | `DESKTOP-46KJBL7\SOCUser` |
| **Integrity Level** | `Medium` |
| **SHA256** | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| **Parent Process ID** | `3120` |
| **Parent Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

---

## Investigation 2: Windows Service Creation

| Field | Value |
|---|---|
| **Time** | `2026-10-22 13:57:12.106` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:System` |
| **Event ID** | `7045` |
| **Service Name** | `SOC-Lab-Detection-Service-2` |
| **Service File Name** | `C:\Windows\System32\cmd.exe /c exit` |
| **Service Type** | `user mode service` |
| **Service Start Type** | `demand start` |
| **Service Account** | `LocalSystem` |

---

## Investigation 3: Scheduled Task Creation

| Field | Value |
|---|---|
| **Time** | `2026-10-22 14:18:02.790` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:Security` |
| **Event ID** | `4698` |

### Subject

| Field | Value |
|---|---|
| **Account Name** | `SOCUser` |
| **Account Domain** | `DESKTOP-46KJBL7` |

### Task Information

| Field | Value |
|---|---|
| **Task Name** | `\SOC-Lab-Detection-Task-2` |
| **Author** | `DESKTOP-46KJBL7\SOCUser` |

### Trigger

| Field | Value |
|---|---|
| **Type** | `Time trigger` |
| **Start Boundary** | `2026-10-22 23:59:00` |

### Actions

| Field | Value |
|---|---|
| **Command** | `cmd.exe` |
| **Arguments** | `/c exit` |

### Principals

| Field | Value |
|---|---|
| **User ID** | `DESKTOP-46KJBL7\SOCUser` |
| **Logon Type** | `InteractiveToken` |
| **Run Level** | `LeastPrivilege` |

### Other Information

| Field | Value |
|---|---|
| **Client Process ID** | `2240` |
| **Parent Process ID** | `8284` |

---

## Investigation 4: User Account Creation

| Field | Value |
|---|---|
| **Time** | `2026-10-22 14:27:23.550` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:Security` |
| **Event ID** | `4720` |

### Subject

| Field | Value |
|---|---|
| **Account Name** | `SOCUser` |
| **Account Domain** | `DESKTOP-46KJBL7` |

### New Account

| Field | Value |
|---|---|
| **Account Name** | `SOC-Lab-TestUser-2` |
| **Account Domain** | `DESKTOP-46KJBL7` |

### Attributes

| Field | Value |
|---|---|
| **SAM Account Name** | `SOC-Lab-TestUser-2` |
| **Password Last Set** | `<never>` |
| **Account Expires** | `<never>` |
| **Primary Group ID** | `513` |
| **Logon Hours** | `All` |

---

## Investigation 5: Failed Windows Logon

| Field | Value |
|---|---|
| **Time** | `2026-10-22 14:47:40.361` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:Security` |
| **Event ID** | `4625` |
| **Logon Type** | `2` |

### Account For Which Logon Failed

| Field | Value |
|---|---|
| **Account Name** | `SOCUser` |
| **Account Domain** | `DESKTOP-46KJBL7` |

### Failure Information

| Field | Value |
|---|---|
| **Failure Reason** | `Unknown user name or bad password` |

### Process Information

| Field | Value |
|---|---|
| **Caller Process Name** | `C:\Windows\System32\svchost.exe` |

### Network Information

| Field | Value |
|---|---|
| **Workstation Name** | `DESKTOP-46KJBL7` |
| **Source Network Address** | `127.0.0.1` |
| **Source Port** | `0` |

---

## Investigation 6: PowerShell Encoded Command

| Field | Value |
|---|---|
| **Time** | `2026-10-22 14:58:50.584` |
| **Host** | `DESKTOP-46KJBL7` |
| **Source** | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| **Event ID** | `1` |
| **Process ID** | `9868` |
| **Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Command Line** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABTAE8AQwAtAEwAYQBiAC0ARABlAHQAZQBjAHQAaQBvAG4ALQBUAGUAcwB0AA==` |
| **Current Directory** | `C:\Windows\system32\` |
| **User** | `DESKTOP-46KJBL7\SOCUser` |
| **Integrity Level** | `High` |
| **SHA256** | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| **Parent Process ID** | `4100` |
| **Parent Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
