# Splunk Threat Hunting Queries

This document contains example Splunk queries used during my SOC lab exercises.  
These searches help identify suspicious behavior using Sysmon logs.

---

# Process Creation Monitoring

Sysmon Event ID 1 logs process execution activity.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host Image CommandLine ParentImage User
| sort - _time



This query helps identify programs executed on the system and investigate suspicious processes.

---

# PowerShell Activity

PowerShell is commonly used in attacks to execute scripts or download payloads.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*powershell*"
| table _time host Image CommandLine ParentImage
| sort - _time
<img width="1200" height="816" alt="Image" src="https://github.com/user-attachments/assets/a6d65ec0-8025-44dc-9e75-2605953d9001" />
This query identifies PowerShell execution and the commands used.

---

# Network Connection Monitoring

Sysmon Event ID 3 logs outbound network connections initiated by processes.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| table _time host Image DestinationIp DestinationPort Protocol
| sort - _time

This query allows analysts to detect processes communicating with external hosts.

---

# Suspicious Parent-Child Process Relationships

This query helps detect suspicious process chains.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host ParentImage Image CommandLine
| sort - _time

Example suspicious patterns include:

- cmd.exe → powershell.exe
- powershell.exe → download command
- explorer.exe → unknown executable

---

# Failed Network Connection Attempts

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by Image DestinationIp DestinationPort

This helps identify repeated connection attempts to hosts on the network.

---

# Summary

These queries were used during SOC lab exercises to practice identifying suspicious activity using Splunk and Sysmon telemetry.
