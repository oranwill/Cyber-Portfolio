# Splunk Threat Hunting Queries

This document contains example Splunk queries used during my SOC lab exercises.  
These searches help identify suspicious behavior using Sysmon logs.

---

# Process Creation Monitoring

Sysmon Event ID 1 logs process execution activity.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host Image CommandLine ParentImage User
| sort - _time
<img width="1200" height="816" alt="Image" src="https://github.com/user-attachments/assets/a6d65ec0-8025-44dc-9e75-2605953d9001" />
This query helps identify programs executed on the system and investigate suspicious processes.

---

# PowerShell Activity

PowerShell is commonly used in attacks to execute scripts or download payloads.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*powershell*"
| table _time host Image CommandLine ParentImage
| sort - _time
<img width="1204" height="819" alt="Image" src="https://github.com/user-attachments/assets/4478cc35-b6fd-4503-9ebf-e4eabe252068" />
This query identifies PowerShell execution and the commands used.

---

# Network Connection Monitoring

Sysmon Event ID 3 logs outbound network connections initiated by processes.

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "Network Connections Detected"
| table _time host Image DestinationIp DestinationPort Protocol
| sort - _time
<img width="1228" height="815" alt="Image" src="https://github.com/user-attachments/assets/4cb20087-8286-44c6-80dd-492814be1c25" />
This query allows analysts to detect processes communicating with external hosts.

---

# Suspicious Parent-Child Process Relationships

This query helps detect suspicious process chains.

index=main host="Windows" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| sort 0 - _time
| head 10
| table _time Image CommandLine ParentImage User
<img width="1232" height="815" alt="Image" src="https://github.com/user-attachments/assets/c8c7a9be-4e49-4749-8854-7dc7069931a3" />
Example suspicious patterns include:

- cmd.exe → powershell.exe
- powershell.exe → download command
- explorer.exe → unknown executable

---

# Failed Network Connection Attempts

index=main host="Windows" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by Image DestinationIp DestinationPort
<img width="1232" height="819" alt="Image" src="https://github.com/user-attachments/assets/3e667fcc-a8dd-420c-8e94-55c9352f8cc0" />
This helps identify repeated connection attempts to hosts on the network.

---

# Summary

These queries were used during SOC lab exercises to practice identifying suspicious activity using Splunk and Sysmon telemetry.
