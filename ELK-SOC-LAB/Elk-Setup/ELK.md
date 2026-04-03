# ELK Setup

This document contains how I set up my ELK Stack  
These Dashboards, Rules and Alerts is how my ELK Stack was set up

---

## Dashboards

These are my Dashboards for ELK Stack and how I set them up using commands

### KQL Synthx

```kql
Failed logons
winlog.event_id: 4625
Successful logons
winlog.event_id: 4624
Process creation
winlog.event_id: 4688
PowerShell
process.name: "powershell.exe"
Top Event Activity
process.name
```

### Purpose
<img width="1026" height="711" alt="Image" src="https://github.com/user-attachments/assets/7f1d373e-87a1-4108-b5fb-ffb66b3e6c18" />

- Identify Failed Logons
- Identify Successful Logons
- Identify Process creation
- Investigate Powershell Activitiy
- Top Event Activitiy
## Rules

These are my Rules for ELK Stack and how I set them up using commands. Elasticsearch query were used for all.

### Elasticsearch query

```kql
Failed Logon
winlog.event_id: 4625
High Process Creation Activity
winlog.event_id: 4688
Powershell Execution
winlog.channel: "Windows Powershell" AND event code: 403
Suspicious PowerShell ExecutionPolicy Bypass
event.provider: "Powershell" AND event.code: 403
```

### Purpose
<img width="1030" height="726" alt="Image" src="https://github.com/user-attachments/assets/bc2027c1-afd3-4db4-a9c0-a4f14c3e8f0e" />

- Identify Failed Logons
- Identify High Process Creation Activity
- Identify Powershell Executions
- Investigate Suspicious Powershell Executions

## Dashboards

These are the Alerts my Rules Created ELK Stack

### Alerts

```kql
Failed logons
winlog.event_id: 4625
Successful logons
winlog.event_id: 4624
Process creation
winlog.event_id: 4688
PowerShell
process.name: "powershell.exe"
Top Event Activity
process.name
```

### Purpose
<img width="1020" height="713" alt="Image" src="https://github.com/user-attachments/assets/5d758605-347a-4692-ac4f-ef9eaaeb1313" />

- Identify Failed Logons
- Identify High Process Creation Activity
- Identify Powershell Executions
- Investigate Suspicious Powershell Executions
