# ELK Threat Hunting Queries

This document contains example threat hunting searches used in my ELK lab environment.  
These searches help identify suspicious behavior using Windows and Sysmon logs ingested into Elasticsearch and reviewed in Kibana.

---

## Process Creation Monitoring

Process creation events help identify programs executed on the system, command-line activity, and suspicious parent-child relationships.

### KQL Query

```kql
event.code:"1"
```

### Purpose
<img width="1032" height="724" alt="Image" src="https://github.com/user-attachments/assets/6b29608b-b12d-4694-8785-e7ffe3acbffd" />
<img width="1024" height="723" alt="Image" src="https://github.com/user-attachments/assets/eb7168b1-241f-4180-8ed9-d515ef772eae" />
- Identify executed programs
- Review command-line activity
- Investigate suspicious processes

---

## PowerShell Activity

PowerShell is commonly used in attacks to execute scripts, perform reconnaissance, and download payloads.

### KQL Query

```kql
process.name: "powershell.exe" and process.name:"powershell.exe"
```

### Purpose
<img width="1027" height="719" alt="Image" src="https://github.com/user-attachments/assets/a9a126f2-3baf-4fec-a37c-3181bf9d9912" />
- Detect PowerShell execution
- Investigate suspicious command-line usage
- Identify script-based activity

---

## Command Prompt Activity

Command prompt activity can be useful for identifying manual attacker actions or suspicious command execution.

### KQL Query

```kql
event.code:"1" and process.name:"cmd.exe"
```

### Purpose
<img width="1018" height="720" alt="Image" src="https://github.com/user-attachments/assets/7b905a73-4d26-4672-80df-5596e3458b29" />
- Detect command shell execution
- Investigate administrative or suspicious activity
- Review command-line behavior

---

## Network Connection Monitoring

Network connection events help identify processes communicating with external or internal systems.

### KQL Query

```kql
event.code:"3"
```

### Purpose
<img width="1028" height="715" alt="Image" src="https://github.com/user-attachments/assets/038c02f0-b081-4b3c-91d7-b85ffb8a6a8e" />
- Identify outbound network connections
- Detect unexpected process communication
- Investigate possible command-and-control activity

---

## 

This query helps identify PowerShell making network connections.

### KQL Query

```kql
event.code:"3" and process.name:"powershell.exe"
```

### Purpose
<img width="1027" height="722" alt="Image" src="https://github.com/user-attachments/assets/8d779d6b-d9bf-496d-a4fd-376cdda2178b" />
- Detect PowerShell-initiated network traffic
- Investigate possible payload downloads
- Review suspicious remote connections

---

## Suspicious Parent-Child Process Relationships

Attackers often use process chains such as `cmd.exe` launching `powershell.exe`.

### KQL Query

```kql
event.code:"1" and process.parent.name:"cmd.exe" and process.name:"powershell.exe"
```

### Purpose
<img width="1027" height="721" alt="Image" src="https://github.com/user-attachments/assets/ef0fe841-97e6-44f3-9edb-545c8aa32821" />
- Detect suspicious process chains
- Identify command shell to PowerShell execution
- Investigate possible living-off-the-land activity

---

## Explorer Launching Unusual Processes

User-driven applications often launch from `explorer.exe`, but this can still be useful for investigation.

### KQL Query

```kql
event.code:"1" and process.parent.name:"explorer.exe"
```

### Purpose
<img width="1020" height="722" alt="Image" src="https://github.com/user-attachments/assets/11b25e57-9072-4116-9078-d324c9cbfc4d" />
- Review user-launched applications
- Identify unusual executables launched from Explorer
- Investigate suspicious user activity

---

## PowerShell Download Behavior

This query looks for PowerShell commands commonly associated with file downloads.

### KQL Query

```kql
event.code:"1" and process.name:"powershell.exe" and process.command_line:("*Invoke-WebRequest*" or "*download*" or "*wget*" or "*curl*")
```

### Purpose
<img width="1065" height="715" alt="Image" src="https://github.com/user-attachments/assets/661031ff-dacd-40b2-a677-fdbb8da53ee6" />
- Detect PowerShell download commands
- Investigate possible payload retrieval
- Identify suspicious script execution

---

## Summary

These ELK queries were used during my lab exercises to practice:

- Threat hunting in Kibana
- Process monitoring
- PowerShell investigation
- Network activity analysis
- Parent-child process review

The lab environment included:

- Windows host with Sysmon
- Logs ingested into Elasticsearch
- Analysis performed in Kibana
- Kali Linux used to generate lab activity

These exercises demonstrate how endpoint telemetry can be used to investigate suspicious behavior in a SIEM environment.
