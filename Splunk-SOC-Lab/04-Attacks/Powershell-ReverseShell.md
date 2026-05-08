# SOC Lab: PowerShell & Reverse Shell Detection Using Splunk

---

This project demonstrates a SOC (Security Operations Center) home lab built using Splunk, Sysmon, Kali Linux, and Windows. The lab was used to simulate PowerShell-based attacker behavior and investigate suspicious activity using Sysmon telemetry and Splunk detection queries.

The project focuses on:

- PowerShell execution monitoring
- Suspicious web request detection
- Reverse-shell-style network behavior
- Event correlation and attack timeline analysis
- Threat investigation using Sysmon Event IDs 1 and 3

## Attack Simulation
# PowerShell Execution

Simulated suspicious PowerShell activity using:
```Splunk Query
powershell -Command "Invoke-WebRequest http://example.com"
```
<img width="1040" height="766" alt="Image" src="https://github.com/user-attachments/assets/793d4852-c60b-443e-b8d2-00af10c7a485" />

# Purpose
This generated Sysmon process creation logs for detection analysis.

# Reverse Shell Network Activity

Simulated reverse-shell-style outbound TCP behavior using PowerShell and Netcat.

Kali Listener
```Kali Listener
nc -lvnp 4444
```
<img width="1058" height="765" alt="Image" src="https://github.com/user-attachments/assets/7e2b1ec4-1c9c-4bbc-9d8f-f62260b2297b" />

PowerShell TCP Connection
```PowerShell TCP Connection
$client = New-Object System.Net.Sockets.TCPClient("192.168.56.10",4444)
```
<img width="1031" height="760" alt="Image" src="https://github.com/user-attachments/assets/90f893f1-6466-4029-8f17-461cd5a034b8" />

# Purpose
This generated Sysmon network connection events (Event ID 3) for investigation.

## Detection Queries
# Suspicious PowerShell Detection

```Splunk Query
index=main EventCode=1 Image="*powershell.exe*"
| search CommandLine="*Invoke-WebRequest*"
| table _time User CommandLine ParentImage
```
<img width="1027" height="360" alt="Image" src="https://github.com/user-attachments/assets/2694d842-6b12-4b87-8911-bd50d80278dd" />

# Reverse Shell Connection Detection

```Splunk Query
index=main EventCode=3 DestinationPort=4444
| table _time Image DestinationIp DestinationPort
```
<img width="1029" height="780" alt="Image" src="https://github.com/user-attachments/assets/6387ca8e-288a-4f8d-b9ee-8adaf9f06839" />

# Purpose
Detects outbound TCP connections associated with reverse-shell-style behavior.

## Investigation Goals

The purpose of this investigation was to identify and analyze suspicious PowerShell activity within the lab environment. Sysmon telemetry and Splunk searches were used to correlate process creation events with outbound network connections.

# Goals:
- Identify suspicious PowerShell execution
- Detect PowerShell-based web request behavior
- Investigate outbound TCP connections to the attacker machine
- Correlate Sysmon Event IDs 1 and 3
- Build an attack timeline using Splunk searches

```Splunk Query
index=main (Image="*powershell.exe*" OR DestinationPort=4444)
| search NOT "splunk"
| search User="WINDOWS\\Franklin"
| sort 0 - _time
| table _time EventCode Image CommandLine DestinationIp DestinationPort User
```
<img width="1014" height="441" alt="Image" src="https://github.com/user-attachments/assets/88ea577a-60b6-489f-8bf7-e4a06a54655e" />

## MITRE ATT&CK Mapping

| Technique | Description                          |
| --------- | ------------------------------------ |
| T1059.001 | PowerShell                           |
| T1105     | Ingress Tool Transfer                |
| T1071     | Application Layer Protocol           |
| T1049     | System Network Connections Discovery |

## Key Findings

- Successfully ingested Sysmon telemetry into Splunk
- Detected suspicious PowerShell execution activity
- Identified outbound TCP connections associated with reverse-shell-style behavior
- Correlated process creation and network telemetry for incident investigation
- Improved understanding of SOC workflows and detection engineering

## Skills Demonstrated

- SIEM Analysis
- Threat Detection
- Event Correlation
- Sysmon Log Analysis
- PowerShell Monitoring
- Network Connection Investigation
- Splunk Query Development
- SOC Investigation Workflow
