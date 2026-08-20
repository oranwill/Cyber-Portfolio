# ELK Stack SOC Lab

This folder contains documentation for my home ELK SOC lab.

## Topics
- Lab architecture
- Virtual machines
- ELK setup
- Kali Linux 
- Sysmon/Winlogbeat setup
## Lab architecture
- This lab has 3 Virtual Machines
- Windows VM running ELK as the main SIEM <img width="1022" height="719" alt="Image" src="https://github.com/user-attachments/assets/7aaf15ab-5cc3-4fb0-9a70-bfd91c9a3cec" />
- Kali Linux VM as the attacker <img width="1916" height="990" alt="Image" src="https://github.com/user-attachments/assets/f7d2b2c4-ea8d-497b-9a47-b40c4a54903a" />
- Windows VM as the victim <img width="1026" height="728" alt="Image" src="https://github.com/user-attachments/assets/02986cde-0152-4be3-9377-44bc45503488" />
##  SOC Investigations
After building and configuring the ELK Stack environment, I expanded the lab to focus on hands-on SOC analysis and threat hunting. Using Sysmon, Winlogbeat, Elasticsearch, Kibana, and KQL, I analyzed Windows endpoint telemetry, investigated PowerShell activity, examined parent-child process relationships, and correlated multiple events to determine whether activity was benign or required further investigation.

### Investigation 1 — PowerShell Process Analysis

<img width="1024" height="637" alt="Image" src="https://github.com/user-attachments/assets/2b4ad598-5235-4138-ada1-c8b894e8fd28" />
Objective: Analyze PowerShell process creation and determine whether the activity represented suspicious behavior.
KQL Query:
process.name : "powershell.exe"

Telemetry Analyzed:

- Sysmon Event ID 1 — Process Creation
- Username
- Process name
- Process command line
- Parent process
- Timestamp

Findings:

The investigation identified powershell.exe being launched by explorer.exe under the user account Franklin.

The command line showed a standard PowerShell launch with no encoded commands, downloads, execution-policy bypasses, or other immediately suspicious parameters.

Analyst Verdict: Benign

PowerShell execution alone does not indicate malicious activity. The parent-child relationship and command-line arguments were consistent with a user manually launching PowerShell.

### Investigation 2 — PowerShell Execution Policy Bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion"

KQL Hunt:

process.name : "powershell.exe" and process.command_line : "*ExecutionPolicy*"

Findings:

The process used:

- NoProfile
- ExecutionPolicy Bypass

and executed Get-ComputerInfo to retrieve operating system information.

Although retrieving system information is not inherently malicious, the combination of ExecutionPolicy Bypass and system discovery warranted additional investigation.

The event demonstrated why analysts should evaluate PowerShell based on context rather than automatically classifying PowerShell activity as malicious.

Analyst Verdict: Investigate Further

Additional investigation would include reviewing surrounding process activity, network connections, downloaded files, additional child processes, user behavior, and whether the activity was expected for the account.

### Investigation 3 — System Discovery Timeline
Objective: Correlate multiple endpoint events and reconstruct a sequence of potentially suspicious activity.

The simulated activity included:

whoami
hostname
ipconfig
Get-ComputerInfo
cmd.exe /c "whoami && hostname"

Using Sysmon process-creation telemetry in Kibana, I reconstructed the sequence of commands and analyzed the activity as a timeline rather than evaluating each event independently.

Observed Behavior:

1. User/account information was queried.
2. The system hostname was identified.
3. Network configuration and IP information were collected.
4. Operating system information was retrieved.
5. Additional commands were executed through cmd.exe.

Individually, commands such as whoami, hostname, and ipconfig are common administrative commands and are not inherently malicious.

When observed together, however, they can represent system and network discovery behavior that warrants additional investigation—particularly when occurring unexpectedly or following suspicious authentication or process activity.

Analyst Verdict: Investigate Further

Before escalating or closing the activity, I would establish additional context by determining who initiated the commands, whether the account normally performs administrative activity, what occurred immediately before and after the commands, and whether there were suspicious network connections, file downloads, or additional process execution.

##  Skills Demonstrated
- Windows endpoint telemetry analysis
- Sysmon Event ID 1 investigation
- Winlogbeat log collection
- Elasticsearch event ingestion
- Kibana Discover
- KQL threat hunting
- PowerShell command-line analysis
- Parent-child process analysis
- Event correlation
- Timeline reconstruction
- System discovery analysis
- Alert triage
- Benign vs. suspicious activity classification
- Evidence-based escalation decisions

## Dashboard
<img width="1026" height="711" alt="Image" src="https://github.com/user-attachments/assets/4c6ea1fa-5734-4689-adeb-fa9f57d870a9" />
