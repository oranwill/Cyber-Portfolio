# ELK Stack SOC Lab

Built a Windows-based ELK SIEM environment to collect and analyze endpoint security telemetry using Sysmon, Winlogbeat, Elasticsearch, and Kibana. The lab focuses on KQL threat hunting, Windows process analysis, PowerShell investigation, event correlation, and SOC-style incident triage.

## Topics
- Lab architecture
- Virtual machines
- ELK setup
- Kali Linux 
- Sysmon/Winlogbeat setup

---

## Lab architecture
- This lab has 3 Virtual Machines
- Windows VM running ELK as the main SIEM <img width="1022" height="719" alt="Image" src="https://github.com/user-attachments/assets/7aaf15ab-5cc3-4fb0-9a70-bfd91c9a3cec" />
- Kali Linux VM as the attacker <img width="1916" height="990" alt="Image" src="https://github.com/user-attachments/assets/f7d2b2c4-ea8d-497b-9a47-b40c4a54903a" />
- Windows VM as the victim <img width="1026" height="728" alt="Image" src="https://github.com/user-attachments/assets/02986cde-0152-4be3-9377-44bc45503488" />

---

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

---

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

---

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

---

### Investigation 4 — Parent-Child Process Chain Analysis
<img width="1028" height="639" alt="Image" src="https://github.com/user-attachments/assets/21f606d5-5155-44cc-9360-9983a46cb815" />

**Objective:** Analyze a multi-stage Windows process chain using Sysmon process creation telemetry and determine whether the activity required escalation.

**KQL Query:**

```text
event.code : "1" and user.name : "Franklin"
```

**Observed Process Chain:**

```text
powershell.exe
      ↓
   cmd.exe
      ↓
powershell.exe
      ↓
 notepad.exe
```

The investigation initially identified an unusual parent-child relationship involving PowerShell spawning Command Prompt, which subsequently launched another PowerShell process.

Command-line analysis revealed:

```text
cmd.exe /c powershell.exe -NoProfile -Command "Start-Process notepad.exe"
```

The child PowerShell process then executed:

```text
powershell.exe -NoProfile -Command "Start-Process notepad.exe"
```

The final process created was `notepad.exe`.

**Analysis:**

The `PowerShell → CMD → PowerShell` relationship warranted additional investigation because unusual parent-child process relationships can provide valuable indicators of suspicious execution.

Rather than determining the activity was malicious based solely on the process names, I examined the associated command-line telemetry to establish what the processes were instructed to execute.

No suspicious downloads, persistence mechanisms, external network activity, or additional malicious behavior were identified.

**Analyst Verdict:** **Benign**

The activity was initially investigated because of the unusual process chain but was determined to be benign after reviewing the command-line arguments and surrounding activity.

---

### Investigation 5 — Sysmon Network Connection Analysis
<img width="1020" height="631" alt="Image" src="https://github.com/user-attachments/assets/ee0fd347-dbbb-44d2-9121-136e0ac52eb9" />

**Objective:** Use Sysmon network telemetry to identify which process initiated a network connection and determine the purpose of the destination.

**KQL Query:**

```text
event.code : "3" and destination.ip : "192.168.56.10"
```

**Telemetry Analyzed:**

* Sysmon Event ID 3 — Network Connection
* Source IP
* Destination IP
* Destination port
* Initiating process
* User account
* Timestamp

**Observed Connection:**

```text
Process:          powershell.exe
Source IP:        192.168.56.20
Destination IP:   192.168.56.10
Destination Port: 9200
User:             Franklin
```

The investigation identified `powershell.exe` initiating a TCP connection from the Windows endpoint at `192.168.56.20` to the internal ELK server at `192.168.56.10` over port `9200`.

Port `9200` was identified as the Elasticsearch service used by the lab SIEM.

**Analysis:**

Although the destination was a known internal Elasticsearch server, the connection was not automatically considered safe based solely on the internal IP address.

The initiating process, destination service, command-line activity, and surrounding endpoint events would need to be considered together before determining the final disposition.

This investigation demonstrated the importance of correlating process execution with network telemetry rather than analyzing individual security events in isolation.

**Analyst Verdict:** **Investigate Further**

The connection targeted a known internal service, but additional context should be reviewed to verify why PowerShell initiated the connection and whether the behavior was expected.

---

### Investigation 6 — Process and Network Event Correlation
<img width="1023" height="644" alt="Image" src="https://github.com/user-attachments/assets/60f9fdb9-d164-40b2-8679-83bd65e3ebd1" />

**Objective:** Correlate Sysmon process creation and network connection telemetry to reconstruct endpoint activity.

**KQL Query:**

```text
process.name : "powershell.exe" and (event.code : "1" or event.code : "3")
```

Sysmon Event ID `1` was used to identify PowerShell process creation, while Event ID `3` provided network connection telemetry associated with PowerShell.

The correlated activity showed:

```text
PowerShell Process Execution
           ↓
     Sysmon Event ID 1
           ↓
PowerShell Network Activity
           ↓
     Sysmon Event ID 3
           ↓
192.168.56.20 → 192.168.56.10:9200
           ↓
      Elasticsearch
```

**Analyst Summary:**

A PowerShell process was observed executing on the endpoint and initiating a network connection to the internal host `192.168.56.10` over TCP port `9200`. The destination was identified as the Elasticsearch service used by the SIEM environment. The activity would require examination of the PowerShell command line and surrounding endpoint activity before determining whether the connection was expected.

**Skills Demonstrated:**

* Sysmon Event ID 1 analysis
* Sysmon Event ID 3 analysis
* Parent-child process analysis
* PowerShell investigation
* Command-line analysis
* KQL threat hunting
* Network connection analysis
* Process/network event correlation
* Timeline reconstruction
* Evidence-based alert disposition


## Dashboard
<img width="1026" height="711" alt="Image" src="https://github.com/user-attachments/assets/4c6ea1fa-5734-4689-adeb-fa9f57d870a9" />
