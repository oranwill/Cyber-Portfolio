## Detection Lab Overview

This section of the portfolio focuses on detecting suspicious activity using log analysis and SIEM tools. The goal of these projects is to simulate how a Security Operations Center (SOC) analyst investigates activity using telemetry collected from endpoints.

In this lab environment, I configured Windows logging and Sysmon to generate detailed system events and forwarded those logs into Splunk for monitoring and analysis.

Using this setup, I investigated several types of activity including:

- Process creation events
- PowerShell execution
- Network connections
- Suspicious downloads
- Potential malware behavior

---

## Lab Setup

The lab environment consists of three virtual machines designed to simulate a small SOC monitoring environment.

**Attacker / Testing Machine**
- Kali Linux
- Used to generate activity and simulate user actions

**Victim Machine**
- Windows 10
- Sysmon installed for enhanced logging
- Generates Windows event logs and Sysmon telemetry

**SIEM Platform**
- Splunk
- Used to ingest logs from the Windows machine
- Allows searching, monitoring, and investigating events

---

## Logging Configuration 

Sysmon was installed on the Windows system to provide detailed telemetry including:

- Process creation events <img width="1033" height="707" alt="Image" src="https://github.com/user-attachments/assets/1eee5654-e446-4b7e-8590-5516b0ea4b1f" />
- PowerShell execution <img width="1023" height="719" alt="Image" src="https://github.com/user-attachments/assets/0621b47c-406d-4b0c-ae4f-e61a3c0d947c" />

These logs were then ingested into Splunk, allowing them to be searched and analyzed through the Splunk interface.

---

## Detection & Investigation Examples

During the lab exercises, I investigated several types of activity including:

### Process Creation Monitoring
Using Sysmon Event ID 1, I analyzed processes that were executed on the system, including command line activity.

Examples observed:
- cmd.exe execution <img width="1197" height="815" alt="Image" src="https://github.com/user-attachments/assets/74179829-1f20-4972-ba82-456dfb32eb47" />
- powershell.exe activity <img width="1008" height="721" alt="Image" src="https://github.com/user-attachments/assets/a6f558a7-ca5f-4ad8-ac16-8b50cd5db021" />
- python processes <img width="1025" height="755" alt="Image" src="https://github.com/user-attachments/assets/9af7b83e-6267-4dc2-a6b5-c53eefc7d860" />

These events allow analysts to identify suspicious or unexpected program execution.

---

### PowerShell Activity

PowerShell execution events were reviewed to understand how scripts and commands are launched within the system.

Monitoring PowerShell activity is important because it is commonly used in attacks for:
- downloading payloads
- executing scripts
- performing system discovery

---

### Network Connection Monitoring

Sysmon network events were reviewed to observe outbound connections initiated by processes on the host.

This type of monitoring helps identify:

- suspicious outbound traffic
- connections initiated by unexpected processes
- potential command-and-control activity

---

### Suspicious Download Investigation

In the lab environment, potential suspicious download activity was observed and analyzed through Splunk logs.

These events were investigated by reviewing:

- process execution logs
- associated network connections
- related system activity

This process simulates how a SOC analyst investigates potential malware activity.

---

## Skills Demonstrated

Through these exercises, the following cybersecurity skills were demonstrated:

- SIEM monitoring using Splunk
- Windows log analysis
- Sysmon event investigation
- Process monitoring
- PowerShell activity analysis
- Network connection monitoring
- Basic incident investigation workflow

---

## Tools Used

- Splunk
- Sysmon
- Windows 10
- Kali Linux
- VirtualBox
