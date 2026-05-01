# AI SOC Log Analyzer.

Overview

This project is a Python-based AI cybersecurity tool that analyzes system log data and provides SOC-style triage output, including severity classification, suspicious activity detection, and recommended response actions.
The tool integrates simulated SOC workflows by combining Splunk log analysis with AI-driven interpretation to assist in identifying potentially malicious behavior.

## Features

- AI-powered log analysis
- Severity classification (Low, Medium, High)
- Suspicious activity detection
- Recommended response actions
- Multi-line log input support
## Lab architecture

- Python <img width="1017" height="172" alt="Image" src="https://github.com/user-attachments/assets/c58a5597-b8f0-4832-a363-47eaeb1287d6" />
- OpenAI API 
- Splunk (SIEM)
- Sysmon (Windows Event Logging)
## AI TOOL

<img width="1030" height="763" alt="Image" src="https://github.com/user-attachments/assets/2142d5b2-fe48-4781-8d25-6e9d3c92f103" />

## Project Workflow
1. Generate activity on a Windows endpoint
2. Collect logs using Sysmon
3. Forward logs to Splunk via Universal Forwarder
4. Query logs in Splunk
5. Extract relevant events
6. Analyze events using the AI SOC Log Analyzer
## Example Splunk Query

```spl
index=* EventCode=1
| sort 0 - _time
| head 10
| table _time host Image CommandLine ParentImage User
```

<img width="1032" height="715" alt="Image" src="https://github.com/user-attachments/assets/1123ad3b-2963-419f-a946-5b148561f791" />

## Example Input

```spl
EventCode=1
Image=powershell.exe
CommandLine=powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process"
ParentImage=cmd.exe
User=LAB\user
Host=Windows
```

## Example Output

Severity: Medium  
Suspicious: Yes  
Reason: PowerShell was launched from cmd. exe with '-NoProfile' and '-ExecutionPolicy Bypass', which are commonly used to evade script restrictions, even though the command itself is benign (Get-Process').
Recommended Action: Verify whether this PowerShell usage was expected; review parent process activity and any
related command history for further suspicious behavior.  
<img width="1034" height="774" alt="Image" src="https://github.com/user-attachments/assets/db3cce0f-1f67-4afe-a4dd-bdfd6d1de267" />

## Example Input

```spl
EventCode=1
Image=powershell.exe
CommandLine=powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA
ParentImage=winword.exe
User=LAB\user
Host=Windows
```

## Example Output  
Severity: High  
Suspicious: Yes  
Reason: PowerShell was launched hidden from Microsoft Word with ExecutionPolicy Bypass and an encoded command, which is a common malware execution pattern.  
Recommended Action: Isolate the host, investigate the Word document and PowerShell activity, and hunt for related malicious files or persistence.  
<img width="1026" height="767" alt="Image" src="https://github.com/user-attachments/assets/057e9c46-31f0-49da-8055-5a3567e16f33" />

## Key Learning Outcomes
- Built an AI-assisted SOC analysis tool
- Practiced SIEM log analysis using Splunk
- Understood Sysmon event logging and process creation events
- Integrated automation into cybersecurity workflows
## Future Improvements
- Automate log ingestion directly from Splunk API
- Batch log analysis
- Risk scoring per host
- Web-based interface/dashboard
