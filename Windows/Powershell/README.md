


# XDR Trigger Simulation Script

## Overview
This PowerShell script simulates various cybersecurity incidents to trigger detection alerts in an Extended Detection and Response (XDR) system. It includes:

- **EDR Simulation**: Memory dumping, Mimikatz execution.
- **NDR Simulation**: UDP-based C2 communication, malicious file downloads.
- **Firewall Simulation**: Random IP-based HTTP requests.
- **NVM Simulation**: Various MITRE ATT&CK TTPs, including obfuscation, command execution, and DNS abuse.

## Prerequisites
### Install PowerShell Core 7.5+
The script requires **PowerShell Core (7.5 or later)** for execution.

#### Windows:
1. Download PowerShell Core from the official Microsoft site:
   ```powershell
   winget install --id Microsoft.PowerShell -e
   ```
2. Verify installation:
   ```powershell
   pwsh --version
   ```

#### Linux/macOS:
1. Install via package manager:
   ```sh
   curl -sSL https://aka.ms/install-powershell.sh | bash
   ```
2. Verify installation:
   ```sh
   pwsh --version
   ```

## Usage Instructions
### 1. Download and Execute the Script
To execute the script **without saving to disk**:
```powershell
pwsh -ExecutionPolicy Bypass -NoProfile -Command "iwr -UseBasicParsing 'https://raw.githubusercontent.com/xdrinc/xdr_triggers/main/triggerscript.ps1' | iex"
```

### 2. Running the Script
When executed, the script presents a menu:
```powershell
Choose an option:
1) EDR Trigger
2) NVM Trigger
3) NDR Trigger
4) Firewall Trigger
5) ALL TRIGGERS (default after 10s)
```

- **If no input is provided within 10 seconds, it defaults to ALL TRIGGERS.**

### 3. Output Report
- The script logs the success/failure of each attack simulation.
- A final report is stored in:
  ```
  C:\Users\<YourUser>\Downloads\Trigger_Report.txt
  ```
- The user is notified at the end about the report location.

## MITRE ATT&CK Coverage
The script simulates several **MITRE ATT&CK Tactics & Techniques**, including:
- **Credential Access** (T1003.001, T1059.001)
- **Defense Evasion** (T1027.010, T1564.001)
- **Command & Control** (T1041, T1090.003)
- **Execution** (T1059.001)
- **Exfiltration** (T1105)

## Notes
- This script is for **training and detection validation purposes only**.
- Use it only in **controlled environments** with proper authorization.
- Running this in a **production environment** may trigger security alerts.

## Troubleshooting
### 1. PowerShell Execution Policy Errors
If execution is blocked:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### 2. Script Not Running in PowerShell Core
Ensure you are using PowerShell 7.5+:
```powershell
pwsh -ExecutionPolicy Bypass -File triggerscript.ps1
```

### 3. Network Scan Not Detecting Hosts
- Ensure **Windows Defender Firewall** is disabled (or configured to allow ICMP pings).
- Run as **Administrator**:
  ```powershell
  Start-Process pwsh -Verb RunAs
  ```

---
_If you have questions or concerns, contact Mike Simone (mikesim@cisco.com). I won't answer, but it will make you feel better._

