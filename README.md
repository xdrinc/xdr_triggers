# Batch File Triggers

These files are emulation batch files designed to safely trigger security alerts

The 2 batch files were created for all MS supported versions of Windows

The "Cisco Cisco XDR Windows Triggers" version gives user control menu for each detection trigger or to run all 4

The "Cisco XDR Windows Triggers-no prompts" version is intended to be scheduled to run periodically without any user prompting

These files will create 6 XDR Incidents
  1) 2X endpoint detections: LSASS Memory Dump critical alert and W32.ComsvcsDumped Medium Alert
  2) 2X NVM detections: Use of Environment Variables and Content Download Using Powershell Critical Alerts
  3) 1 Network detection: DNS Abuse critical alert
  4) 1 Firewall detection: Potentially Harmful Hidden File Extension

XDR will correlate these 4 telemetry sources and 6 detections all aggregated to the associated host.
Note: If this batch file is applied to several hosts, XDR will correlate the hosts together based on MITRE detections
Note: Running in administrative mode is not necessary. No additional tools are required.
Expect this file to take 5 to 10 minutes to run...

To avoid this file being quarantined by EDR prior to execution, it is advised to place the EDR in audit before downloading.

For questions and modifications, contact darhicks@cisco.com


# Powershell trigger

***NOTE:*** You need to run the powershell version in Powershell-Core 7, and you need to run it as admin. You can get that from [Microsoft](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5).

This does all the same things as the two batch files, except 
* They do it faster
* There's a check for your local subnet, so it scans that subnet, instead. 
* It adds some more things which your EDR will find threatening (but aren't actually dangerous)

## Usage
1. Either put your EDR in audit mode, or save the file somewhere which is excluded by anti-malware scanning.
2. In your powershell window, set your execution policy to "Bypass"
``` powershell
Set Execution-Policy Bypass
```
3. Run ./triggerscript.ps1 from that directory using pwsh (Powershell 7 Core). If you're a local admin, it'll automatically continue. If you run it as a regular user, it'll spawn a UAC window, and then a new window, if you have local admin rights. If you're not a local admin, it'll exit.
4. Select one of the five menu options, or just wait ten seconds, and it'll run all scans.
5. When it gets to the network scan (about two seconds later; don't go anywhere) it'll prompt you if you want to scan the local subnet (the default) or a remote subnet ***(MUST*** be an RFC-1918 address.) Make your choice, and enter a network in CIDR notation.
6. Go grab a coffee or something; this takes a while.
7. Enjoy watching XDR light up like a Christmas tree.

If you have trouble with the powershell one, hit up mikesim@cisco.com . I might even answer.
