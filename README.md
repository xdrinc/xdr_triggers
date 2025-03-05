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

***NOTE:*** You need to run the powershell version in Powershell-Core 7, and you need to run it as admin.

This does all the same things as the two batch files, except 
* They do it faster
* There's a check for your local subnet, so it scans that subnet, instead. 
* It adds some more things which your EDR will find threatening (but aren't actually dangerous)

If you have trouble with the powershell one, hit up mikesim@cisco.com . I might even answer.
