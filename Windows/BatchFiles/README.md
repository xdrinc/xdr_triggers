# Batch File Triggers
(version 10 adds administrator check, revised NVM detection, and new abuse IPs changed from Comcast to Test-Net and Cisco IPs)

These files are emulation batch files designed to safely trigger security alerts

The 2 batch files were created for all MS supported versions of Windows

The "Cisco XDR Windows Triggers" version gives user control menu for each detection trigger or to run all 4

The "Cisco XDR Windows Triggers-no prompts" version is intended to be scheduled to run periodically without any user prompting with the same results.

These files will create 6 XDR Incidents
  1) 2X endpoint detections: LSASS Memory Dump critical alert and W32.ComsvcsDumped Medium Alert
  2) 1 NVM detection: Curl command Telegram
  3) 1 Network detection: DNS Abuse critical alert
  4) 1 Firewall detection: Potentially Harmful Hidden File Extension

XDR will correlate these 4 telemetry sources and 6 detections all aggregated to the associated host/s.
Note: If this batch file is applied to several hosts, XDR will correlate the hosts together based on MITRE detections
Note: Running in administrative is preferred for the CURL command. No additional tools are required.
Expect this file to take 5 to 10 minutes to run...

IMPORTANT: To avoid this file being quarantined by EDR prior to execution, it is advised to place the EDR in audit before downloading. 

For questions and modifications, contact darhicks@cisco.com
