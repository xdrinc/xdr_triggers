This batch file is created for all MS supported versions of Windows
This version is intended to be scheduled to run periodically without any user prompting

The file will create 6 XDR Incidents
  2) endpoint detections: LSASS Memory Dump critical alert and W32.ComsvcsDumped Medium Alert
  2) NVM detections: Use of Environment Variables and Content Download Using Powershell Critical Alerts
  1) Network detection: DNS Abuse critical alert
  1) Firewall detection: Potentially Harmful Hidden File Extension

XDR will correlate these 4 telemetry sources and 6 detections to the same host.

If this batch file is applied to several hosts, XDR will correlate the hosts together based on MITRE detections

Expect this file to take 5 to 10 minutes to run...

For questions and modifications, contact darhicks@cisco.com
