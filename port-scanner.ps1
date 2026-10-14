param(
    [Parameter(Mandatory=$false)]
    [string]$Target,

    [ValidateSet("Common", "Important", "Full", "Ports")]
    [string]$ScanType = "Common",

    [int]$TimeoutMs = 500,

    [int[]]$Ports
)

# ============================================================
# PORT DEFINITIONS
# ============================================================

$commonPorts = @(
    @{ Port = 21;    Service = "ftp" },
    @{ Port = 22;    Service = "ssh" },
    @{ Port = 23;    Service = "telnet" },
    @{ Port = 25;    Service = "smtp" },
    @{ Port = 53;    Service = "dns" },
    @{ Port = 80;    Service = "http" },
    @{ Port = 110;   Service = "pop3" },
    @{ Port = 111;   Service = "rpcbind" },
    @{ Port = 135;   Service = "msrpc" },
    @{ Port = 139;   Service = "netbios-ssn" },
    @{ Port = 143;   Service = "imap" },
    @{ Port = 443;   Service = "https" },
    @{ Port = 445;   Service = "microsoft-ds" },
    @{ Port = 465;   Service = "smtps" },
    @{ Port = 587;   Service = "submission" },
    @{ Port = 636;   Service = "ldaps" },
    @{ Port = 993;   Service = "imaps" },
    @{ Port = 995;   Service = "pop3s" },
    @{ Port = 1433;  Service = "ms-sql-s" },
    @{ Port = 1521;  Service = "oracle" },
    @{ Port = 2049;  Service = "nfs" },
    @{ Port = 2375;  Service = "docker" },
    @{ Port = 2376;  Service = "docker-ssl" },
    @{ Port = 3000;  Service = "http-alt" },
    @{ Port = 3306;  Service = "mysql" },
    @{ Port = 3389;  Service = "ms-wbt-server" },
    @{ Port = 5432;  Service = "postgresql" },
    @{ Port = 5672;  Service = "amqp" },
    @{ Port = 5900;  Service = "vnc" },
    @{ Port = 6379;  Service = "redis" },
    @{ Port = 6443;  Service = "kubernetes" },
    @{ Port = 8080;  Service = "http-proxy" },
    @{ Port = 8443;  Service = "https-alt" },
    @{ Port = 9000;  Service = "php-fpm" },
    @{ Port = 9090;  Service = "http-alt" },
    @{ Port = 9200;  Service = "elasticsearch" },
    @{ Port = 27017; Service = "mongodb" }
)

$importantPorts = @(
    @{ Port = 21;    Service = "ftp" },
    @{ Port = 22;    Service = "ssh" },
    @{ Port = 23;    Service = "telnet" },
    @{ Port = 80;    Service = "http" },
    @{ Port = 443;   Service = "https" },
    @{ Port = 445;   Service = "microsoft-ds" },
    @{ Port = 1433;  Service = "ms-sql-s" },
    @{ Port = 1521;  Service = "oracle" },
    @{ Port = 3306;  Service = "mysql" },
    @{ Port = 3389;  Service = "ms-wbt-server" },
    @{ Port = 5432;  Service = "postgresql" },
    @{ Port = 8080;  Service = "http-proxy" },
    @{ Port = 8443;  Service = "https-alt" },
    @{ Port = 9000;  Service = "php-fpm" },
    @{ Port = 9090;  Service = "http-alt" },
    @{ Port = 27017; Service = "mongodb" }
)

# ============================================================
# BANNER
# ============================================================

function Show-Banner {

    Clear-Host

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                  POWER PORT SCANNER" -ForegroundColor Cyan
    Write-Host "                    PowerShell Edition" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " TCP connectivity scanner - No external software required."
    Write-Host " Similar concept to Nmap TCP port scanning."
    Write-Host ""
    Write-Host " IMPORTANT:" -ForegroundColor Yellow
    Write-Host " Use this scanner only against systems you are authorized"
    Write-Host " to test."
    Write-Host ""
    Write-Host "------------------------------------------------------------"
    Write-Host " INTERACTIVE SCAN"
    Write-Host "------------------------------------------------------------"
    Write-Host ""
    Write-Host " [1] Common Ports"
    Write-Host "     Scan commonly used TCP ports."
    Write-Host ""
    Write-Host " [2] Important Ports"
    Write-Host "     Scan a smaller set of important infrastructure ports."
    Write-Host ""
    Write-Host " [3] Full Scan"
    Write-Host "     Scan TCP ports 1-65535."
    Write-Host ""
    Write-Host " [4] Custom Ports"
    Write-Host "     Enter your own ports, e.g. 22,80,443,1521."
    Write-Host ""
    Write-Host " [5] Exit"
    Write-Host ""
    Write-Host "------------------------------------------------------------"
    Write-Host " COMMAND LINE USAGE"
    Write-Host "------------------------------------------------------------"
    Write-Host ""
    Write-Host " Common:"
    Write-Host " .\port-scanner.ps1 -Target 10.10.10.100"
    Write-Host ""
    Write-Host " Important:"
    Write-Host " .\port-scanner.ps1 -Target 10.10.10.100 -ScanType Important"
    Write-Host ""
    Write-Host " Full:"
    Write-Host " .\port-scanner.ps1 -Target 10.10.10.100 -ScanType Full"
    Write-Host ""
    Write-Host " Custom:"
    Write-Host " .\port-scanner.ps1 -Target 10.10.10.100 -ScanType Ports -Ports 22,1521,8080"
    Write-Host ""
    Write-Host " Timeout:"
    Write-Host " .\port-scanner.ps1 -Target 10.10.10.100 -TimeoutMs 1000"
    Write-Host ""
    Write-Host " Default timeout: 500 ms"
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
# SERVICE LOOKUP
# ============================================================

function Get-ServiceName {
    param(
        [int]$Port
    )

    $match = $commonPorts | Where-Object { $_.Port -eq $Port }

    if ($null -ne $match) {
        return $match.Service
    }

    return "unknown"
}

# ============================================================
# TCP PORT SCAN
# ============================================================

function Test-TcpPort {
    param(
        [string]$Target,
        [int]$Port,
        [int]$TimeoutMs
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient

    try {

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $asyncResult = $tcpClient.BeginConnect(
            $Target,
            $Port,
            $null,
            $null
        )

        $connected = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)

        $stopwatch.Stop()

        # -------------------------
        # OPEN
        # -------------------------

        if ($connected -and $tcpClient.Connected) {

            return [PSCustomObject]@{
                Port    = $Port
                State   = "OPEN"
                Service = Get-ServiceName $Port
                Latency = $stopwatch.ElapsedMilliseconds
            }
        }

        # -------------------------
        # TIMEOUT
        # -------------------------

        if (-not $connected) {

            return [PSCustomObject]@{
                Port    = $Port
                State   = "TIMEOUT"
                Service = Get-ServiceName $Port
                Latency = $stopwatch.ElapsedMilliseconds
            }
        }

        # -------------------------
        # CLOSED
        # -------------------------

        return [PSCustomObject]@{
            Port    = $Port
            State   = "CLOSED"
            Service = Get-ServiceName $Port
            Latency = $stopwatch.ElapsedMilliseconds
        }

    }
    catch {

        # Connection was actively refused / failed.
        return [PSCustomObject]@{
            Port    = $Port
            State   = "CLOSED"
            Service = Get-ServiceName $Port
            Latency = 0
        }

    }
    finally {

        if ($null -ne $tcpClient) {
            $tcpClient.Close()
        }
    }
}

# ============================================================
# DETERMINE PORTS
# ============================================================

function Get-PortsToScan {

    switch ($ScanType) {

        "Common" {
            return $commonPorts
        }

        "Important" {
            return $importantPorts
        }

        "Full" {
            return (1..65535 | ForEach-Object {
                @{
                    Port    = $_
                    Service = Get-ServiceName $_
                }
            })
        }

        "Ports" {

            if ($null -eq $Ports -or $Ports.Count -eq 0) {
                Write-Host ""
                Write-Host "[ERROR] -ScanType Ports requires -Ports." -ForegroundColor Red
                Write-Host ""
                exit 1
            }

            foreach ($port in $Ports) {

                if ($port -lt 1 -or $port -gt 65535) {
                    Write-Host "[ERROR] Invalid port: $port" -ForegroundColor Red
                    Write-Host "        Valid range: 1-65535"
                    exit 1
                }
            }

            return ($Ports | ForEach-Object {
                @{
                    Port    = $_
                    Service = Get-ServiceName $_
                }
            })
        }
    }
}

# ============================================================
# INTERACTIVE MODE
# ============================================================

$interactiveMode = [string]::IsNullOrWhiteSpace($Target)

if ($interactiveMode) {

    Show-Banner

    # -------------------------
    # TARGET
    # -------------------------

    do {

        $Target = Read-Host "Target IP / Hostname"

        if ([string]::IsNullOrWhiteSpace($Target)) {
            Write-Host "[ERROR] Target cannot be empty." -ForegroundColor Red
        }

    } while ([string]::IsNullOrWhiteSpace($Target))

    Write-Host ""

    # -------------------------
    # SCAN TYPE
    # -------------------------

    do {

        Write-Host "Select scan type:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1] Common"
        Write-Host " [2] Important"
        Write-Host " [3] Full"
        Write-Host " [4] Custom"
        Write-Host " [5] Exit"
        Write-Host ""

        $choice = Read-Host "Choice"

        switch ($choice) {

            "1" {
                $ScanType = "Common"
                $validChoice = $true
            }

            "2" {
                $ScanType = "Important"
                $validChoice = $true
            }

            "3" {
                $ScanType = "Full"
                $validChoice = $true
            }

            "4" {
                $ScanType = "Ports"
                $validChoice = $true
            }

            "5" {
                Write-Host ""
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit 0
            }

            default {
                Write-Host ""
                Write-Host "[ERROR] Invalid choice." -ForegroundColor Red
                Write-Host ""
                $validChoice = $false
            }
        }

    } while (-not $validChoice)

    # -------------------------
    # CUSTOM PORTS
    # -------------------------

    if ($ScanType -eq "Ports") {

        Write-Host ""
        Write-Host "Example: 22,80,443,1521,3389" -ForegroundColor DarkGray

        do {

            $portInput = Read-Host "Enter ports"

            try {

                $Ports = $portInput -split "," |
                    ForEach-Object {
                        [int]$_.Trim()
                    }

                $invalidPorts = $Ports | Where-Object {
                    $_ -lt 1 -or $_ -gt 65535
                }

                if ($Ports.Count -eq 0 -or $invalidPorts.Count -gt 0) {
                    throw "Invalid port"
                }

                $validPorts = $true

            }
            catch {

                Write-Host ""
                Write-Host "[ERROR] Invalid port list." -ForegroundColor Red
                Write-Host "        Valid example: 22,80,443,1521"
                Write-Host ""

                $validPorts = $false
            }

        } while (-not $validPorts)
    }
}

# ============================================================
# RESOLVE TARGET
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SCAN CONFIGURATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target      : $Target"
Write-Host "Scan Type   : $ScanType"
Write-Host "Timeout     : $TimeoutMs ms"

if ($ScanType -eq "Ports") {
    Write-Host "Ports       : $($Ports -join ', ')"
}

Write-Host ""

try {

    $addresses = [System.Net.Dns]::GetHostAddresses($Target)

    if ($addresses.Count -eq 0) {
        throw "No address found."
    }

    $resolvedAddress = $addresses[0].IPAddressToString

    Write-Host "Resolved IP : $resolvedAddress" -ForegroundColor Green
}
catch {

    Write-Host ""
    Write-Host "[ERROR] Unable to resolve target: $Target" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ============================================================
# PREPARE SCAN
# ============================================================

$portsToScan = Get-PortsToScan

Write-Host ""
Write-Host "Ports to scan: $($portsToScan.Count)"
Write-Host ""

if ($ScanType -eq "Full") {

    Write-Host "[!] Full scan may take some time." -ForegroundColor Yellow
    Write-Host "[!] Press Ctrl+C to stop." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Starting scan..." -ForegroundColor Cyan
Write-Host ""

# ============================================================
# SCAN
# ============================================================

$results = @()
$openPorts = @()

$scanStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$totalPorts = $portsToScan.Count
$currentPort = 0

foreach ($portInfo in $portsToScan) {

    $currentPort++

    $port = $portInfo.Port

    # -------------------------
    # Progress for Full Scan
    # -------------------------

    if ($ScanType -eq "Full") {

        $percent = [math]::Round(
            ($currentPort / $totalPorts) * 100,
            1
        )

        Write-Progress `
            -Activity "Scanning $Target" `
            -Status "Port $port ($currentPort / $totalPorts)" `
            -PercentComplete $percent
    }

    # -------------------------
    # Test Port
    # -------------------------

    $result = Test-TcpPort `
        -Target $Target `
        -Port $port `
        -TimeoutMs $TimeoutMs

    $results += $result

    # -------------------------
    # Save OPEN ports
    # -------------------------

    if ($result.State -eq "OPEN") {

        $openPorts += $result

        Write-Host (
            "[OPEN]   {0,-6} {1,-20} {2} ms" -f `
            $result.Port,
            $result.Service,
            $result.Latency
        ) -ForegroundColor Green
    }

    # -------------------------
    # Show CLOSED / TIMEOUT
    # -------------------------

    elseif ($ScanType -ne "Full") {

        if ($result.State -eq "CLOSED") {

            Write-Host (
                "[CLOSED] {0,-6} {1,-20}" -f `
                $result.Port,
                $result.Service
            ) -ForegroundColor DarkGray

        }
        elseif ($result.State -eq "TIMEOUT") {

            Write-Host (
                "[TIMEOUT] {0,-5} {1,-20}" -f `
                $result.Port,
                $result.Service
            ) -ForegroundColor Yellow
        }
    }
}

$scanStopwatch.Stop()

if ($ScanType -eq "Full") {

    Write-Progress `
        -Activity "Scanning $Target" `
        -Completed
}

# ============================================================
# RESULT
# ============================================================

$closedPorts = @(
    $results | Where-Object { $_.State -eq "CLOSED" }
)

$timeoutPorts = @(
    $results | Where-Object { $_.State -eq "TIMEOUT" }
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SCAN RESULT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($results.Count -eq 0) {

    Write-Host "No scan result." -ForegroundColor Yellow

}
else {

    Write-Host (
        "{0,-8} {1,-10} {2,-20} {3}" -f `
        "PORT",
        "STATE",
        "SERVICE",
        "LATENCY"
    )

    Write-Host "------------------------------------------------------------"

    foreach ($result in $results) {

        if ($result.State -eq "OPEN") {

            Write-Host (
                "{0,-8} {1,-10} {2,-20} {3} ms" -f `
                $result.Port,
                $result.State,
                $result.Service,
                $result.Latency
            ) -ForegroundColor Green
        }
        elseif ($result.State -eq "CLOSED") {

            Write-Host (
                "{0,-8} {1,-10} {2,-20}" -f `
                $result.Port,
                $result.State,
                $result.Service
            ) -ForegroundColor DarkGray
        }
        else {

            Write-Host (
                "{0,-8} {1,-10} {2,-20}" -f `
                $result.Port,
                $result.State,
                $result.Service
            ) -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "------------------------------------------------------------"
Write-Host "Target          : $Target"
Write-Host "Scan Type       : $ScanType"
Write-Host "Ports Scanned   : $totalPorts"
Write-Host "Open Ports      : $($openPorts.Count)"
Write-Host "Closed Ports    : $($closedPorts.Count)"
Write-Host "Timeout Ports   : $($timeoutPorts.Count)"
Write-Host "Scan Duration   : $([math]::Round($scanStopwatch.Elapsed.TotalSeconds, 2)) seconds"
Write-Host "------------------------------------------------------------"
Write-Host ""

if ($interactiveMode) {

    Write-Host "Scan completed." -ForegroundColor Green
    Write-Host ""

    Read-Host "Press ENTER to exit"
}