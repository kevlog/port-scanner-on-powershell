param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [ValidateSet("Common", "Important", "Full", "Ports")]
    [string]$ScanType = "Common",

    [int]$TimeoutMs = 500,

    [int[]]$Ports
)

# ============================================================
# NMAP-LIKE TCP PORT SCANNER
# Native PowerShell / .NET - No external tools required
# ============================================================

# ------------------------------------------------------------
# Common ports
# ------------------------------------------------------------

$commonPorts = @{
    21    = "ftp"
    22    = "ssh"
    23    = "telnet"
    25    = "smtp"
    53    = "dns"
    80    = "http"
    110   = "pop3"
    111   = "rpcbind"
    135   = "msrpc"
    139   = "netbios-ssn"
    143   = "imap"
    443   = "https"
    445   = "microsoft-ds"
    465   = "smtps"
    587   = "submission"
    636   = "ldaps"
    993   = "imaps"
    995   = "pop3s"
    1433  = "ms-sql-s"
    1521  = "oracle"
    2049  = "nfs"
    2375  = "docker"
    2376  = "docker-ssl"
    3000  = "http-alt"
    3306  = "mysql"
    3389  = "ms-wbt-server"
    5432  = "postgresql"
    5672  = "amqp"
    5900  = "vnc"
    6379  = "redis"
    6443  = "kubernetes"
    8080  = "http-proxy"
    8443  = "https-alt"
    9000  = "php-fpm"
    9090  = "http-alt"
    9200  = "elasticsearch"
    27017 = "mongodb"
}

# ------------------------------------------------------------
# Important ports
#
# Fokus pada port yang umum digunakan untuk:
# - SSH / Remote Access
# - Web / Application
# - Database
# - File Transfer
# - Windows services
# ------------------------------------------------------------

$importantPorts = @{
    21    = "ftp"
    22    = "ssh"
    23    = "telnet"
    80    = "http"
    443   = "https"
    445   = "microsoft-ds"
    1433  = "ms-sql-s"
    1521  = "oracle"
    3306  = "mysql"
    3389  = "ms-wbt-server"
    5432  = "postgresql"
    8080  = "http-proxy"
    8443  = "https-alt"
    9000  = "php-fpm"
    9090  = "http-alt"
    27017 = "mongodb"
}

# ------------------------------------------------------------
# Determine ports to scan
# ------------------------------------------------------------

switch ($ScanType) {

    "Common" {
        $portsToScan = $commonPorts.Keys | Sort-Object
    }

    "Important" {
        $portsToScan = $importantPorts.Keys | Sort-Object
    }

    "Full" {
        $portsToScan = 1..65535
    }

    "Ports" {

        if (-not $Ports -or $Ports.Count -eq 0) {

            Write-Host ""
            Write-Host "ERROR: ScanType 'Ports' requires -Ports." `
                -ForegroundColor Red

            Write-Host ""
            Write-Host "Example:"
            Write-Host ".\port-scanner.ps1 -Target 10.10.10.100 -ScanType Ports -Ports 22,1521,1433"
            Write-Host ""

            exit 1
        }

        $portsToScan = $Ports | Sort-Object -Unique
    }
}

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host "              NMAP-LIKE TCP PORT SCANNER"
Write-Host "============================================================"
Write-Host "Target       : $Target"
Write-Host "Scan Type    : $ScanType"
Write-Host "Timeout      : $TimeoutMs ms"
Write-Host "Port Count   : $($portsToScan.Count)"
Write-Host "Started      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"
Write-Host ""

# ------------------------------------------------------------
# Resolve hostname
# ------------------------------------------------------------

try {

    $resolved = [System.Net.Dns]::GetHostAddresses($Target)

    Write-Host "Resolved IP  : $($resolved -join ', ')" `
        -ForegroundColor Cyan
}
catch {

    Write-Host "WARNING: Could not resolve target." `
        -ForegroundColor Yellow
}

Write-Host ""

# ------------------------------------------------------------
# Table Header
# ------------------------------------------------------------

Write-Host (
    "{0,-10} {1,-10} {2,-20} {3,-10}" -f
    "PORT",
    "STATE",
    "SERVICE",
    "LATENCY"
)

Write-Host ("-" * 55)

# ------------------------------------------------------------
# Scan
# ------------------------------------------------------------

$openPorts = @()
$startTime = Get-Date

foreach ($port in $portsToScan) {

    $tcpClient = New-Object System.Net.Sockets.TcpClient

    try {

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $asyncResult = $tcpClient.BeginConnect(
            $Target,
            [int]$port,
            $null,
            $null
        )

        $success = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)

        if ($success -and $tcpClient.Connected) {

            $stopwatch.Stop()

            $latency = $stopwatch.ElapsedMilliseconds

            # ------------------------------------------------
            # Determine service name
            # ------------------------------------------------

            if ($commonPorts.ContainsKey([int]$port)) {

                $service = $commonPorts[[int]$port]
            }
            else {

                $service = "unknown"
            }

            # ------------------------------------------------
            # Display OPEN port
            # ------------------------------------------------

            Write-Host (
                "{0,-10} {1,-10} {2,-20} {3,-10}" -f
                "$port/tcp",
                "OPEN",
                $service,
                "$latency ms"
            ) -ForegroundColor Green

            # ------------------------------------------------
            # Store result
            # ------------------------------------------------

            $openPorts += [PSCustomObject]@{
                Port     = $port
                Protocol = "tcp"
                State    = "open"
                Service  = $service
                Latency  = "$latency ms"
            }
        }
    }
    catch {
        # Ignore connection errors
    }
    finally {

        if ($tcpClient) {

            $tcpClient.Close()
            $tcpClient.Dispose()
        }
    }

    # --------------------------------------------------------
    # Progress indicator for Full scan
    # --------------------------------------------------------

    if ($ScanType -eq "Full") {

        $percent = [math]::Round(
            (($port / 65535) * 100),
            1
        )

        Write-Progress `
            -Activity "Scanning $Target" `
            -Status "$port / 65535 ports" `
            -PercentComplete $percent
    }
}

# ------------------------------------------------------------
# Finish progress
# ------------------------------------------------------------

if ($ScanType -eq "Full") {

    Write-Progress `
        -Activity "Scanning" `
        -Completed
}

$endTime = Get-Date
$duration = $endTime - $startTime

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host "SCAN COMPLETED"
Write-Host "============================================================"
Write-Host "Target       : $Target"
Write-Host "Scan Type    : $ScanType"
Write-Host "Ports Scanned: $($portsToScan.Count)"
Write-Host "Open Ports   : $($openPorts.Count)"
Write-Host "Duration     : $($duration.ToString())"
Write-Host "Finished     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"

# ------------------------------------------------------------
# Open port summary
# ------------------------------------------------------------

if ($openPorts.Count -gt 0) {

    Write-Host ""
    Write-Host "OPEN PORT SUMMARY" `
        -ForegroundColor Cyan

    Write-Host ""

    $openPorts |
        Format-Table `
            Port,
            Protocol,
            State,
            Service,
            Latency `
            -AutoSize
}
else {

    Write-Host ""
    Write-Host "No open TCP ports detected." `
        -ForegroundColor Yellow
}