param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [ValidateSet("Common", "Full")]
    [string]$ScanType = "Common",

    [int]$TimeoutMs = 500
)

# ============================================================
# NMAP-LIKE TCP PORT SCANNER
# Native PowerShell / .NET - No external tools required
# ============================================================

$commonPorts = @{
    21   = "ftp"
    22   = "ssh"
    23   = "telnet"
    25   = "smtp"
    53   = "dns"
    80   = "http"
    110  = "pop3"
    111  = "rpcbind"
    135  = "msrpc"
    139  = "netbios-ssn"
    143  = "imap"
    443  = "https"
    445  = "microsoft-ds"
    465  = "smtps"
    587  = "submission"
    636  = "ldaps"
    993  = "imaps"
    995  = "pop3s"
    1433 = "ms-sql-s"
    1521 = "oracle"
    2049 = "nfs"
    2375 = "docker"
    2376 = "docker-ssl"
    3000 = "http-alt"
    3306 = "mysql"
    3389 = "ms-wbt-server"
    5432 = "postgresql"
    5672 = "amqp"
    5900 = "vnc"
    6379 = "redis"
    6443 = "kubernetes"
    8080 = "http-proxy"
    8443 = "https-alt"
    9000 = "php-fpm"
    9090 = "http-alt"
    9200 = "elasticsearch"
    27017 = "mongodb"
}

if ($ScanType -eq "Common") {
    $ports = $commonPorts.Keys | Sort-Object
}
else {
    $ports = 1..65535
}

Write-Host ""
Write-Host "============================================================"
Write-Host "              NMAP-LIKE TCP PORT SCANNER"
Write-Host "============================================================"
Write-Host "Target       : $Target"
Write-Host "Scan Type    : $ScanType"
Write-Host "Timeout      : $TimeoutMs ms"
Write-Host "Port Count   : $($ports.Count)"
Write-Host "Started      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"
Write-Host ""

# Resolve hostname
try {
    $resolved = [System.Net.Dns]::GetHostAddresses($Target)

    Write-Host "Resolved IP : $($resolved -join ', ')" -ForegroundColor Cyan
}
catch {
    Write-Host "WARNING: Could not resolve target." -ForegroundColor Yellow
}

Write-Host ""
Write-Host ("{0,-8} {1,-10} {2,-20} {3,-10}" -f "PORT", "STATE", "SERVICE", "LATENCY")
Write-Host ("-" * 55)

$openPorts = @()
$startTime = Get-Date

foreach ($port in $ports) {

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

            if ($commonPorts.ContainsKey([int]$port)) {
                $service = $commonPorts[[int]$port]
            }
            else {
                $service = "unknown"
            }

            Write-Host (
                "{0,-8} {1,-10} {2,-20} {3,-10}" -f
                "$port/tcp",
                "OPEN",
                $service,
                "$latency ms"
            ) -ForegroundColor Green

            $openPorts += [PSCustomObject]@{
                Port    = $port
                Protocol = "tcp"
                State   = "open"
                Service = $service
                Latency = "$latency ms"
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

    # Progress indicator
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

Write-Progress -Activity "Scanning" -Completed

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "============================================================"
Write-Host "SCAN COMPLETED"
Write-Host "============================================================"
Write-Host "Target       : $Target"
Write-Host "Open Ports   : $($openPorts.Count)"
Write-Host "Duration     : $($duration.ToString())"
Write-Host "Finished     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"

if ($openPorts.Count -gt 0) {

    Write-Host ""
    Write-Host "OPEN PORT SUMMARY" -ForegroundColor Cyan
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
    Write-Host "No open TCP ports detected." -ForegroundColor Yellow
}