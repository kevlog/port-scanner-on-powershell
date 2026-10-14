# ⚡ Power Port Scanner (PowerShell Edition)

A fast, lightweight, and zero-dependency TCP port scanner written entirely in native **PowerShell** and **.NET** (`System.Net.Sockets.TcpClient`). Designed for network administrators, penetration testers, and security professionals who need a quick, Nmap-style TCP scanner without installing external binaries.

---

## ✨ Features

- **Zero External Dependencies**: Works out-of-the-box on any Windows machine with PowerShell.
- **Interactive CLI Wizard**: Run without parameters to launch an interactive setup menu.
- **Accurate State Detection**: Distinguishes between `OPEN`, `CLOSED` (refused), and `TIMEOUT` states.
- **Latency Measurement**: Measures connection latency in milliseconds using high-precision stopwatches.
- **Multiple Scan Profiles**:
  - `Common`: Scans standard, frequently used services (FTP, SSH, HTTP, HTTPS, DBs, etc.).
  - `Important`: Fast scan targeting critical infrastructure and administrative ports.
  - `Full`: Comprehensive scan of all 65,535 TCP ports with progress indicator.
  - `Ports`: Custom target ports specified via command-line arguments or interactive input.
- **DNS Resolution**: Automatically resolves hostnames to IP addresses before scanning.
- **Color-Coded Output & Metrics**: Real-time feedback and structured summary tables.

---

## 🚀 Usage

### 1. Interactive Mode
Simply run the script with no arguments to launch the wizard:
```powershell
.\port-scanner.ps1
```

### 2. Command Line Arguments

**Scan Common Ports (Default):**
```powershell
.\port-scanner.ps1 -Target 192.168.1.1
```

**Scan Important Infrastructure Ports:**
```powershell
.\port-scanner.ps1 -Target 192.168.1.1 -ScanType Important
```

**Scan Custom Ports:**
```powershell
.\port-scanner.ps1 -Target 192.168.1.1 -ScanType Ports -Ports 22,80,443,3389,8080
```

**Full 65,535 Port Scan:**
```powershell
.\port-scanner.ps1 -Target 192.168.1.1 -ScanType Full
```

**Custom Connection Timeout (Default: 500 ms):**
```powershell
.\port-scanner.ps1 -Target 192.168.1.1 -TimeoutMs 1000
```

---

## 📋 Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Target` | String | *Interactive* | Target hostname or IPv4 address |
| `-ScanType` | String | `Common` | Scan profile: `Common`, `Important`, `Full`, or `Ports` |
| `-Ports` | Int[] | `$null` | Comma-separated list of ports (used with `-ScanType Ports`) |
| `-TimeoutMs`| Int | `500` | Connection timeout in milliseconds per port |

---

## ⚠️ Disclaimer

This tool is intended strictly for educational, defensive, and authorized administrative or penetration testing purposes. Do not scan targets without prior explicit written authorization.
