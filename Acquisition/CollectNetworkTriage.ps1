<#
.Description: Collects volatile Network State and Historical Network Profiles (DNS Cache, ARP/Neighbors, Routes, SMB Sessions, Wi-Fi/Ethernet profiles).
.Documentation: Invaluable for detecting C2 domains (DNS cache), lateral movement targets (SMB sessions, ARP table), and multi-homed / network pivoting activity.
.Required Permissions: User / Administrator (some SMB and network profile features require Admin)

.Example:
    .\CollectNetworkTriage.ps1
    .\CollectNetworkTriage.ps1 -OutputDir "C:\IR\NetworkTriage"
#>

param (
    [String]$OutputDir
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "NetworkTriage"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$csvDir = Join-Path -Path $OutputDir -ChildPath "CSV"
New-Item -Path $csvDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         Network Triage & Volatile State Collector" -ForegroundColor Cyan
Write-Host "         Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# 1. DNS Client Cache
Write-Host "`n[1/5] Collecting DNS Client Cache..." -ForegroundColor Yellow
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, Status, TimeToLive, Data
    if ($dnsCache) {
        $dnsCsv = Join-Path -Path $csvDir -ChildPath "DNS_Client_Cache.csv"
        $dnsCache | Export-Csv -Path $dnsCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($dnsCache.Count) DNS cache entries saved to: $dnsCsv" -ForegroundColor Green
    } else {
        Write-Host " [-] DNS Client Cache empty or unavailable." -ForegroundColor DarkGray
    }
} catch {
    Write-Warning " Error querying DNS Cache: $($_.Exception.Message)"
}

# 2. ARP / NetNeighbor Table
Write-Host "`n[2/5] Collecting ARP / NetNeighbor Table..." -ForegroundColor Yellow
try {
    $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias, AddressFamily
    if ($neighbors) {
        $neighborCsv = Join-Path -Path $csvDir -ChildPath "NetNeighbor_ARP.csv"
        $neighbors | Export-Csv -Path $neighborCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($neighbors.Count) NetNeighbor entries saved to: $neighborCsv" -ForegroundColor Green
    } else {
        Write-Host " [-] No NetNeighbor entries found." -ForegroundColor DarkGray
    }
} catch {
    Write-Warning " Error querying NetNeighbor: $($_.Exception.Message)"
}

# 3. IP Routing Table
Write-Host "`n[3/5] Collecting IP Routing Table..." -ForegroundColor Yellow
try {
    $routes = Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, Protocol
    if ($routes) {
        $routeCsv = Join-Path -Path $csvDir -ChildPath "IP_Routes.csv"
        $routes | Export-Csv -Path $routeCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($routes.Count) IP Routes saved to: $routeCsv" -ForegroundColor Green
    }
} catch {
    Write-Warning " Error querying IP Routes: $($_.Exception.Message)"
}

# 4. SMB Connections, Sessions & Open Files
Write-Host "`n[4/5] Collecting SMB Sessions & Connections..." -ForegroundColor Yellow
try {
    $smbConns = Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName, ShareName, UserName, NumOpens, Dialect
    if ($smbConns) {
        $smbConnCsv = Join-Path -Path $csvDir -ChildPath "SMB_Outbound_Connections.csv"
        $smbConns | Export-Csv -Path $smbConnCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($smbConns.Count) Outbound SMB Connection(s) exported" -ForegroundColor Green
    }
} catch { }

try {
    $smbSessions = Get-SmbSession -ErrorAction SilentlyContinue | Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens, SecondsExists
    if ($smbSessions) {
        $smbSessCsv = Join-Path -Path $csvDir -ChildPath "SMB_Inbound_Sessions.csv"
        $smbSessions | Export-Csv -Path $smbSessCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($smbSessions.Count) Inbound SMB Session(s) exported" -ForegroundColor Green
    }
} catch { }

try {
    $smbOpens = Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object FileId, Path, SessionId, ClientUserName, ClientComputerName
    if ($smbOpens) {
        $smbOpenCsv = Join-Path -Path $csvDir -ChildPath "SMB_OpenFiles.csv"
        $smbOpens | Export-Csv -Path $smbOpenCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($smbOpens.Count) Active SMB Open File(s) exported" -ForegroundColor Green
    }
} catch { }

# 5. Historical Network Profiles (SSIDs, Ethernet networks)
Write-Host "`n[5/5] Collecting Historical Network Profiles from Registry..." -ForegroundColor Yellow
$profileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
$networkProfiles = @()

if (Test-Path $profileRegPath) {
    $profileKeys = Get-ChildItem -Path $profileRegPath -ErrorAction SilentlyContinue
    foreach ($k in $profileKeys) {
        $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        $networkProfiles += [PSCustomObject]@{
            ProfileGUID   = $k.PSChildName
            ProfileName   = $props.ProfileName
            Description   = $props.Description
            Category      = switch ($props.Category) { 0 { "Public" } 1 { "Private" } 2 { "DomainAuthenticated" } default { "Unknown" } }
            DateCreated   = $props.DateCreated
            DateLastConnected = $props.DateLastConnected
        }
    }

    if ($networkProfiles.Count -gt 0) {
        $netProfileCsv = Join-Path -Path $csvDir -ChildPath "Network_Profiles_History.csv"
        $networkProfiles | Export-Csv -Path $netProfileCsv -NoTypeInformation -Encoding UTF8
        Write-Host " [+] $($networkProfiles.Count) Historical Network Profile(s) exported to: $netProfileCsv" -ForegroundColor Green
    }
}

Write-Host "`nCompleted Network Triage acquisition! Output: $OutputDir" -ForegroundColor Cyan
