<#
.Description: Collects live Network Sockets (TCP/UDP with Process Mapping) and VPN configurations/gateways across all or targeted users.
.Documentation: In DFIR, live sockets reveal active C2 beacons and listening backdoors, while VPN artifacts (Cisco, GlobalProtect, OpenVPN, FortiClient, WireGuard, Windows RAS) identify corporate access points, remote gateways, and tunneling tools.
.Required Permissions: User (for current user/sockets) / Administrator (for full process command lines, -AllUsers, and system VPN configs)

.Example:
    .\CollectVPNAndSockets.ps1
    .\CollectVPNAndSockets.ps1 -AllUsers
    .\CollectVPNAndSockets.ps1 -Username "Belk0ruh"
    .\CollectVPNAndSockets.ps1 -OutputDir "C:\IR\VPN_Sockets_Dump"
    .\CollectVPNAndSockets.ps1 -AllUsers -IncludeLogs
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir,
    [Switch]$IncludeLogs
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "VPN_Sockets_Dump_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$csvDir = Join-Path -Path $OutputDir -ChildPath "CSV"
New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
$vpnConfigDir = Join-Path -Path $OutputDir -ChildPath "VPN_Configurations"
New-Item -Path $vpnConfigDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       Live Sockets & VPN Forensics Collector" -ForegroundColor Cyan
Write-Host "       Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

function Get-UserProfilesToProcess {
    param([string]$TargetUser, [switch]$ProcessAll)

    $profiles = @()
    if ($TargetUser) {
        $userReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -and ($_.ProfileImagePath -like "*\$TargetUser") }
        if ($userReg) {
            $profiles += [PSCustomObject]@{
                Username = Split-Path -Leaf $userReg.ProfileImagePath
                Path     = $userReg.ProfileImagePath
            }
        } else {
            Write-Warning "User profile for '$TargetUser' not found."
        }
    } elseif ($ProcessAll) {
        $regProfiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -and (Test-Path $_.ProfileImagePath) }
        foreach ($p in $regProfiles) {
            $uName = Split-Path -Leaf $p.ProfileImagePath
            if ($uName -notmatch '^(systemprofile|LocalService|NetworkService)$') {
                $profiles += [PSCustomObject]@{
                    Username = $uName
                    Path     = $p.ProfileImagePath
                }
            }
        }
    } else {
        $profiles += [PSCustomObject]@{
            Username = $env:USERNAME
            Path     = $env:USERPROFILE
        }
    }
    return $profiles
}

$profilesToProcess = Get-UserProfilesToProcess -TargetUser $Username -ProcessAll:$AllUsers

# Build Process Cache for Socket Enrichment
Write-Host "`n[1/4] Building Process Cache for Socket Correlation..." -ForegroundColor Yellow
$processCache = @{}
try {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        $processCache[$proc.ProcessId] = [PSCustomObject]@{
            Name        = $proc.Name
            Path        = $proc.ExecutablePath
            CommandLine = $proc.CommandLine
            ParentPID   = $proc.ParentProcessId
        }
    }
} catch {
    # Fallback to Get-Process
    $rawProcs = Get-Process -ErrorAction SilentlyContinue
    foreach ($rp in $rawProcs) {
        $processCache[$rp.Id] = [PSCustomObject]@{
            Name        = $rp.ProcessName
            Path        = $rp.Path
            CommandLine = ""
            ParentPID   = 0
        }
    }
}

# 1. Capture Active TCP Sockets
Write-Host "`n[2/4] Capturing Active TCP Sockets..." -ForegroundColor Yellow
$tcpSocketsList = @()

try {
    $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
    foreach ($conn in $tcpConnections) {
        $pidNum = $conn.OwningProcess
        $procInfo = if ($processCache.ContainsKey($pidNum)) { $processCache[$pidNum] } else { $null }

        $tcpSocketsList += [PSCustomObject]@{
            Protocol           = "TCP"
            LocalAddress       = $conn.LocalAddress
            LocalPort          = $conn.LocalPort
            RemoteAddress      = $conn.RemoteAddress
            RemotePort         = $conn.RemotePort
            State              = "$($conn.State)"
            PID                = $pidNum
            ProcessName        = if ($procInfo) { $procInfo.Name } else { "Unknown" }
            ProcessPath        = if ($procInfo) { $procInfo.Path } else { "" }
            ProcessCommandLine = if ($procInfo) { $procInfo.CommandLine } else { "" }
            CreationTime       = if ($conn.CreationTime) { $conn.CreationTime.ToString("o") } else { "" }
        }
    }
} catch {
    # Fallback to netstat -ano -p tcp
    Write-Host " [i] CIM unavailable for Get-NetTCPConnection, falling back to netstat..." -ForegroundColor DarkGray
    $netstatTcp = netstat.exe -ano -p tcp 2>$null
    foreach ($line in $netstatTcp) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^TCP\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(\d+)$') {
            $localEndpoint = $Matches[1]
            $remoteEndpoint = $Matches[2]
            $state = $Matches[3]
            $pidNum = [int]$Matches[4]

            $localIp = $localEndpoint.Substring(0, $localEndpoint.LastIndexOf(':'))
            $localPort = $localEndpoint.Substring($localEndpoint.LastIndexOf(':') + 1)
            $remoteIp = $remoteEndpoint.Substring(0, $remoteEndpoint.LastIndexOf(':'))
            $remotePort = $remoteEndpoint.Substring($remoteEndpoint.LastIndexOf(':') + 1)

            $procInfo = if ($processCache.ContainsKey($pidNum)) { $processCache[$pidNum] } else { $null }

            $tcpSocketsList += [PSCustomObject]@{
                Protocol           = "TCP"
                LocalAddress       = $localIp
                LocalPort          = $localPort
                RemoteAddress      = $remoteIp
                RemotePort         = $remotePort
                State              = $state
                PID                = $pidNum
                ProcessName        = if ($procInfo) { $procInfo.Name } else { "Unknown" }
                ProcessPath        = if ($procInfo) { $procInfo.Path } else { "" }
                ProcessCommandLine = if ($procInfo) { $procInfo.CommandLine } else { "" }
                CreationTime       = ""
            }
        }
    }
}

if ($tcpSocketsList.Count -gt 0) {
    $tcpCsv = Join-Path -Path $csvDir -ChildPath "Network_Sockets_TCP.csv"
    $tcpSocketsList | Export-Csv -Path $tcpCsv -NoTypeInformation -Encoding UTF8
    Write-Host " [+] $($tcpSocketsList.Count) TCP socket(s) recorded -> $tcpCsv" -ForegroundColor Green
}

# 2. Capture Active UDP Sockets
$udpSocketsList = @()
try {
    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
    foreach ($udp in $udpEndpoints) {
        $pidNum = $udp.OwningProcess
        $procInfo = if ($processCache.ContainsKey($pidNum)) { $processCache[$pidNum] } else { $null }

        $udpSocketsList += [PSCustomObject]@{
            Protocol           = "UDP"
            LocalAddress       = $udp.LocalAddress
            LocalPort          = $udp.LocalPort
            PID                = $pidNum
            ProcessName        = if ($procInfo) { $procInfo.Name } else { "Unknown" }
            ProcessPath        = if ($procInfo) { $procInfo.Path } else { "" }
            ProcessCommandLine = if ($procInfo) { $procInfo.CommandLine } else { "" }
            CreationTime       = if ($udp.CreationTime) { $udp.CreationTime.ToString("o") } else { "" }
        }
    }
} catch {
    # Fallback to netstat -ano -p udp
    $netstatUdp = netstat.exe -ano -p udp 2>$null
    foreach ($line in $netstatUdp) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^UDP\s+([^\s]+)\s+([^\s]+)\s+(\d+)$') {
            $localEndpoint = $Matches[1]
            $pidNum = [int]$Matches[3]

            $localIp = $localEndpoint.Substring(0, $localEndpoint.LastIndexOf(':'))
            $localPort = $localEndpoint.Substring($localEndpoint.LastIndexOf(':') + 1)
            $procInfo = if ($processCache.ContainsKey($pidNum)) { $processCache[$pidNum] } else { $null }

            $udpSocketsList += [PSCustomObject]@{
                Protocol           = "UDP"
                LocalAddress       = $localIp
                LocalPort          = $localPort
                PID                = $pidNum
                ProcessName        = if ($procInfo) { $procInfo.Name } else { "Unknown" }
                ProcessPath        = if ($procInfo) { $procInfo.Path } else { "" }
                ProcessCommandLine = if ($procInfo) { $procInfo.CommandLine } else { "" }
                CreationTime       = ""
            }
        }
    }
}

if ($udpSocketsList.Count -gt 0) {
    $udpCsv = Join-Path -Path $csvDir -ChildPath "Network_Sockets_UDP.csv"
    $udpSocketsList | Export-Csv -Path $udpCsv -NoTypeInformation -Encoding UTF8
    Write-Host " [+] $($udpSocketsList.Count) UDP socket(s) recorded -> $udpCsv" -ForegroundColor Green
}

# 3. Capture Network Adapters (Physical + Virtual / VPN)
Write-Host "`n[3/4] Enumerating Network Adapters & Virtual VPN Interfaces..." -ForegroundColor Yellow
$adaptersList = @()
try {
    $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop
    foreach ($ad in $adapters) {
        $isVpnAdapter = ($ad.InterfaceDescription -match 'TAP|TUN|WireGuard|AnyConnect|GlobalProtect|Fortinet|Tailscale|ZeroTier|Virtual|VPN') -or
                        ($ad.Name -match 'VPN|wg|tailscale|zerotier')

        $adaptersList += [PSCustomObject]@{
            Name                 = $ad.Name
            InterfaceDescription = $ad.InterfaceDescription
            Status               = "$($ad.Status)"
            MacAddress           = $ad.MacAddress
            LinkSpeed            = $ad.LinkSpeed
            IsVpnAdapter         = $isVpnAdapter
        }
    }
} catch {
    # Fallback to .NET System.Net.NetworkInformation.NetworkInterface
    try {
        $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($nic in $interfaces) {
            $isVpnAdapter = ($nic.Description -match 'TAP|TUN|WireGuard|AnyConnect|GlobalProtect|Fortinet|Tailscale|ZeroTier|Virtual|VPN') -or
                            ($nic.Name -match 'VPN|wg|tailscale|zerotier')

            $adaptersList += [PSCustomObject]@{
                Name                 = $nic.Name
                InterfaceDescription = $nic.Description
                Status               = "$($nic.OperationalStatus)"
                MacAddress           = $nic.GetPhysicalAddress().ToString()
                LinkSpeed            = "$([math]::Round($nic.Speed / 1MB, 1)) Mbps"
                IsVpnAdapter         = $isVpnAdapter
            }
        }
    } catch { }
}

if ($adaptersList.Count -gt 0) {
    $adCsv = Join-Path -Path $csvDir -ChildPath "Network_Adapters.csv"
    $adaptersList | Export-Csv -Path $adCsv -NoTypeInformation -Encoding UTF8
    Write-Host " [+] $($adaptersList.Count) Network Adapter(s) recorded -> $adCsv" -ForegroundColor Green
}

# 4. VPN Artifacts & Configuration Extraction
Write-Host "`n[4/4] Collecting VPN Configurations & Client Artifacts..." -ForegroundColor Yellow
$vpnInventory = @()

# 4.1 Windows Built-In VPN Connections (RAS)
try {
    $rasConnections = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
    if ($rasConnections) {
        foreach ($ras in $rasConnections) {
            Write-Host " [+] Windows VPN Connection (AllUsers): $($ras.Name) -> $($ras.ServerAddress)" -ForegroundColor Green
            $vpnInventory += [PSCustomObject]@{
                ClientType     = "Windows RAS VPN (System)"
                ProfileName    = $ras.Name
                ServerAddress  = $ras.ServerAddress
                TunnelType     = "$($ras.TunnelType)"
                Authentication = "$($ras.AuthenticationMethod)"
                SourcePath     = "System RAS"
            }
        }
    }
} catch { }

# RAS Phonebook files (rasphone.pbk)
$pbkLocations = @(
    "$env:ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk"
)
foreach ($p in $profilesToProcess) {
    $pbkLocations += Join-Path -Path $p.Path -ChildPath "AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk"
}

foreach ($pbk in $pbkLocations) {
    if (Test-Path -LiteralPath $pbk) {
        $destPbk = Join-Path -Path $vpnConfigDir -ChildPath "rasphone_$(Split-Path -Parent $pbk | Split-Path -Parent | Split-Path -Leaf)_pbk.txt"
        Copy-Item -LiteralPath $pbk -Destination $destPbk -Force -ErrorAction SilentlyContinue
        Write-Host " [+] Found RAS Phonebook: $pbk" -ForegroundColor Green

        $pbkLines = Get-Content -LiteralPath $pbk -ErrorAction SilentlyContinue
        $currentSection = ""
        foreach ($line in $pbkLines) {
            if ($line -match '^\[(.*)\]$') {
                $currentSection = $Matches[1]
            } elseif ($line -match '^PhoneNumber=(.*)$') {
                $srv = $Matches[1]
                if ($srv) {
                    $vpnInventory += [PSCustomObject]@{
                        ClientType     = "Windows RAS (Phonebook)"
                        ProfileName    = $currentSection
                        ServerAddress  = $srv
                        TunnelType     = "RAS/PPTP/L2TP/SSTP/IKEv2"
                        Authentication = ""
                        SourcePath     = $pbk
                    }
                }
            }
        }
    }
}

# 4.2 Cisco AnyConnect / Secure Client
$ciscoProfileDirs = @(
    "$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile",
    "$env:ProgramData\Cisco\Cisco Secure Client\VPN\Profile"
)

foreach ($cDir in $ciscoProfileDirs) {
    if (Test-Path -LiteralPath $cDir) {
        $xmlProfiles = Get-ChildItem -LiteralPath $cDir -Filter "*.xml" -File -ErrorAction SilentlyContinue
        if ($xmlProfiles) {
            $ciscoOut = Join-Path -Path $vpnConfigDir -ChildPath "Cisco_Profiles"
            New-Item -Path $ciscoOut -ItemType Directory -Force | Out-Null

            foreach ($xmlFile in $xmlProfiles) {
                Copy-Item -LiteralPath $xmlFile.FullName -Destination $ciscoOut -Force -ErrorAction SilentlyContinue
                Write-Host " [+] Found Cisco VPN Profile: $($xmlFile.Name)" -ForegroundColor Green

                # Parse ServerList
                $xmlContent = Get-Content -LiteralPath $xmlFile.FullName -Raw -ErrorAction SilentlyContinue
                if ($xmlContent -match '<HostAddress>([^<]+)</HostAddress>') {
                    $vpnInventory += [PSCustomObject]@{
                        ClientType     = "Cisco AnyConnect"
                        ProfileName    = $xmlFile.BaseName
                        ServerAddress  = $Matches[1]
                        TunnelType     = "SSL/IPSec"
                        Authentication = ""
                        SourcePath     = $xmlFile.FullName
                    }
                }
            }
        }
    }
}

# 4.3 Palo Alto GlobalProtect
$gpRegBase = "HKCU:\Software\Palo Alto Networks\GlobalProtect"
$hasGpReg = $false
try {
    if (Test-Path $gpRegBase -ErrorAction Stop) { $hasGpReg = $true }
} catch { }

if ($hasGpReg) {
    $gpOut = Join-Path -Path $vpnConfigDir -ChildPath "GlobalProtect"
    New-Item -Path $gpOut -ItemType Directory -Force | Out-Null

    $regFile = Join-Path -Path $gpOut -ChildPath "GlobalProtect_Registry.reg"
    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "export `"HKCU\Software\Palo Alto Networks\GlobalProtect`" `"$regFile`" /y" -Wait -NoNewWindow -PassThru | Out-Null
        Write-Host " [+] Exported GlobalProtect Registry settings" -ForegroundColor Green
    } catch { }

    $panPortals = Get-ItemProperty -Path "HKCU:\Software\Palo Alto Networks\GlobalProtect\PanSetup" -ErrorAction SilentlyContinue
    if ($panPortals -and $panPortals.Portal) {
        Write-Host " [+] Found GlobalProtect Portal: $($panPortals.Portal)" -ForegroundColor Green
        $vpnInventory += [PSCustomObject]@{
            ClientType     = "GlobalProtect"
            ProfileName    = "PanSetup Portal"
            ServerAddress  = $panPortals.Portal
            TunnelType     = "SSL/IPSec"
            Authentication = ""
            SourcePath     = "Registry HKCU\PanSetup"
        }
    }
}

if ($IncludeLogs) {
    $gpLog = "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPS.log"
    if (Test-Path -LiteralPath $gpLog) {
        $gpOut = Join-Path -Path $vpnConfigDir -ChildPath "GlobalProtect"
        New-Item -Path $gpOut -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $gpLog -Destination $gpOut -Force -ErrorAction SilentlyContinue
        Write-Host " [+] Copied PanGPS.log" -ForegroundColor Green
    }
}

# 4.4 OpenVPN & OpenVPN Connect
$openVpnDirs = @(
    "C:\Program Files\OpenVPN\config",
    "C:\Program Files (x86)\OpenVPN\config"
)
foreach ($p in $profilesToProcess) {
    $openVpnDirs += Join-Path -Path $p.Path -ChildPath "OpenVPN\config"
    $openVpnDirs += Join-Path -Path $p.Path -ChildPath "AppData\Roaming\OpenVPN Connect\profiles"
}

foreach ($ovDir in $openVpnDirs) {
    if (Test-Path -LiteralPath $ovDir) {
        $ovFiles = Get-ChildItem -LiteralPath $ovDir -File -Include @("*.ovpn", "*.conf") -ErrorAction SilentlyContinue
        if ($ovFiles) {
            $ovOut = Join-Path -Path $vpnConfigDir -ChildPath "OpenVPN"
            New-Item -Path $ovOut -ItemType Directory -Force | Out-Null

            foreach ($ovf in $ovFiles) {
                Copy-Item -LiteralPath $ovf.FullName -Destination $ovOut -Force -ErrorAction SilentlyContinue
                Write-Host " [+] Found OpenVPN configuration: $($ovf.Name)" -ForegroundColor Green

                $ovContent = Get-Content -LiteralPath $ovf.FullName -ErrorAction SilentlyContinue
                $remoteLine = $ovContent | Where-Object { $_ -match '^\s*remote\s+([^\s]+)\s*(\d*)' } | Select-Object -First 1
                $srvAddr = if ($remoteLine) { $remoteLine.Trim() } else { "OpenVPN Profile" }

                $vpnInventory += [PSCustomObject]@{
                    ClientType     = "OpenVPN"
                    ProfileName    = $ovf.Name
                    ServerAddress  = $srvAddr
                    TunnelType     = "OpenVPN (SSL/TLS)"
                    Authentication = ""
                    SourcePath     = $ovf.FullName
                }
            }
        }
    }
}

# 4.5 FortiClient SSL-VPN
$fortiReg = "HKLM:\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels"
if (Test-Path $fortiReg) {
    $fortiTunnels = Get-ChildItem -Path $fortiReg -ErrorAction SilentlyContinue
    foreach ($ft in $fortiTunnels) {
        $props = Get-ItemProperty -Path $ft.PSPath -ErrorAction SilentlyContinue
        Write-Host " [+] Found FortiClient Tunnel: $($ft.PSChildName) -> $($props.Server)" -ForegroundColor Green
        $vpnInventory += [PSCustomObject]@{
            ClientType     = "FortiClient SSL-VPN"
            ProfileName    = $ft.PSChildName
            ServerAddress  = $props.Server
            TunnelType     = "SSL-VPN"
            Authentication = $props.User
            SourcePath     = "Registry HKLM\Fortinet"
        }
    }
}

# 4.6 WireGuard Configurations
$wgConfigDir = "C:\Program Files\WireGuard\Data\Configurations"
$hasWg = $false
try {
    if (Test-Path -LiteralPath $wgConfigDir -ErrorAction Stop) {
        $hasWg = $true
    }
} catch { }

if ($hasWg) {
    $wgFiles = Get-ChildItem -LiteralPath $wgConfigDir -File -ErrorAction SilentlyContinue
    if ($wgFiles) {
        $wgOut = Join-Path -Path $vpnConfigDir -ChildPath "WireGuard"
        New-Item -Path $wgOut -ItemType Directory -Force | Out-Null
        foreach ($wgf in $wgFiles) {
            Copy-Item -LiteralPath $wgf.FullName -Destination $wgOut -Force -ErrorAction SilentlyContinue
            $vpnInventory += [PSCustomObject]@{
                ClientType     = "WireGuard"
                ProfileName    = $wgf.Name
                ServerAddress  = "Encrypted DPAPI / WireGuard Interface"
                TunnelType     = "WireGuard (UDP)"
                Authentication = ""
                SourcePath     = $wgf.FullName
            }
        }
        Write-Host " [+] Found $($wgFiles.Count) WireGuard configuration file(s)" -ForegroundColor Green
    }
}

# 4.7 Tailscale & ZeroTier
$tailscaleDir = "$env:ProgramData\Tailscale"
if (Test-Path -LiteralPath $tailscaleDir) {
    $vpnInventory += [PSCustomObject]@{
        ClientType     = "Tailscale"
        ProfileName    = "Tailscale Mesh VPN"
        ServerAddress  = "Tailscale Control Plane"
        TunnelType     = "WireGuard Overlay"
        Authentication = ""
        SourcePath     = $tailscaleDir
    }
    Write-Host " [+] Found Tailscale installed on host" -ForegroundColor Green
}

$zeroTierDir = "$env:ProgramData\ZeroTier\One"
if (Test-Path -LiteralPath $zeroTierDir) {
    $vpnInventory += [PSCustomObject]@{
        ClientType     = "ZeroTier"
        ProfileName    = "ZeroTier One"
        ServerAddress  = "ZeroTier Network"
        TunnelType     = "ZeroTier Virtual L2"
        Authentication = ""
        SourcePath     = $zeroTierDir
    }
    Write-Host " [+] Found ZeroTier One installed on host" -ForegroundColor Green
}

# Export VPN Inventory CSV
if ($vpnInventory.Count -gt 0) {
    $vpnCsv = Join-Path -Path $csvDir -ChildPath "VPN_Profiles_Inventory.csv"
    $vpnInventory | Export-Csv -Path $vpnCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nVPN Profiles Inventory written to: $vpnCsv" -ForegroundColor Cyan
}

Write-Host "`n===========================================================" -ForegroundColor Cyan
Write-Host " VPN & Sockets Forensics Collection Complete!" -ForegroundColor Cyan
Write-Host " TCP Sockets Captured:       $($tcpSocketsList.Count)" -ForegroundColor Cyan
Write-Host " UDP Sockets Captured:       $($udpSocketsList.Count)" -ForegroundColor Cyan
Write-Host " Network Adapters Recorded:  $($adaptersList.Count)" -ForegroundColor Cyan
Write-Host " VPN Profiles Discovered:    $($vpnInventory.Count)" -ForegroundColor Cyan
Write-Host " Output Directory:           $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
