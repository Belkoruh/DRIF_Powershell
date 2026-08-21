<#
.Description: Collects SSH Forensic Artifacts (OpenSSH .ssh configs, known_hosts, authorized_keys, PuTTY sessions/keys, WinSCP, MobaXterm sessions/INI, OpenSSH Server configs, and SSH key inventory).
.Documentation: In DFIR, SSH artifacts reconstruct lateral movement targets (known_hosts), identify backdoor persistence (authorized_keys), and assess credential theft risks (private keys, PuTTY/MobaXterm sessions).
.Required Permissions: Administrator (for -AllUsers or OpenSSH Server files) / User (for current user)

.Example:
    .\CollectSSHArtifacts.ps1
    .\CollectSSHArtifacts.ps1 -AllUsers
    .\CollectSSHArtifacts.ps1 -Username "Belk0ruh"
    .\CollectSSHArtifacts.ps1 -OutputDir "C:\IR\SSH_Dump"
    .\CollectSSHArtifacts.ps1 -AllUsers -CollectPrivateKeys
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [String]$OutputDir,
    [Switch]$CollectPrivateKeys
)

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "SSH_Artifacts_Dump_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$csvDir = Join-Path -Path $OutputDir -ChildPath "CSV"
New-Item -Path $csvDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         SSH Forensics & Lateral Movement Collector" -ForegroundColor Cyan
Write-Host "         Output Directory: $OutputDir" -ForegroundColor Cyan
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

$knownHostsList = @()
$authorizedKeysList = @()
$sshKeysInventory = @()
$puttySessionsList = @()
$winScpSessionsList = @()

# 1. OpenSSH Artifacts Collection (.ssh)
foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $userOutDir = Join-Path -Path $OutputDir -ChildPath "Users\$uName\OpenSSH"

    Write-Host "`nScanning User Profile: $uName ($uPath)" -ForegroundColor Yellow
    $sshDir = Join-Path -Path $uPath -ChildPath ".ssh"

    if (Test-Path -LiteralPath $sshDir) {
        New-Item -Path $userOutDir -ItemType Directory -Force | Out-Null
        $sshFiles = Get-ChildItem -LiteralPath $sshDir -File -ErrorAction SilentlyContinue
        Write-Host " [+] Found .ssh directory with $($sshFiles.Count) file(s)" -ForegroundColor Green

        foreach ($file in $sshFiles) {
            $isPrivateKey = ($file.Name -match '^id_' -and $file.Extension -ne ".pub") -or ($file.Extension -in @(".pem", ".key", ".ppk"))
            
            # Record in key inventory
            $sshKeysInventory += [PSCustomObject]@{
                Username     = $uName
                FileName     = $file.Name
                IsPrivateKey = $isPrivateKey
                SizeBytes    = $file.Length
                LastModified = $file.LastWriteTimeUtc.ToString("o")
                Location     = $file.FullName
            }

            # Copy file
            if (-not $isPrivateKey -or $CollectPrivateKeys) {
                Copy-Item -LiteralPath $file.FullName -Destination $userOutDir -Force -ErrorAction SilentlyContinue
            }

            # Parse known_hosts
            if ($file.Name -match '^known_hosts') {
                $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line.Trim() -and -not $line.StartsWith("#")) {
                        $parts = $line.Trim() -split "\s+", 3
                        $knownHostsList += [PSCustomObject]@{
                            Username   = $uName
                            HostEntry  = if ($parts.Count -gt 0) { $parts[0] } else { "" }
                            KeyType    = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                            PublicKey  = if ($parts.Count -gt 2) { $parts[2] } else { "" }
                            SourceFile = $file.FullName
                        }
                    }
                }
            }

            # Parse authorized_keys
            if ($file.Name -match '^authorized_keys') {
                $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line.Trim() -and -not $line.StartsWith("#")) {
                        $parts = $line.Trim() -split "\s+", 3
                        $authorizedKeysList += [PSCustomObject]@{
                            Username    = $uName
                            KeyType     = if ($parts.Count -gt 0) { $parts[0] } else { "" }
                            PublicKey   = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                            CommentUser = if ($parts.Count -gt 2) { $parts[2] } else { "" }
                            SourceFile  = $file.FullName
                        }
                    }
                }
            }
        }
    } else {
        Write-Host " [-] No .ssh folder for user '$uName'" -ForegroundColor DarkGray
    }

    # Search for additional SSH key files in user profile folders (.ppk, .pem, .key)
    $searchFolders = @("Desktop", "Downloads", "Documents")
    foreach ($folder in $searchFolders) {
        $targetScan = Join-Path -Path $uPath -ChildPath $folder
        if (Test-Path -LiteralPath $targetScan) {
            $foundKeys = Get-ChildItem -LiteralPath $targetScan -Recurse -File -Include @("*.ppk", "*.pem", "*.key") -ErrorAction SilentlyContinue
            foreach ($fk in $foundKeys) {
                $sshKeysInventory += [PSCustomObject]@{
                    Username     = $uName
                    FileName     = $fk.Name
                    IsPrivateKey = $true
                    SizeBytes    = $fk.Length
                    LastModified = $fk.LastWriteTimeUtc.ToString("o")
                    Location     = $fk.FullName
                }

                if ($CollectPrivateKeys) {
                    $keysOut = Join-Path -Path $OutputDir -ChildPath "Users\$uName\FoundKeys"
                    New-Item -Path $keysOut -ItemType Directory -Force | Out-Null
                    Copy-Item -LiteralPath $fk.FullName -Destination $keysOut -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# 2. PuTTY & KiTTY Sessions (Registry)
Write-Host "`n[2/5] Auditing PuTTY / KiTTY Saved Sessions..." -ForegroundColor Yellow
$puttyRegBase = "HKCU:\Software\SimonTatham\PuTTY\Sessions"

$sessionKeys = $null
try {
    if (Test-Path $puttyRegBase -ErrorAction Stop) {
        $sessionKeys = Get-ChildItem -Path $puttyRegBase -ErrorAction SilentlyContinue
    }
} catch { }

if ($sessionKeys -and $sessionKeys.Count -gt 0) {
    $puttyOut = Join-Path -Path $OutputDir -ChildPath "PuTTY"
    New-Item -Path $puttyOut -ItemType Directory -Force | Out-Null

    # Export registry branch
    $regFile = Join-Path -Path $puttyOut -ChildPath "PuTTY_Sessions.reg"
    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "export `"HKCU\Software\SimonTatham\PuTTY\Sessions`" `"$regFile`" /y" -Wait -NoNewWindow -PassThru | Out-Null
    } catch { }

    foreach ($sk in $sessionKeys) {
        $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
        $puttySessionsList += [PSCustomObject]@{
            SessionName    = [System.Uri]::UnescapeDataString($sk.PSChildName)
            HostName       = $props.HostName
            UserName       = $props.UserName
            PortNumber     = $props.PortNumber
            Protocol       = $props.Protocol
            PublicKeyFile  = $props.PublicKeyFile
            ProxyHost      = $props.ProxyHost
        }
    }
    Write-Host " [+] Found $($puttySessionsList.Count) PuTTY saved session(s)" -ForegroundColor Green
} else {
    Write-Host " [-] No PuTTY sessions found in current user registry." -ForegroundColor DarkGray
}

# 3. WinSCP Saved Sessions (Registry)
Write-Host "`n[3/5] Auditing WinSCP Saved Sessions..." -ForegroundColor Yellow
$winScpRegBase = "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions"

$winScpKeys = $null
try {
    if (Test-Path $winScpRegBase -ErrorAction Stop) {
        $winScpKeys = Get-ChildItem -Path $winScpRegBase -ErrorAction SilentlyContinue
    }
} catch { }

if ($winScpKeys -and $winScpKeys.Count -gt 0) {
    $winScpOut = Join-Path -Path $OutputDir -ChildPath "WinSCP"
    New-Item -Path $winScpOut -ItemType Directory -Force | Out-Null

    $regFile = Join-Path -Path $winScpOut -ChildPath "WinSCP_Sessions.reg"
    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "export `"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`" `"$regFile`" /y" -Wait -NoNewWindow -PassThru | Out-Null
    } catch { }

    foreach ($sk in $winScpKeys) {
        $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
        $winScpSessionsList += [PSCustomObject]@{
            SessionName   = [System.Uri]::UnescapeDataString($sk.PSChildName)
            HostName      = $props.HostName
            UserName      = $props.UserName
            PortNumber    = $props.PortNumber
            FSProtocol    = $props.FSProtocol
            PublicKeyFile = $props.PublicKeyFile
        }
    }
    Write-Host " [+] Found $($winScpSessionsList.Count) WinSCP session(s)" -ForegroundColor Green
} else {
    Write-Host " [-] No WinSCP sessions in current user registry." -ForegroundColor DarkGray
}

# 4. MobaXterm Sessions, INI & Embedded Home Artifacts
Write-Host "`n[4/5] Auditing MobaXterm Sessions & Artifacts..." -ForegroundColor Yellow
$mobaXtermSessionsList = @()

foreach ($profile in $profilesToProcess) {
    $uName = $profile.Username
    $uPath = $profile.Path
    $mobaOutDir = Join-Path -Path $OutputDir -ChildPath "Users\$uName\MobaXterm"

    # 4.1 Search for MobaXterm.ini
    $iniCandidates = @(
        (Join-Path -Path $uPath -ChildPath "AppData\Roaming\MobaXterm\MobaXterm.ini"),
        (Join-Path -Path $uPath -ChildPath "Documents\MobaXterm\MobaXterm.ini"),
        (Join-Path -Path $uPath -ChildPath "Desktop\MobaXterm.ini")
    )

    foreach ($iniPath in $iniCandidates) {
        if (Test-Path -LiteralPath $iniPath) {
            New-Item -Path $mobaOutDir -ItemType Directory -Force | Out-Null
            $destIni = Join-Path -Path $mobaOutDir -ChildPath "MobaXterm_$(Split-Path -Parent $iniPath | Split-Path -Leaf).ini"
            Copy-Item -LiteralPath $iniPath -Destination $destIni -Force -ErrorAction SilentlyContinue

            Write-Host " [+] Found MobaXterm configuration: $iniPath" -ForegroundColor Green

            # Parse Bookmarks / Sessions from INI
            $iniContent = Get-Content -LiteralPath $iniPath -ErrorAction SilentlyContinue
            $inBookmarksSection = $false

            foreach ($line in $iniContent) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^\[Bookmarks.*\]') {
                    $inBookmarksSection = $true
                    continue
                } elseif ($trimmed -match '^\[' -and $trimmed -notmatch '^\[Bookmarks.*\]') {
                    $inBookmarksSection = $false
                }

                if ($inBookmarksSection -and $trimmed -match '^([^=]+)=(.*)$') {
                    $sessionName = $Matches[1].Trim()
                    $sessionData = $Matches[2].Trim()

                    if ($sessionData -match '%') {
                        $parts = $sessionData -split "%"
                        $remoteHost = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                        $remotePort = if ($parts.Count -gt 2) { $parts[2] } else { "22" }
                        $remoteUser = if ($parts.Count -gt 3) { $parts[3] } else { "" }
                        $keyPath = ""
                        foreach ($p in $parts) {
                            if ($p -match '\.(ppk|pem|key)$' -or $p -match '^id_') {
                                $keyPath = $p
                                break
                            }
                        }

                        $mobaXtermSessionsList += [PSCustomObject]@{
                            Username      = $uName
                            SessionName   = $sessionName
                            HostName      = $remoteHost
                            PortNumber    = $remotePort
                            RemoteUser    = $remoteUser
                            PrivateKeyFile= $keyPath
                            SourceIni     = $iniPath
                        }
                    }
                }
            }
        }
    }

    # 4.2 Check MobaXterm Embedded Cygwin/Home .ssh directory
    $embeddedSshCandidates = @(
        (Join-Path -Path $uPath -ChildPath "AppData\Roaming\MobaXterm\slash\home\mobaxterm\.ssh"),
        (Join-Path -Path $uPath -ChildPath "AppData\Local\Temp\MobaXterm\slash\home\mobaxterm\.ssh")
    )

    foreach ($mobaSsh in $embeddedSshCandidates) {
        if (Test-Path -LiteralPath $mobaSsh) {
            Write-Host " [+] Found MobaXterm internal .ssh home: $mobaSsh" -ForegroundColor Green
            $mobaSshOut = Join-Path -Path $mobaOutDir -ChildPath "Internal_SSH"
            New-Item -Path $mobaSshOut -ItemType Directory -Force | Out-Null

            $mobaSshFiles = Get-ChildItem -LiteralPath $mobaSsh -File -ErrorAction SilentlyContinue
            foreach ($msf in $mobaSshFiles) {
                Copy-Item -LiteralPath $msf.FullName -Destination $mobaSshOut -Force -ErrorAction SilentlyContinue

                # Parse known_hosts
                if ($msf.Name -match '^known_hosts') {
                    $khLines = Get-Content -LiteralPath $msf.FullName -ErrorAction SilentlyContinue
                    foreach ($line in $khLines) {
                        if ($line.Trim() -and -not $line.StartsWith("#")) {
                            $parts = $line.Trim() -split "\s+", 3
                            $knownHostsList += [PSCustomObject]@{
                                Username   = "$uName (MobaXterm Internal)"
                                HostEntry  = if ($parts.Count -gt 0) { $parts[0] } else { "" }
                                KeyType    = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                                PublicKey  = if ($parts.Count -gt 2) { $parts[2] } else { "" }
                                SourceFile = $msf.FullName
                            }
                        }
                    }
                }
            }
        }
    }
}

# 4.3 MobaXterm Registry (Current User)
$mobaRegBase = "HKCU:\Software\Mobatek\MobaXterm"
$hasMobaReg = $false
try {
    if (Test-Path $mobaRegBase -ErrorAction Stop) {
        $hasMobaReg = $true
    }
} catch { }

if ($hasMobaReg) {
    $mobaRegOut = Join-Path -Path $OutputDir -ChildPath "MobaXterm"
    New-Item -Path $mobaRegOut -ItemType Directory -Force | Out-Null
    $regFile = Join-Path -Path $mobaRegOut -ChildPath "MobaXterm_Registry.reg"
    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "export `"HKCU\Software\Mobatek\MobaXterm`" `"$regFile`" /y" -Wait -NoNewWindow -PassThru | Out-Null
        Write-Host " [+] Exported MobaXterm Registry settings -> $regFile" -ForegroundColor Green
    } catch { }
}

# 5. OpenSSH Server for Windows (C:\ProgramData\ssh)
Write-Host "`n[5/5] Checking OpenSSH Server for Windows..." -ForegroundColor Yellow
$programDataSsh = "$env:ProgramData\ssh"
$hasServerSsh = $false
try {
    $hasServerSsh = Test-Path -LiteralPath $programDataSsh -ErrorAction Stop
} catch { }

if ($hasServerSsh) {
    $serverOut = Join-Path -Path $OutputDir -ChildPath "System_OpenSSH_Server"
    New-Item -Path $serverOut -ItemType Directory -Force | Out-Null

    $adminKeys = Join-Path -Path $programDataSsh -ChildPath "administrators_authorized_keys"
    if (Test-Path -LiteralPath $adminKeys -ErrorAction SilentlyContinue) {
        Write-Host " [!] FOUND administrators_authorized_keys (OpenSSH Server Admin Backdoors/Keys)!" -ForegroundColor Red
        Copy-Item -LiteralPath $adminKeys -Destination $serverOut -Force -ErrorAction SilentlyContinue

        $lines = Get-Content -LiteralPath $adminKeys -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line.Trim() -and -not $line.StartsWith("#")) {
                $parts = $line.Trim() -split "\s+", 3
                $authorizedKeysList += [PSCustomObject]@{
                    Username    = "SYSTEM (administrators_authorized_keys)"
                    KeyType     = if ($parts.Count -gt 0) { $parts[0] } else { "" }
                    PublicKey   = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                    CommentUser = if ($parts.Count -gt 2) { $parts[2] } else { "" }
                    SourceFile  = $adminKeys
                }
            }
        }
    }

    $sshdConfig = Join-Path -Path $programDataSsh -ChildPath "sshd_config"
    if (Test-Path -LiteralPath $sshdConfig) {
        Copy-Item -LiteralPath $sshdConfig -Destination $serverOut -Force -ErrorAction SilentlyContinue
        Write-Host " [+] Copied sshd_config" -ForegroundColor Green
    }
} else {
    Write-Host " OpenSSH Server directory ($programDataSsh) not present." -ForegroundColor DarkGray
}

# Export CSV Reports
if ($knownHostsList.Count -gt 0) {
    $khCsv = Join-Path -Path $csvDir -ChildPath "SSH_Known_Hosts.csv"
    $knownHostsList | Export-Csv -Path $khCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nKnown Hosts CSV written to: $khCsv" -ForegroundColor Cyan
}

if ($authorizedKeysList.Count -gt 0) {
    $akCsv = Join-Path -Path $csvDir -ChildPath "SSH_Authorized_Keys.csv"
    $authorizedKeysList | Export-Csv -Path $akCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Authorized Keys CSV written to: $akCsv" -ForegroundColor $(if ($authorizedKeysList.Count -gt 0) { 'Red' } else { 'Cyan' })
}

if ($sshKeysInventory.Count -gt 0) {
    $invCsv = Join-Path -Path $csvDir -ChildPath "SSH_Keys_Inventory.csv"
    $sshKeysInventory | Export-Csv -Path $invCsv -NoTypeInformation -Encoding UTF8
    Write-Host "SSH Keys Inventory written to: $invCsv" -ForegroundColor Cyan
}

if ($puttySessionsList.Count -gt 0) {
    $puttyCsv = Join-Path -Path $csvDir -ChildPath "SSH_PuTTY_Sessions.csv"
    $puttySessionsList | Export-Csv -Path $puttyCsv -NoTypeInformation -Encoding UTF8
    Write-Host "PuTTY Sessions CSV written to: $puttyCsv" -ForegroundColor Cyan
}

if ($winScpSessionsList.Count -gt 0) {
    $winScpCsv = Join-Path -Path $csvDir -ChildPath "SSH_WinSCP_Sessions.csv"
    $winScpSessionsList | Export-Csv -Path $winScpCsv -NoTypeInformation -Encoding UTF8
    Write-Host "WinSCP Sessions CSV written to: $winScpCsv" -ForegroundColor Cyan
}

if ($mobaXtermSessionsList.Count -gt 0) {
    $mobaCsv = Join-Path -Path $csvDir -ChildPath "SSH_MobaXterm_Sessions.csv"
    $mobaXtermSessionsList | Export-Csv -Path $mobaCsv -NoTypeInformation -Encoding UTF8
    Write-Host "MobaXterm Sessions CSV written to: $mobaCsv" -ForegroundColor Cyan
}

Write-Host "`n===========================================================" -ForegroundColor Cyan
Write-Host " SSH Forensics Acquisition Complete!" -ForegroundColor Cyan
Write-Host " Known Hosts Entries:    $($knownHostsList.Count)" -ForegroundColor Cyan
Write-Host " Authorized Keys:        $($authorizedKeysList.Count)" -ForegroundColor Cyan
Write-Host " SSH Keys Discovered:    $($sshKeysInventory.Count)" -ForegroundColor Cyan
Write-Host " PuTTY Sessions:         $($puttySessionsList.Count)" -ForegroundColor Cyan
Write-Host " WinSCP Sessions:        $($winScpSessionsList.Count)" -ForegroundColor Cyan
Write-Host " MobaXterm Sessions:     $($mobaXtermSessionsList.Count)" -ForegroundColor Cyan
Write-Host " Output Directory:       $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
