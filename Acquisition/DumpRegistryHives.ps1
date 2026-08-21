<#
.Description: Dumps Windows Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE, DEFAULT, NTUSER.DAT, UsrClass.dat) for Digital Forensics & Incident Response.
.Documentation: Saves raw registry hive files using the Windows reg.exe save utility.
.Required Permissions: Administrator

.Example:
    .\DumpRegistryHives.ps1
    .\DumpRegistryHives.ps1 -OutputDir "C:\IR\RegistryDump"
    .\DumpRegistryHives.ps1 -SystemOnly
    .\DumpRegistryHives.ps1 -UserOnly
    .\DumpRegistryHives.ps1 -Username "Belk0ruh"
#>

param (
    [String]$OutputDir,
    [String]$Username,
    [Switch]$SystemOnly,
    [Switch]$UserOnly
)

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to dump Windows Registry Hives (SAM, SYSTEM, SECURITY, etc.). Please run PowerShell as Administrator."
    return
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "RegistryHivesDump"
}

$systemHivesDir = Join-Path -Path $OutputDir -ChildPath "System"
$userHivesDir = Join-Path -Path $OutputDir -ChildPath "Users"

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       Windows Registry Hives Acquisition Tool" -ForegroundColor Cyan
Write-Host "       Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

function Save-Hive {
    param (
        [string]$RegistryKey,
        [string]$DestinationFile,
        [string]$HiveName
    )

    $parentDir = Split-Path -Path $DestinationFile -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    Write-Host "Saving $HiveName ($RegistryKey) -> $DestinationFile..." -NoNewline
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "save `"$RegistryKey`" `"$DestinationFile`" /y" -Wait -NoNewWindow -PassThru

    if ($process.ExitCode -eq 0 -and (Test-Path $DestinationFile)) {
        $fileSizeKB = [math]::Round(((Get-Item $DestinationFile).Length / 1KB), 2)
        Write-Host " [OK] ($fileSizeKB KB)" -ForegroundColor Green
    } else {
        Write-Host " [FAILED / NOT PRESENT]" -ForegroundColor Yellow
    }
}

# 1. System Hives Collection
if (-not $UserOnly) {
    Write-Host "`n--- Collecting System Registry Hives ---" -ForegroundColor Blue
    New-Item -Path $systemHivesDir -ItemType Directory -Force | Out-Null

    Save-Hive -RegistryKey "HKLM\SAM" -DestinationFile (Join-Path $systemHivesDir "SAM") -HiveName "SAM Hive"
    Save-Hive -RegistryKey "HKLM\SYSTEM" -DestinationFile (Join-Path $systemHivesDir "SYSTEM") -HiveName "SYSTEM Hive"
    Save-Hive -RegistryKey "HKLM\SECURITY" -DestinationFile (Join-Path $systemHivesDir "SECURITY") -HiveName "SECURITY Hive"
    Save-Hive -RegistryKey "HKLM\SOFTWARE" -DestinationFile (Join-Path $systemHivesDir "SOFTWARE") -HiveName "SOFTWARE Hive"
    Save-Hive -RegistryKey "HKU\.DEFAULT" -DestinationFile (Join-Path $systemHivesDir "DEFAULT") -HiveName "DEFAULT Hive"

    # Optional components / BCD if present
    if (Test-Path "HKLM:\COMPONENTS") {
        Save-Hive -RegistryKey "HKLM\COMPONENTS" -DestinationFile (Join-Path $systemHivesDir "COMPONENTS") -HiveName "COMPONENTS Hive"
    }
    if (Test-Path "HKLM:\BCD00000000") {
        Save-Hive -RegistryKey "HKLM\BCD00000000" -DestinationFile (Join-Path $systemHivesDir "BCD") -HiveName "BCD Hive"
    }
}

# 2. User Hives Collection (NTUSER.DAT & UsrClass.dat)
if (-not $SystemOnly) {
    Write-Host "`n--- Collecting User Registry Hives (NTUSER.DAT & UsrClass.dat) ---" -ForegroundColor Blue
    New-Item -Path $userHivesDir -ItemType Directory -Force | Out-Null

    # Map user SIDs from registry ProfileList
    $profileList = @{}
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.ProfileImagePath
    } | ForEach-Object {
        $profileList[$_.ProfileImagePath.ToLower()] = $_.PSChildName
    }

    if ($Username) {
        $userDir = "C:\Users\$Username"
        if (-not (Test-Path $userDir)) {
            Write-Warning "User directory for '$Username' not found at $userDir."
            $targetUsers = @()
        } else {
            $targetUsers = @([IO.DirectoryInfo]::new($userDir))
        }
    } else {
        $targetUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -notmatch '^(Public|Default|Default User|All Users)$'
        }
    }

    foreach ($user in $targetUsers) {
        $userName = $user.Name
        $userPath = $user.FullName
        $userDestDir = Join-Path -Path $userHivesDir -ChildPath $userName
        New-Item -Path $userDestDir -ItemType Directory -Force | Out-Null

        $sid = $profileList[$userPath.ToLower()]
        Write-Host "`nProcessing user: $userName $(if ($sid) { "($sid)" })" -ForegroundColor Cyan

        # Collect NTUSER.DAT
        $ntuserFile = Join-Path $userPath "NTUSER.DAT"
        $ntuserDest = Join-Path $userDestDir "NTUSER.DAT"

        if ($sid -and (Test-Path "registry::HKEY_USERS\$sid")) {
            # Active loaded hive -> reg save from HKU
            Save-Hive -RegistryKey "HKU\$sid" -DestinationFile $ntuserDest -HiveName "$userName NTUSER.DAT (from HKU)"
        } elseif (Test-Path $ntuserFile) {
            # Try raw copy or temporary mount
            try {
                Copy-Item -LiteralPath $ntuserFile -Destination $ntuserDest -Force -ErrorAction Stop
                Write-Host "Copied $userName NTUSER.DAT (direct copy) -> $ntuserDest [OK]" -ForegroundColor Green
            } catch {
                $tempKey = "TempHive_NTUSER_$userName"
                Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKU\$tempKey`" `"$ntuserFile`"" -Wait -NoNewWindow | Out-Null
                Save-Hive -RegistryKey "HKU\$tempKey" -DestinationFile $ntuserDest -HiveName "$userName NTUSER.DAT"
                Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$tempKey`"" -Wait -NoNewWindow | Out-Null
            }
        }

        # Collect UsrClass.dat (Shellbags, user associations, MRUs)
        $usrClassFile = Join-Path $userPath "AppData\Local\Microsoft\Windows\UsrClass.dat"
        $usrClassDest = Join-Path $userDestDir "UsrClass.dat"

        if ($sid -and (Test-Path "registry::HKEY_USERS\${sid}_Classes")) {
            # Active loaded classes hive -> reg save from HKU\_Classes
            Save-Hive -RegistryKey "HKU\${sid}_Classes" -DestinationFile $usrClassDest -HiveName "$userName UsrClass.dat (from HKU)"
        } elseif (Test-Path $usrClassFile) {
            try {
                Copy-Item -LiteralPath $usrClassFile -Destination $usrClassDest -Force -ErrorAction Stop
                Write-Host "Copied $userName UsrClass.dat (direct copy) -> $usrClassDest [OK]" -ForegroundColor Green
            } catch {
                $tempKey = "TempHive_UsrClass_$userName"
                Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKU\$tempKey`" `"$usrClassFile`"" -Wait -NoNewWindow | Out-Null
                Save-Hive -RegistryKey "HKU\$tempKey" -DestinationFile $usrClassDest -HiveName "$userName UsrClass.dat"
                Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$tempKey`"" -Wait -NoNewWindow | Out-Null
            }
        }
    }
}

Write-Host "`n===========================================================" -ForegroundColor Green
Write-Host " Windows Registry Hives dump completed successfully." -ForegroundColor Green
Write-Host " Export Location: $OutputDir" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
