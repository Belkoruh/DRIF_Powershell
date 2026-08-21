<#
.Description: Collects Opera and Opera GX Logs and Forensic Artifacts for Browser Forensics.
.Recommended to use https://github.com/sqlitebrowser/sqlitebrowser to view exported SQLite Database files.
.Documentation: -
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\OperaArtifacts.ps1 -Username "Belk0ruh"
    .\OperaArtifacts.ps1 -Username "Belk0ruh" -CollectAllArtifacts
    .\OperaArtifacts.ps1 -AllUsers
    .\OperaArtifacts.ps1 -AllUsers -CollectAllArtifacts
    .\OperaArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\Export"
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [Switch]$CollectAllArtifacts,
    [String]$OutputDir
)

function Test-SQLiteFile {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $false }
    try {
        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $buffer = New-Object byte[] 15
        $bytesRead = $fileStream.Read($buffer, 0, 15)
        $fileStream.Close()
        $fileStream.Dispose()
        if ($bytesRead -ge 15) {
            $header = [System.Text.Encoding]::ASCII.GetString($buffer)
            return $header.StartsWith("SQLite format 3")
        }
    } catch {
        return $false
    }
    return $false
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "OperaBrowserArtifacts"
}
$HistoryFolder = Join-Path -Path $OutputDir -ChildPath "Browsers\Opera"
New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

Write-Host "Collecting Opera & Opera GX artifacts..." -ForegroundColor Cyan

$filesToCopy = @(
    'Preferences',
    'Secure Preferences',
    'History',
    'History-journal',
    'History-wal',
    'Bookmarks',
    'Bookmarks.bak',
    'Login Data',
    'Login Data-journal',
    'Web Data',
    'Web Data-journal',
    'Top Sites',
    'Top Sites-journal',
    'Shortcuts',
    'Shortcuts-journal',
    'Visited Links',
    'Current Session',
    'Current Tabs',
    'Last Session',
    'Last Tabs',
    'Network\Cookies',
    'Cookies'
)

$dirsToCopy = @(
    'Extensions',
    'IndexedDB',
    'Local Storage',
    'Sessions',
    'Sync Data',
    '_side_profiles'
)

if ($AllUsers) {
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object { 
        (Test-Path "$($_.FullName)\AppData\Roaming\Opera Software") -or (Test-Path "$($_.FullName)\AppData\Local\Programs\Opera") 
    }
} elseif ($Username) {
    $userDir = "C:\Users\$Username"
    if (-Not (Test-Path "$userDir\AppData\Roaming\Opera Software")) {
        Write-Warning "User profile for '$Username' not found or AppData\Roaming\Opera Software doesn't exist."
        return
    }
    $userDirs = @([IO.DirectoryInfo]::new($userDir))
} else {
    $currentUsername = $env:USERNAME
    $userDir = "C:\Users\$currentUsername"
    if ((Test-Path "$userDir\AppData\Roaming\Opera Software") -or (Test-Path "$userDir\AppData\Local\Programs\Opera")) {
        Write-Host "No user parameter specified, using current user: $currentUsername"
        $userDirs = @([IO.DirectoryInfo]::new($userDir))
    } else {
        Write-Warning "Please specify either -Username or -AllUsers"
        return
    }
}

$collectedCount = 0

foreach ($userDir in $userDirs) {
    $userProfileName = $userDir.Name
    $operaRoamingBase = "$($userDir.FullName)\AppData\Roaming\Opera Software"
    $operaLocalBase = "$($userDir.FullName)\AppData\Local\Opera Software"

    if (Test-Path $operaRoamingBase) {
        $operaFlavors = Get-ChildItem -Path $operaRoamingBase -Directory -ErrorAction SilentlyContinue

        foreach ($flavor in $operaFlavors) {
            $historyFile = Join-Path -Path $flavor.FullName -ChildPath "History"
            $prefFile = Join-Path -Path $flavor.FullName -ChildPath "Preferences"

            if ((Test-Path $historyFile) -or (Test-Path $prefFile)) {
                $destPath = Join-Path -Path $HistoryFolder -ChildPath "$userProfileName\$($flavor.Name)"
                New-Item -Path $destPath -ItemType Directory -Force | Out-Null

                if ($CollectAllArtifacts) {
                    Write-Host "Collecting ALL Opera files from $($flavor.FullName)" -ForegroundColor Yellow
                    Get-ChildItem -Path $flavor.FullName -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $relFilePath = $_.FullName.Substring($flavor.FullName.Length).TrimStart('\', '/')
                        $targetFile = Join-Path $destPath $relFilePath
                        $targetDir = Split-Path $targetFile -Parent
                        if (-not (Test-Path $targetDir)) {
                            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                        }
                        Copy-Item -Path $_.FullName -Destination $targetFile -Force -ErrorAction SilentlyContinue
                    }
                    $collectedCount++
                } else {
                    Write-Host "Collecting targeted Opera forensic artifacts from $($flavor.FullName)"
                    foreach ($file in $filesToCopy) {
                        $sourceFile = Join-Path -Path $flavor.FullName -ChildPath $file
                        if (Test-Path $sourceFile) {
                            $targetFile = Join-Path -Path $destPath -ChildPath $file
                            $targetDir = Split-Path $targetFile -Parent
                            if (-not (Test-Path $targetDir)) {
                                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                            }
                            Copy-Item -Path $sourceFile -Destination $targetFile -Force -ErrorAction SilentlyContinue
                        }
                    }

                    foreach ($dir in $dirsToCopy) {
                        $sourceDir = Join-Path -Path $flavor.FullName -ChildPath $dir
                        if (Test-Path $sourceDir) {
                            $targetDir = Join-Path $destPath $dir
                            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                            Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }

                    # Check Local AppData companion folder for IndexedDB / Local Storage if exists
                    $localCompanion = Join-Path -Path $operaLocalBase -ChildPath $flavor.Name
                    if (Test-Path $localCompanion) {
                        foreach ($dir in @('IndexedDB', 'Local Storage')) {
                            $sourceDir = Join-Path -Path $localCompanion -ChildPath $dir
                            if (Test-Path $sourceDir) {
                                $targetDir = Join-Path $destPath "Local_$dir"
                                New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                                Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }

                    $collectedCount++
                }
            }
        }
    }
}

Write-Host "Opera artifacts collection completed ($collectedCount profile(s) processed). Output folder: $OutputDir" -ForegroundColor Green
