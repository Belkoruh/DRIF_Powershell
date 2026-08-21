<#
.Description: Collects Mozilla Firefox Artifacts and logs for Browser Forensics.
.Recommended to use https://github.com/sqlitebrowser/sqlitebrowser to view exported SQLite Database files.
.Documentation: -
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\FirefoxArtifacts.ps1 -Username "Belk0ruh"
    .\FirefoxArtifacts.ps1 -Username "Belk0ruh" -CollectAllArtifacts
    .\FirefoxArtifacts.ps1 -AllUsers
    .\FirefoxArtifacts.ps1 -AllUsers -CollectAllArtifacts
    .\FirefoxArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\Export"
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
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "FirefoxBrowserArtifacts"
}
$HistoryFolder = Join-Path -Path $OutputDir -ChildPath "Browsers\Firefox"
New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

Write-Host "Collecting Firefox artifacts..." -ForegroundColor Cyan

$filesToCopy = @(
    'places.sqlite',
    'places.sqlite-wal',
    'places.sqlite-shm',
    'cookies.sqlite',
    'cookies.sqlite-wal',
    'cookies.sqlite-shm',
    'formhistory.sqlite',
    'formhistory.sqlite-wal',
    'permissions.sqlite',
    'content-prefs.sqlite',
    'favicons.sqlite',
    'favicons.sqlite-wal',
    'logins.json',
    'key4.db',
    'cert9.db',
    'handlers.json',
    'extensions.json',
    'addons.json',
    'extension-preferences.json',
    'prefs.js',
    'search.json.mozlz4',
    'sessionstore.jsonlz4'
)

$dirsToCopy = @(
    'extensions',
    'sessionstore-backups'
)

if ($AllUsers) {
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object { Test-Path "$($_.FullName)\AppData\Roaming\Mozilla\Firefox" }
} elseif ($Username) {
    $userDir = "C:\Users\$Username"
    if (-Not (Test-Path "$userDir\AppData\Roaming\Mozilla\Firefox")) {
        Write-Warning "User profile for '$Username' not found or AppData\Roaming\Mozilla\Firefox doesn't exist."
        return
    }
    $userDirs = @([IO.DirectoryInfo]::new($userDir))
} else {
    # Default to current user if neither is specified
    $currentUsername = $env:USERNAME
    $userDir = "C:\Users\$currentUsername"
    if (Test-Path "$userDir\AppData\Roaming\Mozilla\Firefox") {
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
    $firefoxProfilesPath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Mozilla\Firefox\Profiles"
    
    if (-not (Test-Path $firefoxProfilesPath)) {
        continue
    }

    $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue

    foreach ($profile in $profiles) {
        $placesFile = Join-Path -Path $profile.FullName -ChildPath "places.sqlite"
        $isValidProfile = (Test-Path $placesFile)

        if ($isValidProfile) {
            $destPath = Join-Path -Path $HistoryFolder -ChildPath "$userProfileName\$($profile.Name)"
            New-Item -Path $destPath -ItemType Directory -Force | Out-Null

            if ($CollectAllArtifacts) {
                Write-Host "Collecting ALL Firefox files from $($profile.FullName)" -ForegroundColor Yellow
                Get-ChildItem -Path $profile.FullName -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $relFilePath = $_.FullName.Substring($profile.FullName.Length).TrimStart('\', '/')
                    $targetFile = Join-Path $destPath $relFilePath
                    $targetDir = Split-Path $targetFile -Parent
                    if (-not (Test-Path $targetDir)) {
                        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                    }
                    Copy-Item -Path $_.FullName -Destination $targetFile -Force -ErrorAction SilentlyContinue
                }
                $collectedCount++
            } else {
                Write-Host "Collecting targeted forensic artifacts from $($profile.FullName)"
                foreach ($file in $filesToCopy) {
                    $sourceFile = Join-Path -Path $profile.FullName -ChildPath $file
                    if (Test-Path $sourceFile) {
                        Copy-Item -Path $sourceFile -Destination (Join-Path $destPath $file) -Force -ErrorAction SilentlyContinue
                    }
                }

                foreach ($dir in $dirsToCopy) {
                    $sourceDir = Join-Path -Path $profile.FullName -ChildPath $dir
                    if (Test-Path $sourceDir) {
                        $targetDir = Join-Path $destPath $dir
                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                        Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                $collectedCount++
            }
        }
    }
}

Write-Host "Firefox artifacts collection completed ($collectedCount profile(s) processed). Output folder: $OutputDir" -ForegroundColor Green
