<#
.Description: Collects Microsoft Edge Logs and Forensic Artifacts for Browser Forensics.
.Recommended to use https://github.com/sqlitebrowser/sqlitebrowser to view exported SQLite Database files.
.Documentation: -
.Required Permissions: Administrator (for -AllUsers or other users) / User (for current user)

.Example:
    .\EdgeArtifacts.ps1 -Username "Belk0ruh"
    .\EdgeArtifacts.ps1 -Username "Belk0ruh" -CollectAllArtifacts
    .\EdgeArtifacts.ps1 -AllUsers
    .\EdgeArtifacts.ps1 -AllUsers -CollectAllArtifacts
    .\EdgeArtifacts.ps1 -Username "Belk0ruh" -OutputDir "C:\IR\Export"
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
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "EdgeBrowserArtifacts"
}
$HistoryFolder = Join-Path -Path $OutputDir -ChildPath "Browsers\Edge"
New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

Write-Host "Collecting Microsoft Edge artifacts..." -ForegroundColor Cyan

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
    'Sync Data'
)

if ($AllUsers) {
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object { Test-Path "$($_.FullName)\AppData\Local" }
} elseif ($Username) {
    $userDir = "C:\Users\$Username"
    if (-Not (Test-Path "$userDir\AppData\Local")) {
        Write-Warning "User profile for '$Username' not found or AppData\Local doesn't exist."
        return
    }
    $userDirs = @([IO.DirectoryInfo]::new($userDir))
} else {
    $currentUsername = $env:USERNAME
    $userDir = "C:\Users\$currentUsername"
    if (Test-Path "$userDir\AppData\Local") {
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
    $edgeBasePaths = @(
        "$($userDir.FullName)\AppData\Local\Microsoft\Edge\User Data",
        "$($userDir.FullName)\AppData\Local\Microsoft\Edge Beta\User Data",
        "$($userDir.FullName)\AppData\Local\Microsoft\Edge Dev\User Data",
        "$($userDir.FullName)\AppData\Local\Microsoft\Edge SxS\User Data"
    )

    foreach ($basePath in $edgeBasePaths) {
        if (-not (Test-Path $basePath)) { continue }

        $editionName = Split-Path (Split-Path $basePath -Parent) -Leaf
        $profileDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName "History")) -or (Test-Path (Join-Path $_.FullName "Preferences"))
        }

        foreach ($profile in $profileDirs) {
            $destPath = Join-Path -Path $HistoryFolder -ChildPath "$userProfileName\$editionName\$($profile.Name)"
            New-Item -Path $destPath -ItemType Directory -Force | Out-Null

            if ($CollectAllArtifacts) {
                Write-Host "Collecting ALL Edge files from $($profile.FullName)" -ForegroundColor Yellow
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
                Write-Host "Collecting targeted Edge forensic artifacts from $($profile.FullName)"
                foreach ($file in $filesToCopy) {
                    $sourceFile = Join-Path -Path $profile.FullName -ChildPath $file
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

Write-Host "Microsoft Edge artifacts collection completed ($collectedCount profile(s) processed). Output folder: $OutputDir" -ForegroundColor Green
