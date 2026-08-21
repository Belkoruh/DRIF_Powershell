<#
.SYNOPSIS
    Uploads evidence files from a directory to an Azure Storage Blob container.

.DESCRIPTION
    Transfers local forensic artifacts or ZIP archives directly to an Azure Storage Blob container
    using a Shared Access Signature (SAS) Token via HTTPS REST PUT requests.

.PARAMETER StorageAccountName
    Name of the target Azure Storage Account.

.PARAMETER ContainerName
    Name of the target Blob Container.

.PARAMETER SasToken
    Shared Access Signature (SAS) token with Write/Create permissions (leading '?' is optional).

.PARAMETER SourceDir
    Source directory containing the files to upload (defaults to current directory).

.PARAMETER Filter
    File filter pattern (defaults to '*.*' or '*.zip').

.EXAMPLE
    .\FolderToStorageBlob.ps1 -StorageAccountName "irvault" -ContainerName "evidence" -SasToken "sp=racwd&st=...&sig=..."

.EXAMPLE
    .\FolderToStorageBlob.ps1 -StorageAccountName "irvault" -ContainerName "evidence" -SasToken "sp=..." -SourceDir "C:\IR\DFIR-DUMP"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $true)]
    [string]$ContainerName,

    [Parameter(Mandatory = $true)]
    [string]$SasToken,

    [Parameter(Mandatory = $false)]
    [string]$SourceDir,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "*.*"
)

if (-not $SourceDir) {
    $SourceDir = (Get-Location).Path
}

if (-not (Test-Path $SourceDir)) {
    Write-Error "Source directory '$SourceDir' does not exist."
    return
}

# Clean SAS token
$token = $SasToken.TrimStart('?')

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "       Azure Storage Blob Evidence Uploader" -ForegroundColor Cyan
Write-Host "       Target Account: $StorageAccountName | Container: $ContainerName" -ForegroundColor Cyan
Write-Host "       Source Directory: $SourceDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$files = Get-ChildItem -Path $SourceDir -File -Filter $Filter -ErrorAction SilentlyContinue

if (-not $files -or $files.Count -eq 0) {
    Write-Warning "No files found matching filter '$Filter' in '$SourceDir'."
    return
}

$uploadedCount = 0
$failedCount = 0

foreach ($file in $files) {
    $fileName = $file.Name
    $uri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$fileName`?$token"
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
        "x-ms-date"      = (Get-Date).ToUniversalTime().ToString("R")
    }

    try {
        Write-Host "[*] Uploading: $fileName ($([math]::Round($file.Length / 1MB, 2)) MB)..." -ForegroundColor Yellow
        $response = Invoke-RestMethod -Method "PUT" -Headers $headers -Uri $uri -InFile $file.FullName -ErrorAction Stop
        Write-Host " [+] Successfully uploaded $fileName" -ForegroundColor Green
        $uploadedCount++
    } catch {
        Write-Error " [-] Failed to upload $fileName : $($_.Exception.Message)"
        $failedCount++
    }
}

Write-Host "`nUpload Complete: $uploadedCount succeeded, $failedCount failed." -ForegroundColor Cyan