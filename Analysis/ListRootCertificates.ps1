<#
.Description: Lists and audits installed Root and Intermediate Certificate Authorities (CAs) to detect rogue certificates or TLS intercepting proxies.
.Documentation: Attackers and adware installers sometimes install custom Root Certificates in the trusted store to perform stealthy Man-In-The-Middle (MitM) TLS inspection or sign malicious payloads.
.Required Permissions: User / Administrator

.Example:
    .\ListRootCertificates.ps1
    .\ListRootCertificates.ps1 -OutputDir "C:\IR\Certificates"
    .\ListRootCertificates.ps1 -ExportCsv
#>

param (
    [String]$OutputDir,
    [Switch]$ExportCsv
)

if (-not $OutputDir -and $ExportCsv) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "RootCertificatesAudit"
}
if ($OutputDir) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "         Root & Trusted CA Certificate Auditor" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$stores = @(
    @{ StorePath = "Cert:\LocalMachine\Root"; StoreName = "LocalMachine Trusted Root" },
    @{ StorePath = "Cert:\LocalMachine\CA"; StoreName = "LocalMachine Intermediate CA" },
    @{ StorePath = "Cert:\CurrentUser\Root"; StoreName = "CurrentUser Trusted Root" }
)

$certList = @()
$suspiciousCount = 0

# Known common legitimate root issuers prefix
$commonRootIssuers = @(
    "Microsoft", "DigiCert", "VeriSign", "GlobalSign", "Sectigo", "GoDaddy", 
    "Let's Encrypt", "Entrust", "Thawte", "GeoTrust", "Amazon", "Google", "USERTrust", "AAA Certificate"
)

foreach ($s in $stores) {
    Write-Host "`nAuditing Store: $($s.StoreName) ($($s.StorePath))" -ForegroundColor Yellow

    if (Test-Path $s.StorePath) {
        $certs = Get-ChildItem -Path $s.StorePath -ErrorAction SilentlyContinue

        foreach ($cert in $certs) {
            $isKnownVendor = $false
            foreach ($vendor in $commonRootIssuers) {
                if ($cert.Issuer -like "*$vendor*" -or $cert.Subject -like "*$vendor*") {
                    $isKnownVendor = $true
                    break
                }
            }

            $isSelfSigned = ($cert.Subject -eq $cert.Issuer)

            if (-not $isKnownVendor) {
                $suspiciousCount++
                Write-Host " [!] NON-STANDARD / CUSTOM CA:" -ForegroundColor Red
                Write-Host "     Subject:      $($cert.Subject)" -ForegroundColor White
                Write-Host "     Issuer:       $($cert.Issuer)" -ForegroundColor DarkGray
                Write-Host "     Thumbprint:   $($cert.Thumbprint)" -ForegroundColor DarkGray
                Write-Host "     NotAfter:     $($cert.NotAfter)" -ForegroundColor DarkGray
            }

            $certList += [PSCustomObject]@{
                StoreLocation  = $s.StoreName
                Subject        = $cert.Subject
                Issuer         = $cert.Issuer
                Thumbprint     = $cert.Thumbprint
                FriendlyName   = $cert.FriendlyName
                NotBefore      = $cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                NotAfter       = $cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                IsSelfSigned   = $isSelfSigned
                IsKnownIssuer  = $isKnownVendor
            }
        }
    }
}

if ($OutputDir) {
    $csvPath = Join-Path -Path $OutputDir -ChildPath "Root_Certificates_Audit.csv"
    $certList | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nCertificate audit report exported to: $csvPath" -ForegroundColor Cyan
}

Write-Host "`nAudit complete! Total Certificates checked: $($certList.Count) | Non-standard Root CAs: $suspiciousCount" -ForegroundColor Cyan
