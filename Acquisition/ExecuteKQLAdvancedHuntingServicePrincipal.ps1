<#
.SYNOPSIS
    Runs a KQL Advanced Hunting query against Microsoft Defender for Endpoint using Service Principal credentials.

.DESCRIPTION
    Authenticates non-interactively using an Entra ID App Registration (Service Principal)
    to query the M365 Defender Advanced Hunting API via Microsoft Graph Security.

.PARAMETER AppID
    The Application (Client) ID of the Entra ID App Registration.

.PARAMETER TenantID
    The Directory (Tenant) ID.

.PARAMETER Secret
    The Client Secret value (or pass SecureSecret).

.PARAMETER KQL
    The KQL query string to execute.

.PARAMETER Timespan
    Query timespan ISO-8601 duration (default: "P30D" for last 30 days, or "P180D").

.PARAMETER OutputFile
    Optional CSV file path to export query results.

.EXAMPLE
    .\ExecuteKQLAdvancedHuntingServicePrincipal.ps1 -AppID "xxxx" -TenantID "yyyy" -Secret "zzzz" -KQL "DeviceProcessEvents | take 100" -OutputFile "results.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $true)]
    [string]$TenantID,

    [Parameter(Mandatory = $true)]
    [string]$Secret,

    [Parameter(Mandatory = $false)]
    [string]$KQL = 'DeviceEvents | where ActionType startswith "asr" | project Timestamp, DeviceName, ActionType | take 50',

    [Parameter(Mandatory = $false)]
    [string]$Timespan = "P30D",

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

$SecureClientSecret = ConvertTo-SecureString -String $Secret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppID, $SecureClientSecret

Import-Module Microsoft.Graph.Security -ErrorAction Stop

Write-Host "Connecting to Microsoft Graph with Service Principal..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

$params = @{
    Query    = $KQL
    Timespan = $Timespan
}

Write-Host "Executing KQL Advanced Hunting Query..." -ForegroundColor Cyan
$Results = Start-MgSecurityHuntingQuery -BodyParameter $params

$rows = @($Results.Results)
if (-not $rows -or $rows.Count -eq 0) {
    Write-Host "No results returned for the specified KQL query." -ForegroundColor Yellow
    return
}

$allKeys = $rows | ForEach-Object { $_.AdditionalProperties.Keys } | Select-Object -Unique

$table = @()
foreach ($row in $rows) {
    $obj = New-Object PSObject
    foreach ($key in $allKeys) {
        $value = $row.AdditionalProperties[$key]
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $obj | Add-Member -NotePropertyName $key -NotePropertyValue ($value -join ", ")
        } else {
            $obj | Add-Member -NotePropertyName $key -NotePropertyValue $value
        }
    }
    $table += $obj
}

$table | Format-Table -Property $allKeys -AutoSize

if ($OutputFile) {
    $table | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Query results exported to: $OutputFile" -ForegroundColor Green
}