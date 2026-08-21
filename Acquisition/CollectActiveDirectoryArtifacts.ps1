<#
.Description: Detects Active Directory Domain Controller role and collects AD forensic artifacts (SYSVOL/GPOs, NTDS/SYSTEM BootKey, ADSI Kerberos & Privilege Auditing, AD Event Logs, DNS Zones).
.Documentation: When an Active Directory Domain Controller is compromised, this script captures directory configurations, Kerberos attack vectors (Kerberoasting, AS-REP Roasting, Delegations), Golden Ticket indicators (krbtgt), SYSVOL policies, and logs.
.Required Permissions: Administrator / Domain Administrator

.Example:
    .\CollectActiveDirectoryArtifacts.ps1
    .\CollectActiveDirectoryArtifacts.ps1 -OutputDir "C:\IR\AD_Artifacts"
    .\CollectActiveDirectoryArtifacts.ps1 -DumpNTDS
    .\CollectActiveDirectoryArtifacts.ps1 -IncludeSYSVOL
    .\CollectActiveDirectoryArtifacts.ps1 -Force
#>

param (
    [String]$OutputDir,
    [Switch]$DumpNTDS,
    [Switch]$IncludeSYSVOL,
    [Switch]$Force
)

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "    Active Directory Domain Controller Forensics Collector" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# 1. Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to collect Active Directory artifacts. Please run PowerShell as Administrator."
    return
}

# 2. Detect if Host is an Active Directory Domain Controller
$isDC = $false
$detectionReasons = @()

$csInfo = $null
try {
    $csInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
} catch { }

if ($csInfo -and ($csInfo.DomainRole -in @(4, 5))) {
    $isDC = $true
    $roleName = if ($csInfo.DomainRole -eq 5) { "Primary Domain Controller (PDC)" } else { "Backup Domain Controller (BDC)" }
    $detectionReasons += "DomainRole: $roleName"
}

$osInfo = $null
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch { }

if ($osInfo -and ($osInfo.ProductType -eq 2)) {
    $isDC = $true
    $detectionReasons += "ProductType: Domain Controller (Type 2)"
}

$ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($ntdsService -and $ntdsService.Status -eq 'Running') {
    $isDC = $true
    $detectionReasons += "NTDS Service: Running"
}

if (-not $isDC -and -not $Force) {
    Write-Warning "This machine does NOT appear to be an Active Directory Domain Controller."
    Write-Host "Detected Role: $(if ($csInfo) { $csInfo.DomainRole } else { 'Unknown' }) | ProductType: $(if ($osInfo) { $osInfo.ProductType } else { 'Unknown' })" -ForegroundColor DarkGray
    Write-Host "To force execution anyway on domain-joined member servers/workstations, use the -Force parameter." -ForegroundColor Yellow
    return
}

if ($isDC) {
    Write-Host " [+] Confirmed Domain Controller role: $($detectionReasons -join ' | ')" -ForegroundColor Green
} else {
    Write-Host " [!] Executing in forced mode (-Force) on non-DC host." -ForegroundColor Yellow
}

if (-not $OutputDir) {
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "AD_Forensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$csvDir = Join-Path -Path $OutputDir -ChildPath "CSV"
New-Item -Path $csvDir -ItemType Directory -Force | Out-Null

function Copy-LockedFileSafely {
    param ([string]$SourcePath, [string]$DestinationPath)
    try {
        $sourceStream = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $destStream = [System.IO.File]::Create($DestinationPath)
        $sourceStream.CopyTo($destStream)
        $destStream.Close()
        $destStream.Dispose()
        $sourceStream.Close()
        $sourceStream.Dispose()
        return $true
    } catch {
        return $false
    }
}

# 3. Domain & Forest Metadata (via ADSI / .NET)
Write-Host "`n[1/6] Querying Domain & Forest Information..." -ForegroundColor Yellow
$domainName = $env:USERDNSDOMAIN
$domainInfoList = @()

try {
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $currentDomain.Name
    $forest = $currentDomain.Forest

    Write-Host " [+] Domain Name:     $($currentDomain.Name)" -ForegroundColor Green
    Write-Host " [+] Forest Name:     $($forest.Name)" -ForegroundColor Green
    Write-Host " [+] Domain Mode:     $($currentDomain.DomainMode)" -ForegroundColor Green
    Write-Host " [+] PDC Emulator:    $($currentDomain.PdcRoleOwner.Name)" -ForegroundColor Green
    Write-Host " [+] RID Master:      $($currentDomain.RidRoleOwner.Name)" -ForegroundColor Green
    Write-Host " [+] Schema Master:   $($forest.SchemaRoleOwner.Name)" -ForegroundColor Green

    $domainInfoList += [PSCustomObject]@{
        DomainName       = $currentDomain.Name
        ForestName       = $forest.Name
        DomainMode       = "$($currentDomain.DomainMode)"
        ForestMode       = "$($forest.ForestMode)"
        PdcRoleOwner     = "$($currentDomain.PdcRoleOwner.Name)"
        RidRoleOwner     = "$($currentDomain.RidRoleOwner.Name)"
        InfraRoleOwner   = "$($currentDomain.InfrastructureRoleOwner.Name)"
        SchemaRoleOwner  = "$($forest.SchemaRoleOwner.Name)"
        NamingRoleOwner  = "$($forest.NamingRoleOwner.Name)"
    }
    $domainInfoList | Export-Csv -Path "$csvDir\AD_Domain_Summary.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Warning " Could not query Active Directory .NET classes: $($_.Exception.Message)"
}

# 4. ADSI Forensic Object Queries (Kerberos, Privileged Accounts, Trusts)
Write-Host "`n[2/6] Auditing High-Risk Active Directory Objects (ADSI)..." -ForegroundColor Yellow

function Search-ADSI {
    param (
        [string]$Filter,
        [string[]]$Properties = @("name", "samaccountname", "distinguishedname", "useraccountcontrol", "pwdlastset", "whencreated")
    )
    $results = @()
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $rootDse.defaultNamingContext
        if (-not $defaultNamingContext) { return @() }

        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNamingContext")
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }

        $searchResults = $searcher.FindAll()
        foreach ($res in $searchResults) {
            $objProps = [ordered]@{}
            foreach ($prop in $Properties) {
                $val = $res.Properties[$prop]
                $objProps[$prop] = if ($val -and $val.Count -gt 0) { $val[0].ToString() } else { "" }
            }
            $results += [PSCustomObject]$objProps
        }
        $searchResults.Dispose()
        $searcher.Dispose()
    } catch {
        Write-Warning " ADSI Search failed for filter '$Filter': $($_.Exception.Message)"
    }
    return $results
}

# 4.1 Privileged Accounts (adminCount = 1)
Write-Host " [*] Checking Protected / High-Privilege Accounts (adminCount=1)..." -NoNewline
$privAccounts = Search-ADSI -Filter "(&(objectClass=user)(adminCount=1))" -Properties @("samaccountname", "distinguishedname", "useraccountcontrol", "pwdlastset", "whencreated", "memberof")
if ($privAccounts.Count -gt 0) {
    Write-Host " [$($privAccounts.Count) found]" -ForegroundColor Green
    $privAccounts | Export-Csv -Path "$csvDir\AD_PrivilegedAccounts_AdminCount.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [0 found]" -ForegroundColor DarkGray }

# 4.2 Kerberoasting Targets (Users with ServicePrincipalNames)
Write-Host " [*] Checking Kerberoasting Target Accounts (User accounts with SPNs)..." -NoNewline
$spnAccounts = Search-ADSI -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(samaccountname=krbtgt)))" -Properties @("samaccountname", "serviceprincipalname", "distinguishedname", "pwdlastset", "whencreated")
if ($spnAccounts.Count -gt 0) {
    Write-Host " [$($spnAccounts.Count) VULNERABLE TARGETS]" -ForegroundColor Red
    $spnAccounts | Export-Csv -Path "$csvDir\AD_Kerberoasting_Targets.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [0 found]" -ForegroundColor DarkGray }

# 4.3 AS-REP Roasting Targets (DONT_REQ_PREAUTH = 4194304)
Write-Host " [*] Checking AS-REP Roasting Targets (Pre-Auth Disabled)..." -NoNewline
$asrepAccounts = Search-ADSI -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("samaccountname", "distinguishedname", "useraccountcontrol", "pwdlastset", "whencreated")
if ($asrepAccounts.Count -gt 0) {
    Write-Host " [$($asrepAccounts.Count) VULNERABLE TARGETS]" -ForegroundColor Red
    $asrepAccounts | Export-Csv -Path "$csvDir\AD_ASREPRoasting_Targets.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [0 found]" -ForegroundColor DarkGray }

# 4.4 Kerberos Unconstrained Delegation (TRUSTED_FOR_DELEGATION = 524288)
Write-Host " [*] Checking Kerberos Unconstrained Delegation..." -NoNewline
$unconstrained = Search-ADSI -Filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties @("samaccountname", "distinguishedname", "useraccountcontrol", "whencreated")
if ($unconstrained.Count -gt 0) {
    Write-Host " [$($unconstrained.Count) found]" -ForegroundColor Yellow
    $unconstrained | Export-Csv -Path "$csvDir\AD_Unconstrained_Delegation.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [0 found]" -ForegroundColor DarkGray }

# 4.5 krbtgt Account Inspection (Golden Ticket Indicator)
Write-Host " [*] Inspecting krbtgt account metadata..." -NoNewline
$krbtgtObj = Search-ADSI -Filter "(&(objectClass=user)(samaccountname=krbtgt))" -Properties @("samaccountname", "distinguishedname", "pwdlastset", "whencreated", "whenchanged")
if ($krbtgtObj.Count -gt 0) {
    Write-Host " [OK]" -ForegroundColor Green
    $krbtgtObj | Export-Csv -Path "$csvDir\AD_krbtgt_Metadata.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [Not found]" -ForegroundColor DarkGray }

# 4.6 Domain Trusts
Write-Host " [*] Enumerating Domain Trusts..." -NoNewline
$trusts = Search-ADSI -Filter "(objectClass=trustedDomain)" -Properties @("name", "trustdirection", "trusttype", "trustattributes", "flatname")
if ($trusts.Count -gt 0) {
    Write-Host " [$($trusts.Count) trust(s) found]" -ForegroundColor Green
    $trusts | Export-Csv -Path "$csvDir\AD_Domain_Trusts.csv" -NoTypeInformation -Encoding UTF8
} else { Write-Host " [0 trusts]" -ForegroundColor DarkGray }

# 5. SYSVOL & Group Policy (GPO) Acquisition
Write-Host "`n[3/6] Collecting SYSVOL & Group Policy Objects (GPOs)..." -ForegroundColor Yellow
$sysvolBase = "$env:SystemRoot\SYSVOL\sysvol"

if (Test-Path -LiteralPath $sysvolBase) {
    $sysvolOutDir = Join-Path -Path $OutputDir -ChildPath "SYSVOL"
    New-Item -Path $sysvolOutDir -ItemType Directory -Force | Out-Null

    # Scan for cpassword in SYSVOL XMLs
    Write-Host " [*] Scanning SYSVOL XML files for legacy 'cpassword' credentials..." -ForegroundColor Yellow
    $cpasswordMatches = @()
    $gpoXmlFiles = Get-ChildItem -Path $sysvolBase -Recurse -Filter "*.xml" -File -ErrorAction SilentlyContinue

    foreach ($xmlFile in $gpoXmlFiles) {
        $matches = Select-String -Path $xmlFile.FullName -Pattern 'cpassword="([^"]+)"' -ErrorAction SilentlyContinue
        if ($matches) {
            foreach ($m in $matches) {
                Write-Host " [!] FOUND CPASSWORD IN: $($xmlFile.FullName)" -ForegroundColor Red
                $cpasswordMatches += [PSCustomObject]@{
                    File = $xmlFile.FullName
                    Line = $m.LineNumber
                    Match = $m.Line.Trim()
                }
            }
        }
    }

    if ($cpasswordMatches.Count -gt 0) {
        $cpasswordMatches | Export-Csv -Path "$csvDir\AD_SYSVOL_cpassword_Findings.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($IncludeSYSVOL) {
        Write-Host " [*] Archiving complete SYSVOL policies and scripts folder..." -NoNewline
        try {
            $policiesSrc = Get-ChildItem -Path $sysvolBase -Directory -ErrorAction SilentlyContinue
            foreach ($domainDir in $policiesSrc) {
                $targetDomainDir = Join-Path -Path $sysvolOutDir -ChildPath $domainDir.Name
                Copy-Item -Path $domainDir.FullName -Destination $targetDomainDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host " [OK]" -ForegroundColor Green
        } catch {
            Write-Warning " Failed to copy complete SYSVOL: $($_.Exception.Message)"
        }
    } else {
        Write-Host " [*] Collecting GPO scripts and INI/INF templates..." -NoNewline
        $scriptsAndInfs = Get-ChildItem -Path $sysvolBase -Recurse -File -Include @("*.bat", "*.cmd", "*.vbs", "*.ps1", "*.inf", "*.ini") -ErrorAction SilentlyContinue
        $scriptsOut = Join-Path -Path $sysvolOutDir -ChildPath "ScriptsAndTemplates"
        New-Item -Path $scriptsOut -ItemType Directory -Force | Out-Null
        foreach ($sf in $scriptsAndInfs) {
            Copy-Item -LiteralPath $sf.FullName -Destination $scriptsOut -Force -ErrorAction SilentlyContinue
        }
        Write-Host " [$($scriptsAndInfs.Count) files copied]" -ForegroundColor Green
    }
} else {
    Write-Host " SYSVOL directory not present on this host." -ForegroundColor DarkGray
}

# 6. SYSTEM Registry Hive (BootKey / PEK) & Optional NTDS Database Dump
Write-Host "`n[4/6] Dumping SYSTEM Hive (BootKey / PEK Decryption Key)..." -ForegroundColor Yellow
$systemHiveFile = Join-Path -Path $OutputDir -ChildPath "SYSTEM.hive"
$proc = Start-Process -FilePath "reg.exe" -ArgumentList "save `"HKLM\SYSTEM`" `"$systemHiveFile`" /y" -Wait -NoNewWindow -PassThru

if ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $systemHiveFile)) {
    $sizeMB = [math]::Round(((Get-Item $systemHiveFile).Length / 1MB), 2)
    Write-Host " [+] SYSTEM Hive dumped successfully ($sizeMB MB) -> $systemHiveFile" -ForegroundColor Green
} else {
    Write-Warning " Failed to dump SYSTEM Hive."
}

if ($DumpNTDS) {
    Write-Host "`n [*] Dumping NTDS.dit via ntdsutil IFM (Install From Media)..." -ForegroundColor Yellow
    $ntdsDumpDir = Join-Path -Path $OutputDir -ChildPath "NTDS_IFM"
    New-Item -Path $ntdsDumpDir -ItemType Directory -Force | Out-Null

    $ntdsCmd = "activate instance ntds`nifm`ncreate full `"$ntdsDumpDir`"`nq`nq`n"
    $ntdsProcess = Start-Process -FilePath "ntdsutil.exe" -ArgumentList "`"ac i ntds`" `"ifm`" `"create full $ntdsDumpDir`" q q" -Wait -NoNewWindow -PassThru

    $ntdsDitPath = Join-Path -Path $ntdsDumpDir -ChildPath "Active Directory\ntds.dit"
    if (Test-Path -LiteralPath $ntdsDitPath) {
        $ditSizeMB = [math]::Round(((Get-Item $ntdsDitPath).Length / 1MB), 2)
        Write-Host " [+] NTDS.dit successfully exported via IFM ($ditSizeMB MB)!" -ForegroundColor Green
    } else {
        Write-Warning " NTDS.dit IFM export failed or file not found. Check ntdsutil output."
    }
}

# 7. Active Directory EVTX Event Logs
Write-Host "`n[5/6] Collecting Active Directory Event Logs (.evtx)..." -ForegroundColor Yellow
$adEvtxFolder = Join-Path -Path $OutputDir -ChildPath "AD_EventLogs"
New-Item -Path $adEvtxFolder -ItemType Directory -Force | Out-Null
$evtxBase = "$env:SystemRoot\System32\Winevt\Logs"

$adLogs = @(
    "Directory Service.evtx",
    "DNS Server.evtx",
    "Active Directory Web Services.evtx",
    "DFS Replication.evtx",
    "Microsoft-Windows-ActiveDirectory_DomainService%4Operational.evtx",
    "Microsoft-Windows-NTDS-Replication%4Operational.evtx"
)

foreach ($log in $adLogs) {
    $src = Join-Path -Path $evtxBase -ChildPath $log
    $dst = Join-Path -Path $adEvtxFolder -ChildPath $log

    Write-Host " Copying $log..." -NoNewline
    if (Test-Path -LiteralPath $src) {
        $res = Copy-LockedFileSafely -SourcePath $src -DestinationPath $dst
        if ($res) {
            Write-Host " [OK]" -ForegroundColor Green
        } else {
            Write-Host " [LOCKED / FAILED]" -ForegroundColor Red
        }
    } else {
        Write-Host " [NOT PRESENT]" -ForegroundColor DarkGray
    }
}

# 8. DNS Server Zones & Logs
Write-Host "`n[6/6] Collecting DNS Server Configuration & Zones..." -ForegroundColor Yellow
$dnsSys32 = "$env:SystemRoot\System32\dns"
if (Test-Path -LiteralPath $dnsSys32) {
    $dnsOutDir = Join-Path -Path $OutputDir -ChildPath "DNS_Server"
    New-Item -Path $dnsOutDir -ItemType Directory -Force | Out-Null

    $dnsFiles = Get-ChildItem -Path $dnsSys32 -File -ErrorAction SilentlyContinue
    if ($dnsFiles) {
        foreach ($df in $dnsFiles) {
            Copy-Item -LiteralPath $df.FullName -Destination $dnsOutDir -Force -ErrorAction SilentlyContinue
        }
        Write-Host " [+] Copied $($dnsFiles.Count) DNS configuration/zone file(s)." -ForegroundColor Green
    } else {
        Write-Host " No static DNS zone files in $dnsSys32 (Zones may be AD-integrated)." -ForegroundColor DarkGray
    }
}

Write-Host "`n===========================================================" -ForegroundColor Cyan
Write-Host " Active Directory Forensics Acquisition Completed!" -ForegroundColor Cyan
Write-Host " Output Directory: $OutputDir" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
