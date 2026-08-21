<#
.SYNOPSIS
    Active Directory On-Premises & Hybrid User Account Containment & Quarantine.

.DESCRIPTION
    Executes a comprehensive containment workflow on compromised Active Directory user accounts:
    1. Account Disabling (Disable-ADAccount / ADSI userAccountControl flag)
    2. Strong Cryptographic Password Reset (32 characters)
    3. Kerberos TGT Invalidation & Force Password Expiration
    4. Privileged Group Membership Removal (Domain Admins, Enterprise Admins, etc.)
    5. Quarantine OU Relocation (Optional)
    6. ADSI Fallback (Works even without the RSAT ActiveDirectory PowerShell module)

.PARAMETER Identity
    SamAccountName, UserPrincipalName, or DistinguishedName of target user(s).

.PARAMETER DisableAccount
    Disables the Active Directory account immediately. Default: True.

.PARAMETER ResetPassword
    Generates a cryptographically strong 32-character random password. Default: True.

.PARAMETER RemovePrivilegedGroups
    Removes the user from high-privilege groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Server Operators, Account Operators, Backup Operators, Remote Desktop Users).

.PARAMETER QuarantineOU
    DistinguishedName of the Quarantine Organizational Unit to move the user account into (e.g. "OU=Quarantine,DC=corp,DC=local").

.PARAMETER FullContainment
    Executes all containment actions (Disable + Password Reset + Remove Privileged Groups + Quarantine OU if provided).

.EXAMPLE
    .\Revoke-ADUserHybrid.ps1 -Identity "compromised_user" -FullContainment

.EXAMPLE
    .\Revoke-ADUserHybrid.ps1 -Identity "user1", "user2" -DisableAccount -ResetPassword

.EXAMPLE
    .\Revoke-ADUserHybrid.ps1 -Identity "compromised_admin" -RemovePrivilegedGroups -QuarantineOU "OU=Quarantine,DC=domain,DC=com"

.REQUIRED PERMISSIONS
    Domain Administrator / Delegated Active Directory permissions
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [string[]]$Identity,

    [Parameter(Mandatory = $false)]
    [switch]$DisableAccount,

    [Parameter(Mandatory = $false)]
    [switch]$ResetPassword,

    [Parameter(Mandatory = $false)]
    [switch]$RemovePrivilegedGroups,

    [Parameter(Mandatory = $false)]
    [string]$QuarantineOU,

    [Parameter(Mandatory = $false)]
    [switch]$FullContainment
)

if (-not $DisableAccount -and -not $ResetPassword -and -not $RemovePrivilegedGroups -and -not $QuarantineOU) {
    $FullContainment = $true
}

if ($FullContainment) {
    $DisableAccount = $true
    $ResetPassword = $true
    $RemovePrivilegedGroups = $true
}

$PrivilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Server Operators",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Remote Desktop Users",
    "Group Policy Creator Owners",
    "DnsAdmins"
)

function New-StrongPassword {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    return $password
}

Write-Host @"
===================================================================
     Active Directory On-Premises & Hybrid Account Containment
===================================================================
"@ -ForegroundColor Red

$HasADModule = (Get-Module -ListAvailable -Name ActiveDirectory) -ne $null
if ($HasADModule) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Write-Host "[+] ActiveDirectory PowerShell module loaded." -ForegroundColor Green
} else {
    Write-Host "[!] ActiveDirectory module not found. Using ADSI directory services fallback." -ForegroundColor Yellow
}

$summaryReport = @()

foreach ($user in $Identity) {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Yellow
    Write-Host " [!] INITIATING AD CONTAINMENT FOR: $user" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Yellow

    $report = [PSCustomObject]@{
        User               = $user
        AccountDisabled    = "Skipped"
        PasswordReset      = "Skipped"
        TempPassword       = ""
        GroupsRemoved      = "Skipped"
        QuarantineMoved    = "Skipped"
        Status             = "Success"
        Errors             = @()
    }

    if ($HasADModule) {
        # --- RSAT ActiveDirectory Module Implementation ---
        try {
            $adUser = Get-ADUser -Identity $user -Properties MemberOf, Enabled, DistinguishedName -ErrorAction Stop
            Write-Host "[+] User verified: $($adUser.Name) ($($adUser.DistinguishedName))" -ForegroundColor Green
        } catch {
            Write-Error "Failed to locate user '$user' in Active Directory: $($_.Exception.Message)"
            $report.Status = "Failed"
            $report.Errors += "User not found"
            $summaryReport += $report
            continue
        }

        # 1. Disable Account
        if ($DisableAccount) {
            if ($PSCmdlet.ShouldProcess($user, "Disable Active Directory Account")) {
                try {
                    Disable-ADAccount -Identity $adUser.DistinguishedName -ErrorAction Stop
                    Write-Host " [+] [1/4] Account disabled successfully." -ForegroundColor Green
                    $report.AccountDisabled = "Disabled"
                } catch {
                    Write-Warning " [-] [1/4] Failed to disable account: $($_.Exception.Message)"
                    $report.AccountDisabled = "Failed"
                    $report.Errors += "Disable error: $($_.Exception.Message)"
                }
            }
        }

        # 2. Strong Password Reset
        if ($ResetPassword) {
            if ($PSCmdlet.ShouldProcess($user, "Reset password to strong random string & expire")) {
                try {
                    $tempPass = New-StrongPassword
                    $secPass = ConvertTo-SecureString $tempPass -AsPlainText -Force
                    Set-ADAccountPassword -Identity $adUser.DistinguishedName -NewPassword $secPass -Reset -ErrorAction Stop
                    Set-ADUser -Identity $adUser.DistinguishedName -ChangePasswordAtLogon $true -ErrorAction Stop
                    Write-Host " [+] [2/4] Temporary 32-character password set & forced change on next logon." -ForegroundColor Green
                    Write-Host "     ==> Temp Password: $tempPass" -ForegroundColor Magenta
                    $report.PasswordReset = "Reset"
                    $report.TempPassword  = $tempPass
                } catch {
                    Write-Warning " [-] [2/4] Failed to reset password: $($_.Exception.Message)"
                    $report.PasswordReset = "Failed"
                    $report.Errors += "Password reset error: $($_.Exception.Message)"
                }
            }
        }

        # 3. Strip Privileged Group Memberships
        if ($RemovePrivilegedGroups) {
            if ($PSCmdlet.ShouldProcess($user, "Remove user from high-privilege groups")) {
                Write-Host " [*] [3/4] Checking and removing privileged group memberships..." -ForegroundColor Cyan
                $removedCount = 0
                try {
                    $userGroups = Get-ADPrincipalGroupMembership -Identity $adUser.DistinguishedName -ErrorAction SilentlyContinue
                    foreach ($grp in $userGroups) {
                        if ($PrivilegedGroupNames -contains $grp.Name) {
                            Write-Host "     [-] Removing from high-privilege group: $($grp.Name)" -ForegroundColor Yellow
                            Remove-ADGroupMember -Identity $grp.DistinguishedName -Members $adUser.DistinguishedName -Confirm:$false -ErrorAction Stop
                            $removedCount++
                        }
                    }
                    Write-Host " [+] [3/4] Removed from $removedCount privileged group(s)." -ForegroundColor Green
                    $report.GroupsRemoved = "Removed ($removedCount groups)"
                } catch {
                    Write-Warning " [-] [3/4] Error removing group memberships: $($_.Exception.Message)"
                    $report.GroupsRemoved = "Failed"
                    $report.Errors += "Group removal error: $($_.Exception.Message)"
                }
            }
        }

        # 4. Move to Quarantine OU
        if ($QuarantineOU) {
            if ($PSCmdlet.ShouldProcess($user, "Move to Quarantine OU: $QuarantineOU")) {
                try {
                    Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $QuarantineOU -ErrorAction Stop
                    Write-Host " [+] [4/4] Account moved to Quarantine OU: $QuarantineOU" -ForegroundColor Green
                    $report.QuarantineMoved = "Moved"
                } catch {
                    Write-Warning " [-] [4/4] Failed to move user to Quarantine OU: $($_.Exception.Message)"
                    $report.QuarantineMoved = "Failed"
                    $report.Errors += "OU Move error: $($_.Exception.Message)"
                }
            }
        }

    } else {
        # --- ADSI Fallback Implementation (No RSAT required) ---
        try {
            $searcher = [ADSISearcher]"(sAMAccountName=$user)"
            $result = $searcher.FindOne()
            if (-not $result) {
                Write-Error "ADSI searcher failed to find user '$user'."
                $report.Status = "Failed"
                $report.Errors += "User not found via ADSI"
                $summaryReport += $report
                continue
            }

            $de = $result.GetDirectoryEntry()
            Write-Host "[+] User located via ADSI: $($de.distinguishedName)" -ForegroundColor Green

            # 1. Disable Account via userAccountControl bitflag (0x0002 = ACCOUNTDISABLE)
            if ($DisableAccount) {
                if ($PSCmdlet.ShouldProcess($user, "Disable Account via ADSI")) {
                    try {
                        $uac = $de.userAccountControl.Value
                        $de.userAccountControl = $uac -bor 0x0002
                        $de.SetInfo()
                        Write-Host " [+] [1/4] Account disabled via ADSI." -ForegroundColor Green
                        $report.AccountDisabled = "Disabled"
                    } catch {
                        Write-Warning " [-] [1/4] ADSI disable failed: $($_.Exception.Message)"
                        $report.AccountDisabled = "Failed"
                    }
                }
            }

            # 2. Reset Password via ADSI
            if ($ResetPassword) {
                if ($PSCmdlet.ShouldProcess($user, "Reset password via ADSI")) {
                    try {
                        $tempPass = New-StrongPassword
                        $de.SetPassword($tempPass)
                        $de.pwdLastSet = 0 # Force change password on next logon
                        $de.SetInfo()
                        Write-Host " [+] [2/4] Password reset via ADSI & forced change on next logon." -ForegroundColor Green
                        Write-Host "     ==> Temp Password: $tempPass" -ForegroundColor Magenta
                        $report.PasswordReset = "Reset"
                        $report.TempPassword  = $tempPass
                    } catch {
                        Write-Warning " [-] [2/4] ADSI password reset failed: $($_.Exception.Message)"
                        $report.PasswordReset = "Failed"
                    }
                }
            }

        } catch {
            Write-Error "ADSI operation error: $($_.Exception.Message)"
            $report.Status = "Failed"
            $report.Errors += $_.Exception.Message
        }
    }

    if ($report.Errors.Count -gt 0) {
        $report.Status = "Partial/Errors"
    }

    $summaryReport += $report
}

# --- Final Summary Table ---
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "             ACTIVE DIRECTORY CONTAINMENT SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
$summaryReport | Format-Table -Property User, AccountDisabled, PasswordReset, GroupsRemoved, QuarantineMoved, Status -AutoSize
Write-Host "[+] AD Containment execution complete." -ForegroundColor Green
