<#
.Description: Changes the user password with a new random password, and enforces password change on first sign-in.
.Documentation: https://learn.microsoft.com/en-us/graph/api/authenticationmethod-resetpassword?view=graph-rest-1.0&tabs=http
.Required Permissions: UserAuthenticationMethod.ReadWrite.All

.Example:
    .\ForcePasswordChangeNextSignIn.ps1 -Users "compromised_user@domain.com"
    .\ForcePasswordChangeNextSignIn.ps1 -Users "user1@domain.com", "user2@domain.com"
#>

param (
    [Parameter(Mandatory=$false)]
    [string[]]$Users = @('user1@kqlquery.com', 'user2@kqlquery.com')
)

Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All

Import-Module Microsoft.Graph.Users.Actions

Write-Output "Start Force Password Change for $($Users.Count) user(s)..."

# Force Password Change
foreach ($user in $Users) {
    try {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $randomString = -join ((1..30) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $method = Get-MgUserAuthenticationPasswordMethod -UserId $user -ErrorAction Stop
        $methodId = if ($method -is [array]) { $method[0].Id } else { $method.Id }

        if ($methodId) {
            Reset-MgUserAuthenticationMethodPassword -UserId $user -AuthenticationMethodId $methodId -NewPassword $randomString -ErrorAction Stop
            Write-Host " [+] Set force Change Password Next SignIn for $user. Temporary password is: $randomString" -ForegroundColor Green
        } else {
            Write-Warning "No authentication password method found for $user"
        }
    } catch {
        Write-Error "Failed to reset password for $user : $($_.Exception.Message)"
    }
}