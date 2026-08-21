<#
.Description: Resets the active sessions of all users in the defined list.
.Documentation: https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http
.Required Permissions: User.RevokeSessions.All	

.Example:
    .\RevokeSessions.ps1 -Users "compromised_user@domain.com"
    .\RevokeSessions.ps1 -Users "user1@domain.com", "user2@domain.com"
#>

param (
    [Parameter(Mandatory=$false)]
    [string[]]$Users = @('user1@kqlquery.com', 'user2@kqlquery.com')
)

Connect-MgGraph -Scopes User.RevokeSessions.All	

Import-Module Microsoft.Graph.Users.Actions

Write-Output "Start revoking sessions for $($Users.Count) user(s)..."

# Revoke user sessions
foreach ($user in $Users) {
    try {
        $result = Revoke-MgUserSignInSession -UserId $user -ErrorAction Stop
        if ($result) {
            Write-Host " [+] Successfully revoked sessions for $user" -ForegroundColor Green
        } else {
            Write-Host " [-] Failed to revoke sessions for $user" -ForegroundColor Red
        }
    } catch {
        Write-Error "Error revoking sessions for $user : $($_.Exception.Message)"
    }
}