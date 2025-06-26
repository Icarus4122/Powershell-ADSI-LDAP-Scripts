function Get-DomainUserInfo {
    param (
        [string]$Username
    )

    Write-Host "`n[+] Searching for user '$Username' in Active Directory..." -ForegroundColor Yellow

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $ldap = "LDAP://" + $domain.Name
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ldap)
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$Username))"
        $searcher.PageSize = 500
        $searcher.PropertiesToLoad.AddRange(@(
            "samaccountname", "distinguishedname", "userprincipalname", "memberof", "primarygroupid",
            "whencreated", "whenchanged", "lastlogon", "lastlogontimestamp", "pwdlastset",
            "badpwdcount", "badpasswordtime", "logoncount", "useraccountcontrol", "accountexpires",
            "objectsid", "description", "title", "telephoneNumber", "mail"
        ))

        $result = $searcher.FindOne()

        if ($result -ne $null) {
            $user = $result.Properties

            Write-Host "`n=== [*] User Properties ===" -ForegroundColor Cyan
            Write-Host "  sAMAccountName    : $($user.samaccountname)"
            Write-Host "  UserPrincipalName : $($user.userprincipalname)"
            Write-Host "  DistinguishedName : $($user.distinguishedname)"
            Write-Host "  ObjectSID         : $([System.Security.Principal.SecurityIdentifier]::new($user.objectsid[0], 0))"

            Write-Host "`n=== [*] Account Details ===" -ForegroundColor Cyan
            Write-Host "  Account Created   : $($user.whencreated)"
            Write-Host "  Last Changed      : $($user.whenchanged)"
            Write-Host "  Last Logon        : $(Convert-FileTime $user.lastlogon[0])"
            Write-Host "  LastLogonTimestamp: $(Convert-FileTime $user.lastlogontimestamp[0])"
            Write-Host "  Password Last Set : $(Convert-FileTime $user.pwdlastset[0])"
            Write-Host "  Bad Password Count: $($user.badpwdcount)"
            Write-Host "  Logon Count       : $($user.logoncount)"
            Write-Host "  Account Expires   : $(Convert-FileTime $user.accountexpires[0])"
            Write-Host "  UserAccountControl: $($user.useraccountcontrol)"

            Write-Host "`n=== [*] Contact Info ===" -ForegroundColor Cyan
            Write-Host "  Title             : $($user.title)"
            Write-Host "  Email             : $($user.mail)"
            Write-Host "  Phone             : $($user.telephonenumber)"
            Write-Host "  Description       : $($user.description)"

            Write-Host "`n=== [*] Group Memberships ===" -ForegroundColor Cyan
            if ($user.memberof) {
                foreach ($groupDN in $user.memberof) {
                    Write-Host "  [+] $groupDN" -ForegroundColor Magenta
                }
            } else {
                Write-Host "  [-] No group membership found." -ForegroundColor DarkGray
            }

        } else {
            Write-Host "[!] User '$Username' not found." -ForegroundColor Red
        }

    } catch {
        Write-Host "[!] Error during user enumeration: $_" -ForegroundColor Red
    }
}

# Utility: Convert Windows FileTime to readable date
function Convert-FileTime {
    param($fileTime)
    if ($fileTime -is [System.Int64] -and $fileTime -gt 0) {
        return [datetime]::FromFileTime($fileTime)
    } else {
        return "N/A"
    }
}
