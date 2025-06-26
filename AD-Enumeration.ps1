function Test-PasswordSprayable {
    Write-Host "`n[+] Checking Lockout Policy (for password spraying feasibility)..." -ForegroundColor Yellow
    net accounts
}

function Find-ASREPRoastableUsers {
    Write-Host "`n[+] Searching for AS-REP Roastable Users (DONT_REQ_PREAUTH)..." -ForegroundColor Yellow
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname"))
    $users = $searcher.FindAll()

    foreach ($u in $users) {
        $sam = $u.Properties["samaccountname"]
        Write-Host "[AS-REP] User: $sam" -ForegroundColor Cyan
    }
}

function Find-KerberoastableUsers {
    Write-Host "`n[+] Searching for Kerberoastable Users (SPNs set)..." -ForegroundColor Yellow
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname"))
    $results = $searcher.FindAll()

    foreach ($r in $results) {
        $user = $r.Properties["samaccountname"]
        $spns = $r.Properties["serviceprincipalname"]
        foreach ($spn in $spns) {
            Write-Host "[SPN] $user → $spn" -ForegroundColor Cyan
        }
    }
}

function Check-SilverTicketTargets {
    Write-Host "`n[+] Identifying services vulnerable to Silver Tickets..." -ForegroundColor Yellow
    Write-Host "[*] Looking for SPNs for service accounts. These can be forged if NTLM hash is known." -ForegroundColor Gray
    # Reuse SPN enumeration above
    Find-KerberoastableUsers
    Write-Host "[*] Next step would be to extract NTLM hash from SAM or LSASS or dump service account creds to forge." -ForegroundColor DarkGray
}

function Check-DCSyncPermissions {
    Write-Host "`n[+] Checking for DC Sync Privileges..." -ForegroundColor Yellow
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $identity.User.Value
        $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new("Domain")
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
        $dn = "CN=Configuration," + $domainDN
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
        $searcher.Filter = "(objectClass=*)"
        $searcher.SearchScope = "Base"
        $searcher.PropertiesToLoad.Add("ntSecurityDescriptor") > $null
        $result = $searcher.FindOne()
        if ($result) {
            Write-Host "[*] Domain is accessible. Next, use advanced tools (e.g., PowerView or SharpHound) to check for Replication rights (DS-Replication-Get-Changes etc.)" -ForegroundColor Cyan
        } else {
            Write-Host "[!] Could not access domain object." -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error checking DC Sync: $_" -ForegroundColor Red
    }
}

function Find-DCSyncPrincipals {
    Write-Host "`n[+] Enumerating all users/groups with DC Sync privileges..." -ForegroundColor Yellow

    $guidMap = @{
        "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes"
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
    }

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
        $ldapPath = "LDAP://$domainDN"

        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $acl = $entry.ObjectSecurity.Access

        foreach ($ace in $acl) {
            $guid = $ace.ObjectType.ToString().ToLower()
            if ($guidMap.ContainsKey($guid)) {
                $rightName = $guidMap[$guid]
                $principal = $ace.IdentityReference.ToString()
                Write-Host "[+] $principal has $rightName" -ForegroundColor Cyan
            }
        }

        Write-Host "`n[*] NOTE: DCSync requires both 'Get-Changes' AND 'Get-Changes-All'" -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }
}


# Run them all
Test-PasswordSprayable
Find-ASREPRoastableUsers
Find-KerberoastableUsers
Check-SilverTicketTargets
Find-DCSyncPrincipals
Check-DCSyncPermissions
