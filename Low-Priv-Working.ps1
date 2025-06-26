
# Bypass Execution Policy (use this at launch)
# powershell.exe -ep bypass -f .\Low-Priv.ps1

# Get the Primary Domain Controller and Distinguished Name
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domain.PdcRoleOwner.Name
$DN  = ([ADSI]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

# Display Basic Domain Info
Write-Host "[*] PDC: $PDC" -ForegroundColor Cyan
try {
    $PDC_IPs = [System.Net.Dns]::GetHostAddresses($PDC) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
    Write-Host "[*] PDC IP(s): $($PDC_IPs -join ', ')" -ForegroundColor Cyan
} catch {
    Write-Host "[!] Failed to resolve PDC IP address." -ForegroundColor Red
}
Write-Host "[*] DN:  $DN"  -ForegroundColor Cyan

function Resolve-NestedGroupMembers {
    param (
        [string]$GroupDN,
        [string]$Prefix = "",
        [string]$Branch = "+--"
    )

    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(distinguishedName=$GroupDN)"
        $searcher.PropertiesToLoad.Add("member") > $null
        $group = $searcher.FindOne()

        if ($group -and $group.Properties.member) {
            $members = $group.Properties.member | Sort-Object
            $count = $members.Count

            for ($i = 0; $i -lt $count; $i++) {
                $member = $members[$i]
                $isLast = ($i -eq ($count - 1))

                # Replace ternary with if/else
                $branchSymbol = "+--"
                if ($isLast) {
                    $nextPrefix = "$Prefix    "
                } else {
                    $nextPrefix = "$Prefix|   "
                }

                $objSearcher = New-Object DirectoryServices.DirectorySearcher
                $objSearcher.Filter = "(distinguishedName=$member)"
                $objSearcher.PropertiesToLoad.AddRange(@("objectClass", "cn"))
                $objResult = $objSearcher.FindOne()

                if ($objResult) {
                    $classes = $objResult.Properties["objectclass"]
                    $cn = $objResult.Properties["cn"][0]

                    if ($classes -contains "group") {
                        Write-Host "$Prefix$branchSymbol Group : $cn" -ForegroundColor Cyan
                        Resolve-NestedGroupMembers -GroupDN $member -Prefix $nextPrefix
                    }
                    else {
                        Write-Host "$Prefix$branchSymbol User  : $cn" -ForegroundColor Gray
                    }
                }
            }
        }
        else {
            Write-Host "$Prefix$Branch [!] No members found." -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "[!] Error resolving nested members: $_" -ForegroundColor Red
    }
}

function Show-AllComputers {
    Write-Host "`n[+] Enumerating all domain machines (with OS + IP + build info)..." -ForegroundColor Yellow

    # Retrieve computers via LDAP
    $computers = Invoke-LDAPSearch "(objectCategory=computer)"

    foreach ($computer in $computers) {
        $props = $computer.Properties
        $hostname  = $props.dnshostname[0]
        $os        = $props.operatingsystem[0]
        $osver     = $props.operatingsystemversion[0]
        $lastlogon = if ($props.lastlogon) { Convert-FileTime $props.lastlogon[0] } else { "N/A" }

        # Resolve IP address from hostname
        try {
            $ip = [System.Net.Dns]::GetHostAddresses($hostname) |
                  Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                  Select-Object -First 1
            if ($ip) {
                $ipOut = $ip.IPAddressToString
            } else {
                $ipOut = "Unresolved"
            }
        } catch {
            $ipOut = "Resolution Failed"
        }

        # Display the result
        Write-Host "Computer: $hostname" -ForegroundColor Green
        Write-Host "    OS: $os"
        Write-Host "    OS Version: $osver" -ForegroundColor Cyan
        Write-Host "    Last Logon: $lastlogon"
        Write-Host "    IP Address: $ipOut" -ForegroundColor Yellow
        Write-Host "---------------------------------------------"
    }
}

# Create Directory Entry and Searcher
$entry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)

# Function: General LDAP Query
function Invoke-LDAPSearch {
    param([string]$LDAPFilter)
    $searcher.Filter = $LDAPFilter
    return $searcher.FindAll()
}

# Function: Show all Domain Users FileTime Conversion to standard time
function Convert-FileTime {
    param ([long]$fileTime)
    if ($fileTime -eq 0 -or !$fileTime) {
        return "Never"
    } else {
        return [DateTime]::FromFileTime($fileTime).ToString("yyyy-MM-dd HH:mm:ss")
    }
}
# Function: Show all Domain Users w/o Admin =1 and memberof
function Show-AllUsers {
    Write-Host "`n[+] Enumerating all users in domain (with adminCount + group memberships)..." -ForegroundColor Yellow
    $results = Invoke-LDAPSearch "(samAccountType=805306368)"

    foreach ($user in $results) {
        $props     = $user.Properties
        $username  = $props.samaccountname
        $cn        = $props.cn
        $logon     = if ($props.lastlogon) { Convert-FileTime $props.lastlogon[0] } else { "N/A" }
        $pwdset    = if ($props.pwdlastset) { Convert-FileTime $props.pwdlastset[0] } else { "N/A" }
        $adminFlag = if ($props.admincount -eq 1) { $true } else { $false }
        $groups    = if ($props.memberof) { $props.memberof } else { @() }

        # Determine privilege level based on group memberships
        $groupTags = @()
        foreach ($group in $groups) {
            if ($group -match "CN=Domain Admins")       { $groupTags += "DA" }
            elseif ($group -match "CN=Enterprise Admins") { $groupTags += "EA" }
            elseif ($group -match "CN=Administrators")    { $groupTags += "LocalAdmin" }
            elseif ($group -match "CN=Remote Desktop Users") { $groupTags += "RDP" }
        }

        $tagSummary = ($groupTags + @(if ($adminFlag) { "adminCount=1" })) -join ", "

        # Highlight based on privilege
        if ($groupTags -contains "DA" -or $groupTags -contains "EA") {
            $color = "Red"
        } elseif ($adminFlag -or $groupTags -contains "LocalAdmin" -or $groupTags -contains "RDP") {
            $color = "Yellow"
        } else {
            $color = "Green"
        }

        # Output user info
        Write-Host "User: $username" -ForegroundColor $color
        Write-Host "    CN: $cn"
        Write-Host "    Last Logon: $logon"
        Write-Host "    Pwd Last Set: $pwdset"
        Write-Host "    Tags: $tagSummary" -ForegroundColor DarkCyan

        if ($groups.Count -gt 0) {
            Write-Host "    Groups:"
            foreach ($g in $groups) {
                Write-Host "      $g" -ForegroundColor Gray
            }
        } else {
            Write-Host "    Groups: None" -ForegroundColor DarkGray
        }

        Write-Host "---------------------------------------------"
    }
}

function Show-AllGroups {
    Write-Host "`n[+] Enumerating all domain groups (with nested memberships)..." -ForegroundColor Yellow
    $results = Invoke-LDAPSearch "(objectCategory=group)"
    foreach ($group in $results) {
        $cn = $group.Properties.cn[0]
        $dn = $group.Properties.distinguishedname[0]
        Write-Host "`n[+] Group : $cn" -ForegroundColor Magenta
        Resolve-NestedGroupMembers -GroupDN $dn -Prefix "   "
    }
}

# Function: Show Nested Group Membership
function Show-NestedGroup {
    param([string]$GroupCN)
    $query = "(&(objectCategory=group)(cn=$GroupCN))"
    $result = Invoke-LDAPSearch $query
    foreach ($g in $result) {
        Write-Host "`n[+] Group: $($g.Properties.cn)" -ForegroundColor Magenta
        $g.Properties.member | ForEach-Object {
            Write-Host "  Member: $_" -ForegroundColor Cyan
        }
    }
}

# Entry point: Execute Base Recon
Show-AllComputers
Show-AllUsers
Show-AllGroups

# Optional: to test specific nested groups
# Show-NestedGroup -GroupCN "Sales Department"
# Show-NestedGroup -GroupCN "Development Department"
