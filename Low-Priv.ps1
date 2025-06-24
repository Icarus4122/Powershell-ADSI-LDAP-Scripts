# Low-Privilege Active Directory Enumeration and Privesc Discovery Script
# Author: Icarus4122 💀
# Purpose: Comprehensive situational awareness and privesc detection from low-priv user context

Clear-Host
Write-Host "`n=================== WINDOWS LOW-PRIV ENUM SCRIPT ===================`n" -ForegroundColor Cyan

# -----------------------------
# Section 0: Sysinternals Setup
# -----------------------------
Write-Host "`n[+] Sysinternals Tools (assumed preloaded)" -ForegroundColor Cyan
$tools = @("accesschk.exe", "psloggedon.exe", "whoami.exe")
foreach ($tool in $tools) {
    if (Test-Path ".\$tool") {
        Write-Host "[+] Found: $tool" -ForegroundColor Green
    } else {
        Write-Host "[-] Missing: $tool" -ForegroundColor Yellow
    }
}

# AccessChk (Users on C:)
if (Test-Path ".\accesschk.exe") {    
    Write-Host "`n[+] AccessChk - User Privilege and Object Access Review" -ForegroundColor Cyan
    try {
        $username = $env:USERNAME
        $domain = $env:USERDOMAIN
        $fullIdentity = "$domain\$username"
    
        if (Test-Path ".\\accesschk.exe") {
            Write-Host "[>] Running: accesschk.exe -uwcqv $fullIdentity *" -ForegroundColor Yellow
            .\\accesschk.exe -uwcqv $fullIdentity * | ForEach-Object {
                if ($_ -match ".*(Write|Full|Modify).*") {
                    Write-Host $_ -ForegroundColor Red
                } elseif ($_ -match "Read|Query") {
                    Write-Host $_ -ForegroundColor Yellow
                } else {
                    Write-Host $_ -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "[x] accesschk.exe not found in current directory." -ForegroundColor Red
        }
    } catch {
        Write-Host "[x] Error running accesschk." -ForegroundColor Red
    }
}

# PsLoggedOn
if (Test-Path ".\psloggedon.exe") {
    Write-Host "`n[>] psloggedon - local and remote session visibility" -ForegroundColor Cyan
    try {
        .\psloggedon.exe 2>&1 | ForEach-Object {
            if ($_ -match "(Logon|Session|Administrator|Remote)") {
                Write-Host "[!] $_" -ForegroundColor Yellow
            } else {
                Write-Host $_ -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "[!] PsLoggedOn execution failed." -ForegroundColor Red
    }
}

# -----------------------------
# Section A1: Domain Info Summary (ADSI-based)
# -----------------------------
Write-Host "`n[+] Domain Information Summary" -ForegroundColor Cyan

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $forest = $domain.Forest
    $dc = $domain.PdcRoleOwner

    [PSCustomObject]@{
        DomainName        = $domain.Name
        NetBIOSName       = $domain.NetBiosName
        ForestName        = $forest.Name
        DomainMode        = $domain.DomainMode
        ForestMode        = $forest.ForestMode
        DomainControllers = ($domain.DomainControllers | ForEach-Object { $_.Name }) -join ", "
        PDC               = $dc.Name
    } | Format-List
}
catch {
    Write-Host "[x] Failed to retrieve domain info." -ForegroundColor Red
}

# -----------------------------
# Section A2: Domain Computers + IP Resolution (via ADSI)
# -----------------------------
Write-Host "`n[+] Domain Computers (via ADSI with IP Lookup)" -ForegroundColor Cyan

try {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=computer)"
    $searcher.PageSize = 1000
    $computers = $searcher.FindAll()

    foreach ($comp in $computers) {
        $name = $comp.Properties.name
        if ($name) {
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
                if ($resolved) {
                    foreach ($ip in $resolved) {
                        Write-Host "[+] $name => $($ip.IPAddressToString)" -ForegroundColor Green
                    }
                } else {
                    Write-Host "[!] $name => No IP resolved" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[!] $name => DNS lookup failed" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "[x] Failed to enumerate domain computers" -ForegroundColor Red
}


# -----------------------------
# Section X1: MRU File Tracking
# -----------------------------
Write-Host "`n[+] Recent Documents / Open File MRUs" -ForegroundColor Cyan
$MRUPaths = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
)
foreach ($path in $MRUPaths) {
    try {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[MRU] $($_.Name)" -ForegroundColor Yellow
        }
    } catch {}
}

# ----------------------------- 
# Section X2: Writable PATH and Common Directories 
# ----------------------------- 
Write-Host "`n[+] Writable Directories in `$Env:PATH and Common System Folders" -ForegroundColor Cyan

# Get current user token group SIDs
$currentSIDs = whoami /groups | ForEach-Object {
    if ($_ -match "S-1-.*") { ($_ -split '\s+')[0] }
}

# Directories to scan
$dirsToScan = $Env:PATH -split ';'
$dirsToScan += @("C:\", "C:\Windows", "C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)")
$dirsToScan = $dirsToScan | Where-Object { $_ -and ($_.Trim()).Length -gt 0 } | Sort-Object -Unique

foreach ($path in $dirsToScan) {
    $path = $path.Trim()
    Write-Host "[>] Checking: $path" -ForegroundColor DarkGray
    try {
        if (Test-Path $path) {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            if ($acl) {
                foreach ($access in $acl.Access) {
                    $sid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $rights = $access.FileSystemRights.ToString()
                    $type = $access.AccessControlType

                    $color = "Gray"
                    if ($type -eq "Allow" -and $currentSIDs -contains $sid -and $rights -match "Write|Modify|FullControl") {
                        $color = "Red"
                    }

                    Write-Host "[$type] $($access.IdentityReference) => $rights" -ForegroundColor $color
                }
            } else {
                Write-Host "[!] No ACL data retrieved." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[-] Path does not exist: $path" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[x] Error accessing: $path" -ForegroundColor Yellow
    }
}

# -----------------------------
# Section X3: Environment Variables
# -----------------------------
Write-Host "`n[+] Environment Variables" -ForegroundColor Cyan
Get-ChildItem Env: | Sort-Object Name | ForEach-Object {
    Write-Host "[$($_.Name)] = $($_.Value)" -ForegroundColor Gray
}

# -----------------------------
# Section X4: PowerShell Logging Detection
# -----------------------------
Write-Host "`n[+] PowerShell Transcription/Logging Policies" -ForegroundColor Cyan
try {
    $transcription = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
    if ($transcription) {
        $transcription.PSObject.Properties | ForEach-Object {
            Write-Host "[!] $($_.Name): $($_.Value)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "(No transcription policies found)" -ForegroundColor Gray
    }
} catch {}

# -----------------------------
# Section X5: GPP Credential Discovery
# -----------------------------
Write-Host "`n[+] Searching SYSVOL for GPP Credential XMLs" -ForegroundColor Cyan
try {
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $UNC = "\\$domain\SYSVOL\$domain\Policies"
    if (Test-Path $UNC) {
        Get-ChildItem -Path $UNC -Recurse -Include Groups.xml -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[!] Found GPP XML: $($_.FullName)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "SYSVOL path not accessible or not joined to domain." -ForegroundColor Gray
    }
} catch {}

# -----------------------------
# Section 1: Token Privileges
# -----------------------------
Write-Host "`n[+] Token Privileges" -ForegroundColor Cyan
whoami /priv | ForEach-Object {
    if ($_ -match "Se(Impersonate|AssignPrimaryToken|Debug|TakeOwnership|Backup|Restore)") {
        Write-Host $_ -ForegroundColor Red
    } elseif ($_ -match "Se") {
        Write-Host $_ -ForegroundColor Yellow
    } else {
        Write-Host $_ -ForegroundColor Gray
    }
}

# -----------------------------
# Section 2: AdminCount=1 Users
# -----------------------------
Write-Host "`n[+] Users with AdminCount=1" -ForegroundColor Cyan
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(adminCount=1))"
$searcher.PageSize = 1000
$searcher.FindAll() | ForEach-Object {
    $u = $_.Properties
    Write-Host "[!] $($u.samaccountname) ($($u.displayname)) - AdminCount: 1" -ForegroundColor Red
}

# -----------------------------
# Section 3: Group Enumeration
# -----------------------------
Write-Host "`n[+] Domain Groups (Highlighting Non-Default)" -ForegroundColor Cyan
$builtinGroups = @("Domain Users", "Domain Computers", "Administrators", "Users", "Guests", "Account Operators", "Backup Operators", "Print Operators")
$searcher.Filter = "(objectClass=group)"
$groups = $searcher.FindAll()
foreach ($g in $groups) {
    $name = $g.Properties.name[0]
    if ($builtinGroups -contains $name) {
        Write-Host "[G] $name" -ForegroundColor Gray
    } else {
        Write-Host "[!] Custom Group: $name" -ForegroundColor Yellow
    }
}

# -----------------------------
# Section 4: Nested Group Tree
# -----------------------------
Write-Host "`n[+] Nested Group → Group → Users Tree" -ForegroundColor Cyan
function Expand-GroupTree {
    param (
        [string]$GroupDN,
        [int]$Level = 0,
        [ref]$VisitedGroups
    )

    if ($VisitedGroups.Value -contains $GroupDN) { return }
    $VisitedGroups.Value += $GroupDN

    try {
        $group = [ADSI]("LDAP://$GroupDN")
        $indent = ('  ' * $Level)

        if ($Level -eq 0) {
            Write-Host "[+] Group: $($group.name)" -ForegroundColor Cyan
        } else {
            Write-Host "$indent└─ [+] Group: $($group.name)" -ForegroundColor Green
        }

        $nestedGroups = @()
        $userMembers = @()

        if ($group.member) {
            foreach ($memberDN in $group.member) {
                try {
                    $entry = [ADSI]("LDAP://$memberDN")
                    $type = $entry.objectClass | Select-Object -Last 1
                    if ($type -eq "group") {
                        $nestedGroups += $memberDN
                    }
                    elseif ($type -eq "user") {
                        $userMembers += $entry
                    }
                } catch { continue }
            }

            # Recurse first into nested groups
            foreach ($nested in $nestedGroups) {
                Expand-GroupTree -GroupDN $nested -Level ($Level + 1) -VisitedGroups $VisitedGroups
            }

            # Only show users if this is a leaf group
            if ($nestedGroups.Count -eq 0 -and $userMembers.Count -gt 0) {
                Write-Host "$indent   └─ [+] Users:" -ForegroundColor Cyan
                foreach ($user in $userMembers) {
                    $userIndent = ('  ' * ($Level + 2))
                    $sam = $user.samaccountname
                    $disp = $user.displayname
                    $cn = $user.cn
                    $admin = if ($user.admincount) { $user.admincount } else { 0 }
                    Write-Host "$userIndent└─ $sam (CN: $cn | DisplayName: $disp | AdminCount: $admin)" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "$indent   └─ (no members)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "Error processing group: $GroupDN" -ForegroundColor Red
    }
}
# === Entry Point ===
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=group)"
$searcher.PageSize = 1000
$groups = $searcher.FindAll()

foreach ($group in $groups) {
    $groupDN = $group.Properties.distinguishedname[0]
    $visited = New-Object System.Collections.Generic.List[string]
    Expand-GroupTree -GroupDN $groupDN -Level 0 -VisitedGroups ([ref]$visited)
}

# -----------------------------
# Section 5: Writable Directories
# -----------------------------
Write-Host "`n[+] Writable Paths in C:\\ and Program Files" -ForegroundColor Cyan
$paths = @("C:\", "C:\Program Files", "C:\Program Files (x86)")
foreach ($path in $paths) {
    try {
        Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $acl = Get-Acl $_.FullName
            $perm = $acl.Access | Where-Object {
                $_.FileSystemRights -match "Write" -and $_.IdentityReference -match "Everyone|Users"
            }
            if ($perm) {
                Write-Host "[!] Writable: $($_.FullName)" -ForegroundColor Red
            }
        }
    } catch {}
}

# -----------------------------
# Section 6: UAC & Install Policy
# -----------------------------
Write-Host "`n[+] UAC and Install Policies" -ForegroundColor Cyan
try {
    $uac = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    $ae = Get-ItemProperty HKCU:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    Write-Host "ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)" -ForegroundColor (if ($uac.ConsentPromptBehaviorAdmin -eq 0) {"Red"} else {"Gray"})
    Write-Host "EnableLUA: $($uac.EnableLUA)" -ForegroundColor (if ($uac.EnableLUA -eq 0) {"Red"} else {"Gray"})
    Write-Host "AlwaysInstallElevated: $($ae.AlwaysInstallElevated)" -ForegroundColor (if ($ae.AlwaysInstallElevated -eq 1) {"Red"} else {"Gray"})
} catch { Write-Host "[!] Could not read registry." -ForegroundColor Yellow }

# -----------------------------
# Section 7: Local Users
# -----------------------------
Write-Host "`n[+] Local Users via WinNT Provider" -ForegroundColor Cyan
try {
    ([ADSI]"WinNT://$env:COMPUTERNAME").Children | Where-Object {$_.SchemaClassName -eq "User"} | ForEach-Object {
        Write-Host "[User] $($_.Name)" -ForegroundColor Gray
    }
} catch { Write-Warning "Local user enumeration failed." }

# -----------------------------
# Section 8: SPNs
# -----------------------------
Write-Host "`n[+] Service Principal Names (SPNs) for Host" -ForegroundColor Cyan
try {
    $computer = $env:COMPUTERNAME + "$"
    $compSearch = ([adsisearcher]"(&(objectClass=computer)(sAMAccountName=$computer))").FindOne()
    $spns = $compSearch.Properties["serviceprincipalname"]
    if ($spns) {
        foreach ($spn in $spns) { Write-Host $spn -ForegroundColor Yellow }
    } else {
        Write-Host "(none)" -ForegroundColor Gray
    }
} catch { Write-Warning "SPN enumeration failed." }

# -----------------------------
# Section 9: Domain Shares
# -----------------------------
Write-Host "`n[+] Domain Shares (via Net View)" -ForegroundColor Cyan
try {
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    net view /domain:$domain 2>$null | findstr "\\" | ForEach-Object {
        Write-Host $_ -ForegroundColor Gray
    }
} catch {
    Write-Host "(Could not run net view or insufficient access)" -ForegroundColor Yellow
}

Write-Host "`n========================= COMPLETE =========================`n" -ForegroundColor Cyan
