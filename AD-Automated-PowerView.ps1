#Requires -RunAsAdministrator

# ==========================================
# Active Directory OS Enumeration + Access Mapping
# By: Red Team / Low-Priv Ops
# ==========================================

Import-Module .\PowerView.ps1 -ErrorAction SilentlyContinue

function Convert-FileTime {
    param ([long]$fileTime)
    if ($fileTime -eq 0 -or !$fileTime) {
        return "Never"
    } else {
        return [DateTime]::FromFileTime($fileTime).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Get-ADOperatingSystems {
    Write-Host "[+] Enumerating Operating Systems and Hostnames..." -ForegroundColor Yellow
    Get-NetComputer | Select-Object name, dnshostname, operatingsystem, operatingsystemversion | Format-Table -AutoSize
}

function Test-LocalAdminAccess {
    Write-Host "[+] Scanning for Local Admin Access..." -ForegroundColor Yellow
    Find-LocalAdminAccess | ForEach-Object {
        Write-Host "[*] Admin Access On: $_" -ForegroundColor Green
    }
}

function Get-LoggedOnUsers {
    param([string[]]$ComputerList)
    foreach ($comp in $ComputerList) {
        Write-Host "[?] Checking sessions on $comp..." -ForegroundColor Cyan
        try {
            Get-NetSession -ComputerName $comp -ErrorAction Stop | ForEach-Object {
                Write-Host "    [>] User: $($_.UserName) from $($_.CName) on $comp" -ForegroundColor Green
            }
        } catch {
            Write-Host "    [!] Access Denied or No Data" -ForegroundColor DarkGray
        }
    }
}

function Invoke-PsLoggedOnScan {
    param([string[]]$ComputerList)
    Write-Host "[+] Running PsLoggedOn against targets..." -ForegroundColor Yellow
    foreach ($host in $ComputerList) {
        Write-Host "[*] PsLoggedOn: $host" -ForegroundColor Cyan
        try {
            & .\PsLoggedon.exe "\\$host" | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        } catch {
            Write-Host "    [!] Failed to execute PsLoggedOn on $host" -ForegroundColor Red
        }
    }
}

function Get-ActiveSPNs {
    Write-Host "[+] Enumerating Service Principal Names (SPNs)..." -ForegroundColor Yellow
    Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname | Format-Table -AutoSize
}

function Get-InterestingObjectACLs {
    param([string]$TargetObject)
    Write-Host "[+] Enumerating ACLs for object: $TargetObject" -ForegroundColor Yellow
    Get-ObjectAcl -Identity $TargetObject | Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" } | ForEach-Object {
        $sid = $_.SecurityIdentifier
        $resolved = Convert-SidToName $sid
        Write-Host "[*] $resolved has GenericAll access on $TargetObject" -ForegroundColor Red
    }
}

function Get-DomainShares {
    Write-Host "[+] Enumerating Domain Shares..." -ForegroundColor Yellow
    Find-DomainShare | Sort-Object ComputerName | Format-Table -AutoSize
}

function Find-GPPCPasswords {
    Write-Host "[+] Searching for Group Policy Preference cpasswords..." -ForegroundColor Yellow
    $gppFiles = Get-ChildItem -Recurse -Path "\\dc1.corp.com\sysvol" -Include *.xml -ErrorAction SilentlyContinue
    foreach ($file in $gppFiles) {
        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match 'cpassword="([^"]+)"') {
                $encPwd = $matches[1]
                Write-Host "[*] Found Encrypted Password in: $($file.FullName)" -ForegroundColor Cyan
                }
            }
        }
    }
}

function Show-Menu {
    Write-Host "\n========== AD Recon Toolkit ==========" -ForegroundColor Cyan
    Write-Host "[1] Get AD Operating Systems"
    Write-Host "[2] Test Local Admin Access"
    Write-Host "[3] Get Logged-On Users"
    Write-Host "[4] Run PsLoggedOn Scan"
    Write-Host "[5] Enumerate SPNs"
    Write-Host "[6] Check ACLs on Target Object"
    Write-Host "[7] Enumerate Domain Shares"
    Write-Host "[8] Detect GPP cpasswords"
    Write-Host "[9] Exit"
    Write-Host "======================================="
}

# CLI Loop
$exit = $false
while (-not $exit) {
    Show-Menu
    $choice = Read-Host "Select an option"
    switch ($choice) {
        '1' { Get-ADOperatingSystems }
        '2' { Test-LocalAdminAccess }
        '3' {
            $knownHosts = Get-NetComputer | Select-Object -ExpandProperty name
            Get-LoggedOnUsers -ComputerList $knownHosts
        }
        '4' {
            $knownHosts = Get-NetComputer | Select-Object -ExpandProperty name
            Invoke-PsLoggedOnScan -ComputerList $knownHosts
        }
        '5' { Get-ActiveSPNs }
        '6' {
            $target = Read-Host "Enter object name (e.g., 'Management Department')"
            Get-InterestingObjectACLs -TargetObject $target
        }
        '7' { Get-DomainShares }
        '8' { Find-GPPCPasswords }
        '9' { $exit = $true }
        default { Write-Host "[!] Invalid option." -ForegroundColor Red }
    }
}
