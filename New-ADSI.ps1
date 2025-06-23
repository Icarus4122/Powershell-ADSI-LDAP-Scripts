#Globals 
 $global:DomainDN = ([adsisearcher]'(objectClass=Domain)').FindAll().Properties.distinguishedname 
 $global:COMPNAME = Write-Output ([System.DirectoryServices.ActiveDirectory.Domain])::GetCurrentDomain().DomainControllers.Name) 
 $global:ForestInfo = '' 
 #Prevent truncation of results 
 $FormatEnumerationLimit = -1 
 ([adsiSearcher]'(PageSize=5000)').PageSize 
 $Searcher = [AdsiSearcher]"" 
 $Searcher.PageSize = $PageSize 
 $Searcher.PropertyNamesOnly = $false
 function Show-GroupMenu { 
  
     param ([string]$Title = 'AD-User-Menu') 
      
     Clear-Host        
     Write-Host "================ $Title ================" 
     Write-Host " Press '1' for Active Directory Domain Local Groups."         
     Write-Host " Press '2' for Active Directory Domain Local Security Groups." 
     Write-Host " Press '3' for Active Directory Domain Global Distribution Groups."         
     Write-Host " Press '4' for Active Directory Nested Domain Groups."         
     Write-Host " Press '5' for Active Directory Trusted Domains."        
     Write-Host " Press 'R' to Return to Previous Menu."         
     Write-Host " Press 'Q' to Exit." 
     } 
 function Show-ComputerMenu { 
  
     param ([string]$Title = 'AD-Computer-Menu') 
      
     Clear-Host 
     Write-Host "================ $Title ================" 
     Write-Host " Press '1' for Active Directory Computers." 
     Write-Host " Press '2' for Active Directory Computers with unconstrained delegation."         
     Write-Host " Press '3' for Active Directory Listed as primary group of domain controllers."         
     Write-Host " Press '4' for Active Directory Server listings." 
     Write-Host " Press '5' for Active Directory Computers with LAPS passwords." 
     Write-Host " Press 'R' to Return to Previous Menu." 
     Write-Host " Press 'Q' to Exit." 
     } 
 function Show-UserMenu { 
  
     param ([string]$Title = 'AD-User-Menu') 
      
     Clear-Host 
     Write-Host "================ $Title ================" 
     Write-Host " Press '1' for Active Directory Domain Admins." 
     Write-Host " Press '2' for Active Directory Enterprise Admins." 
     Write-Host " Press '3' for Active Directory AdminSHHolders." 
     Write-Host " Press '4' for Active Directory Accounts that do not require passwords." 
     Write-Host " Press '5' for Active Directory Accounts with no expiration date." 
     Write-Host " Press 'R' to Return to Previous Menu." 
     Write-Host " Press 'Q' to Exit." 
     } 
 function Show-Menu { 
  
     param ([string]$Title = 'AD-PARSE-MENU') 
      
     Clear-Host 
     Write-Host "================ $Title ================" 
     Write-Host " Press '1' for Active Directory Domains." 
     Write-Host " Press '2' for Active Directory Computer." 
     Write-Host " Press '3' for Active Directory Users." 
     Write-Host " Press 'Q' to quit." 
     }  
 function DNS-Name{ 
      
     $DomainGrab = Write-Output ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()) 
     $Domain = Write-Output ("LDAP://$DomainGrab")  
     $NetBIOS = Write-Output ([adsisearcher]'(&(objectcategory=Crossref)(dnsRoot=$Domain)(netBIOSName=*))').FindAll() 
     Write-Host "" 
     Write-Host "" 
  
     Write-Host -ForegroundColor Cyan -BackgroundColor Black "Current domain details:" 
     Write-Host "" 
     Write-Host -ForegroundColor Red -BackgroundColor White $Domain 
     Write-Host "" 
     Write-Host "DNS domain name" 
     Write-Host -ForegroundColor Green $NetBIOS 
     Write-Host "" 
 }     
 function Functional-Level { 
  
     $dfl = Write-Output ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.OSVersion) 
     Write-Host "Domain Functional Level" 
     switch ($dfl) 
         { 
         'Windows Server 2000' { Write-Host -ForegroundColor green "Windows 2000 native" } 
         'Windows Ser=ver 2003' { Write-Host -ForegroundColor green "Windows Server 2003" } 
         'Windows Server 2008' { Write-Host -ForegroundColor green "Windows Server 2008" } 
         'Windows Server 2008R2*' { Write-Host -ForegroundColor green "Windows Server 2008 R2" } 
         'Windows Server 2012' { Write-Host -ForegroundColor green "Windows Server 2012" } 
         'Windows Server 2012R2*' { Write-Host -ForegroundColor green "Windows Server 2012 R2" } 
         'Windows Server 2016*' { Write-Host -ForegroundColor Green "Windows Server 2016" } 
         'Windows Server 2019*' { Write-Host -ForegroundColor Green "Windows Server 2019" } 
         default { Write-Host -ForegroundColor red "Other Domain Functional Level:"$dfl } 
         } 
     Write-Host "" 
     } 
 function Sysvol-Replication{ 
      
     Write-Host "SYSVOL replication method:" 
     $FRSsysvol = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))" 
     $DFSRsysvol = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))" 
     $frs = Write-Output ([adsisearcher]$FRSsysvol).Findall().Properties 
     $dfsr = Write-Output (([adsisearcher]$DFSRsysvol).FindAll().Properties) 
  
     if ( $frs -ne $null ) { Write-Host -ForegroundColor Red "FRS" } 
         elseif ( $dfsr -ne $null ) { Write-Host -ForegroundColor Green "DFS-R" } 
                 else { Write-Host -ForegroundColor Red "unknown" } 
     Write-Host "" 
     }  
 function Domain-Controllers { 
  
     $RODCList = Write-Output ([adsisearcher]'(primaryGroupID=521)').FindAll() 
     Write-Host "List of Domain Controllers" 
     Write-Host -ForegroundColor Green (([adsisearcher]'(primaryGroupID=516)').FindAll().Path) 
     Write-Host "" 
     Write-Host "List of Read-Only Domain Controllers: " 
     if ( $RODCList.Count -ne 0){  
             $RODCList | % {Write-Host -ForegroundColor Green } 
         } 
     else{ 
         Write-Host -ForegroundColor Green "Not Found" 
         } 
     Write-Host "" 
     } 
 function Global-Catalog { 
      
     Write-Host "Global Catalog server in the domain" 
     Write-Host -ForegroundColor green (dsquery server -isgc) 
     Write-Host "" 
 } 
 function Domain-Objects { 
     $cmp_location = Write-Output ([adsisearcher]'(objectClass=Computer)').Findone().Properties.objectcategory 
     Write-Host "Default domain Computer objects location" 
     if ($cmp_location.Contains("CN=Computer")){ 
         Write-Host -ForegroundColor green $cmp_location -NoNewline 
         Write-Host -ForegroundColor Yellow " (not redirected)" 
         } 
     else{ 
         Write-Host -ForegroundColor Green $cmp_location -NoNewline 
         Write-Host -ForegroundColor Red " (redirected)" 
         } 
     Write-Host "" 
  
     $usr_location = Write-Output([adsisearcher]'(objectCategory=User)').Findone().Properties.objectcategory 
     Write-host "Default domain user objects location"    
     if ($usr_location.Contains("CN=Users")){ 
         Write-Host -ForegroundColor green $usr_location -NoNewLine 
         Write-Host -ForegroundColor yellow " (not redirected)" 
         }  
     else{ 
         Write-Host -ForegroundColor green $usr_location -NoNewLine 
         Write-Host -ForegroundColor red " (redirected)" 
         } 
     Write-Host "" 
  
 }  
 function Domain-Statistics{ 
     Write-Host "Domain objects Statistics" 
     #Check if orphaned objects exist 
     Write-Host "" 
     $orphaned =Write-Output ([adsisearcher]'(memberOf:1.2.840.113556.1.4.1941:=cn=LostAndFound,$domainDN)').FindAll() 
     if($orphaned.Count -ne 0){ 
         Write-Host -ForegroundColor Red "$($orphaned.Count) orphaned objects have been found!" 
         } 
     else{ 
         Write-Host -ForegroundColor Green "No orphaned objects have been found" 
         } 
     #Check for lingering objects or conflic replication objects exist 
     $lingConfRepl = Write-Output ([adsisearcher]'(memberOf:1.2.840.113556.1.4.1941:=cn=*\0ACNF:*)').FindAll().Count 
  
     if ($lingConfRepl.Count -ne 0){ 
             Write-Host -ForegroundColor Red "$($lingConfRepl.Count) lingering or replication conflict objects have been found!" 
         } 
     else{ 
             Write-Host -ForegroundColor Green "No lingering or replication conflict objects have been found" 
         } 
     Write-Host "" 
      
     $ou_objectsNo = Write-Output([adsisearcher]'(objectClass=organizationalUnit)').FindAll().Count 
     Write-Host "Total number of Organizational Unit objects : " -NoNewline 
     Write-Host -ForegroundColor Green $ou_objectsNo 
     Write-Host "" 
  
     $cmp_objects =  Write-Output ([adsisearcher]'(objectClass=Computer)').findall().Properties 
     $cmp_objectsNo= Write-Output ([adsisearcher]'(objectClass=Computer)').findall().Count 
     Write-Host "Total number of computer objects : " -NoNewline 
     Write-Host -ForegroundColor Green $cmp_objectsNo 
     Write-Host "" 
      
  
     $cmp_os_2000 = 0 
     $cmp_os_xp = 0 
     $cmp_os_7 = 0 
     $cmp_os_8 = 0 
     $cmp_os_81 = 0 
     $cmp_os_10 = 0 
  
     $cmp_srvos_2000 = 0 
     $cmp_srvos_2003 = 0 
     $cmp_srvos_2008 = 0 
     $cmp_srvos_2008r2 = 0 
     $cmp_srvos_2012 = 0 
     $cmp_srvos_2012r2 = 0 
     $cmp_srvos_2016 = 0 
     $cmp_srvos_2019 = 0 
  
     $cmp_objects_OS = Write-Output ([adsisearcher]'(objectClass=Computer)').findall().Properties.operatingsystem 
  
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows 2000 Professional*") { $cmp_os_2000 = $cmp_os_2000 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows XP*") { $cmp_os_xp = $cmp_os_xp + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows 7*") { $cmp_os_7 = $cmp_os_7 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows 8 *") { $cmp_os_8 = $cmp_os_8 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows 8.1*") { $cmp_os_81 = $cmp_os_81 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects.operatingsystem -like "Windows 10") { $cmp_os_10 = $cmp_os_10 + 1 } } 
  
  
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows 2000 Server*") { $cmp_srvos_2000 = $cmp_srvos_2000 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2003*") { $cmp_srvos_2003 = $cmp_srvos_2003 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2008*") { $cmp_srvos_2008 = $cmp_srvos_2008 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2008 R2*") { $cmp_srvos_2008r2 = $cmp_srvos_2008r2 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2012 *") { $cmp_srvos_2012 = $cmp_srvos_2012 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2012 R2*") { $cmp_srvos_2012r2 = $cmp_srvos_2012r2 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2016*") { $cmp_srvos_2016 = $cmp_srvos_2016 + 1 } } 
     $cmp_objects_OS | %{ if ($cmp_objects_OS -like "Windows Server 2012 R2*") { $cmp_srvos_2019 = $cmp_srvos_2019 + 1 } } 
      
     Write-Host "  Client systems" 
     Write-host -ForegroundColor yellow "  Windows 2000                   : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_2000 
     Write-host -ForegroundColor yellow "  Windows XP                     : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_xp 
     Write-host -ForegroundColor yellow "  Windows 7                      : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_7 
     Write-host -ForegroundColor yellow "  Windows 8                      : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_8 
     Write-host -ForegroundColor yellow "  Windows 8.1                    : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_81 
     Write-host -ForegroundColor yellow "  Windows 10                     : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_os_10     
     Write-Host "" 
     Write-Host "" 
     Write-Host "  Server systems" 
     Write-host -ForegroundColor yellow "  Windows 2000 Server            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2000 
     Write-host -ForegroundColor yellow "  Windows Server 2003            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2003 
     Write-host -ForegroundColor yellow "  Windows Server 2008            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2008 
     Write-host -ForegroundColor yellow "  Windows Server 2008R2          : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2008r2 
     Write-host -ForegroundColor yellow "  Windows Server 2012            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2012 
     Write-host -ForegroundColor yellow "  Windows Server 2012R2          : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2012r2 
     Write-host -ForegroundColor yellow "  Windows Server 2016            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2016 
     Write-host -ForegroundColor yellow "  Windows Server 2019            : " -NoNewLine 
     Write-Host -ForegroundColor green $cmp_srvos_2019 
     Write-Host "" 
      
 } 
 function User-Enum { 
      
     $usr_objects = ([adsisearcher]'(objectClass=User)').FindAll().properties 
     $usr_objectsNo = $usr_objects.Count 
     $usr_active_objectsNo = Write-Output ((([adsisearcher]'(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))').FindAll()).Count) 
     $usr_inactive_objectsNo = Write-Output ((([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))').FindAll()).Count) 
     $usr_locked_objectsNo = Write-Output (([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16))').FindAll()).Count 
     $usr_pwdnotexp_objectsNo = Write-Output ((([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))').FindAll()).Count) 
     $usr_objects_pwdnotexp_objectsNo = Write-Output ((([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))').FindAll().Count)) 
     $usr_pwdnotreq_objectsNo = ((([adsisearcher]'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))').FindAll().Count)) 
     Write-Host "" 
     Write-Host "Total number of user objects  : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_objectsNo 
     Write-host -ForegroundColor yellow "  Active                      : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_active_objectsNo 
     Write-host -ForegroundColor yellow "  Inactive                    : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_inactive_objectsNo 
     Write-host -ForegroundColor yellow "  Locked out                  : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_locked_objectsNo 
     Write-host -ForegroundColor yellow "  Password not required       : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_pwdnotreq_objectsNo 
     Write-host -ForegroundColor yellow "  Password never expires      : " -NoNewLine 
     Write-Host -ForegroundColor green $usr_pwdnotexp_objectsNo 
  
     } 
 function Group-Enum { 
      
     $grp_objects = Write-Output([adsisearcher]'(objectClass=Group)').FindAll().Properties 
     $grp_objectsNo = Write-Output([adsisearcher]'(objectClass=Group)').FindAll().Count 
     $grp_objects_localNo = Write-Output(([adsisearcher]'(objectClass=Group)').FindAll().Properties | where grouptype -eq "-2147483644").count 
     $grp_objects_universalNo = Write-Output(([adsisearcher]'(objectClass=Group)').FindAll().Properties | where grouptype -eq "-2147483640").count 
     $grp_objects_globalNo = Write-Output(([adsisearcher]'(objectClass=Group)').FindAll().Properties | where grouptype -eq "-2147483646").count 
     Write-Host "Total number of group objects : " -NoNewLine 
     Write-Host -ForegroundColor green $grp_objectsNo 
     Write-Host -ForegroundColor yellow "  Global                      : " -NoNewLine 
     Write-Host -ForegroundColor green $grp_objects_globalNo 
     Write-Host -ForegroundColor yellow "  Universal                   : " -NoNewLine 
     Write-Host -ForegroundColor green $grp_objects_universalNo 
     Write-Host -ForegroundColor yellow "  Domain Local                : " -NoNewLine 
     Write-Host -ForegroundColor green $grp_objects_localNo 
     Write-Host -ForegroundColor Red  "  Uncategorized Other         : " -NoNewline 
         if ($grp_objectsNo -gt ($grp_objects_localNo + $grp_objects_universalNo + $grp_objects_globalNo)) 
             { 
             Write-Host -ForegroundColor Red ($grp_objectsNo - $grp_objects_localNo - $grp_objects_universalNo - $grp_objects_globalNo)  
             } 
     Write-Host "" 
     } 
 function Admin-Accounts($DomainName) { 
  
     $global:COMPNAME = Write-Output ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.Name) 
     $builtinAdmin = (Get-WmiObject win32_UserAccount -Recurse -ComputerName $global:COMPNAME | Where {$_.SID -match '-500$'}) | Select Name, PasswordExpires, Disabled, Lockout 
     #Gets Total number of Domain Administrator group members 
     $domainAdminsNo = (Get-WmiObject win32_group -Recurse -ComputerName $global:COMPNAME | Where {$_.SID -match '-512$'}).GetRelated("win32_useraccount").count 
     Write-Host "" 
     Write-Host -ForegroundColor yellow -BackgroundColor black "Built-in Domain Administrator account details:"         
     Write-Host ""        
     Write-Host "Account name: " -NoNewline   
     Write-Host -ForegroundColor green $builtinAdmin.Name  
     Write-Host "Account status: " -NoNewline 
     if ( $builtinAdmin.Disabled){ 
         Write-Host -ForegroundColor Green "Disabled" 
         } 
         else{ 
             Write-Host -ForegroundColor red "Enabled" 
             }       
     Write-Host "Password Never Expires: " -NoNewline 
     if ( $builtinAdmin.PasswordNeverExpires ){ 
             Write-Host -ForegroundColor green "no" 
         } 
         else{ 
                 Write-Host -ForegroundColor red "yes" 
             } 
     Write-Host "" 
     Write-Host "Promoted to domain account" 
     if ($builtinAdmins.whenCreated -eq $nul){ 
         Write-Host -ForegroundColor Green "Account Never a Domain Controller" 
         } 
         else{ 
                 Write-Host -ForegroundColor green $builtinAdmin.whenCreated 
             }       
     Write-Host "" 
     Write-Host "Last password change" 
     Write-Host -ForegroundColor green $builtinAdmin.PasswordLastSet 
         if ($builtinAdmins.PasswordLastSet -eq $nul){ 
             Write-Host -ForegroundColor Red "Account Has Never Been Accessed" 
             } 
     Write-Host "" 
     Write-Host "Last logon date" 
     if ($builtinAdmins.PasswordLastSet -eq $nul){ 
         Write-Host -ForegroundColor Red "Password Has Never Been Used" 
         } 
         else{ 
             Write-Host -ForegroundColor green $builtinAdmin.LastLogonDate 
             } 
     Write-Host "" 
     Write-Host ""     
 } 
 function FSMO-Info{ 
     $Netdom = Netdom.exe query fsmo 
     $FSMOPDC = Write-Output $DomainGrab.DomainControllers 
     $FSMORID = Write-Output $DomainGrab.RidRoleOwner 
     $FSMOInfrastructure = Write-Output $DomainGrab.InfrastructureRoleOwner 
     Write-Host -ForegroundColor yellow -BackgroundColor black "FSMO roles details:" 
     Write-Host "" 
     Write-Host "PDC Emulator master" 
     Write-Host -ForegroundColor green $FSMOPDC 
     Write-Host "" 
     Write-Host "RID master" 
     Write-Host -ForegroundColor green $FSMORID 
     Write-Host "" 
     Write-Host "Infrastructure master" 
     Write-Host -ForegroundColor green $FSMOInfrastructure 
     Write-Host "" 
 } 
 function Default-Gpo{ 
     $gpoDefaultDomain = Write-Output ([adsisearcher]'(&(objectClass=groupPolicyContainer)(cn={31B2F340-016D-11D2-945F-00C04FB984F9}))').FindAll() 
     $gpoDefaultDomainController = Write-Output ([adsisearcher]'(&(objectClass=groupPolicyContainer)(cn={6AC1786C-016F-11D2-945F-00C04fB984F9}))').FindAll() 
  
     if ($gpoDefaultDomain -ne $nul) { 
         Write-Host "Default Domain policy             : " -NoNewLine 
         Write-Host -ForegroundColor Green "exists"        
         } 
         else{ 
             Write-Host -ForegroundColor Red "does not exist"    
             } 
  
     if ($gpoDefaultDomainController -ne $nul){ 
             Write-Host "Default Domain Controllers policy : " -NoNewLine 
             Write-Host -ForegroundColor Green "exists"        
         } 
         else{     
                 Write-Host -ForegroundColor Red "does not exist"        
             } 
     Write-Host "" 
  
 #Default Domain Password Policy details 
     $pwdGPO = (([xml](Get-GPOReport -Name "Default Domain Policy" -ReportType xml)).GPO.Computer.ExtensionData.Extension.Account) | Select-Object -Property Name, SettingNumber 
     $FGPPNo = "feature not supported"        
     Write-Host -ForegroundColor yellow -BackgroundColor black "Default Domain Password Policy details:" 
     Write-Host ""    
     Write-Host "Minimum password age: " -NoNewLine 
     Write-Host -ForegroundColor green ($pwdGPO | Where Name -EQ MinimumPasswordAge |Select-Object -ExpandProperty SettingNumber) "day(s)" 
     Write-Host "Maximum password age: " -NoNewLine 
     Write-Host -ForegroundColor green ($pwdGPO | Where Name -EQ MaximumPasswordAge |Select-Object -ExpandProperty SettingNumber) "day(s)" 
     Write-Host "Minimum password length: " -NoNewline 
     Write-Host -ForegroundColor green ($pwdGPO | Where Name -EQ MinimumPasswordLength |Select-Object -ExpandProperty SettingNumber) "characters(s)" 
     Write-Host "Password history count: " -NoNewLine 
     Write-Host -ForegroundColor green (($pwdGPO | Where Name -EQ PasswordHistorySize |Select-Object -ExpandProperty SettingNumber)) "unique password(s)" 
      
     Write-Host "Password must meet complexity: " -NoNewLine 
     if (($pwdGPO | Where Name -EQ PasswordComplexity |Select-Object -ExpandProperty SettingNumber)){ 
         Write-Host -ForegroundColor Green "Yes" 
         } 
         else{ 
             Write-Host -ForegroundColor Red "no" 
             } 
      
     Write-Host "Password uses reversible encryption: " -NoNewLine     
     if (($pwdGPO | Where Name -EQ ReversibleEncryptionEnabled |Select-Object -ExpandProperty SettingNumber)){ 
         Write-Host -ForegroundColor red "yes"        
         }     
         else{  
             Write-Host -ForegroundColor green "no" 
             } 
     Write-Host "" 
          
     Write-Host "Account lockout treshold: " -NoNewLine   
     if (($pwdGPO | Where Name -EQ LockoutBadCount |Select-Object -ExpandProperty SettingNumber) -Eq 0){    
         Write-Host -ForegroundColor red "Account never locks out" 
         } 
         else{     
             Write-Host -ForegroundColor Green "Account Locks out" 
             } 
  
     Write-Host "" 
     Write-Host "Fine-Grained Password Policies: " -NoNewline 
     Write-Host -ForegroundColor Green $FGPPNo 
  
     } 
 function Display-Collection{ 
     if ( $args.Length -gt 0){ 
     $global:ForestInfo=([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()) 
     $args[0] 
     } 
     else{ 
         $global:ForestInfo= ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()) 
         } 
     $Forest = $global:ForestInfo.RootDomain 
     # Clear-Host 
     Write-Host -ForegroundColor White -BackgroundColor black "Active Directory ADSI report V1.0 by Icarus (rebuilt from ADREPORT using .Net Framework/native tools by.Sieik)" 
     Write-host -foregroundColor Green -BackgroundColor -white "(Reformated by Austin Hawk)" 
     Write-host "" 
     Write-host "" 
     Write-Host -ForegroundColor Yellow -BackgroundColor Black "Forest Details:" 
     Write-Host "" 
     Write-Host "Forest Name" 
     Write-Host -ForegroundColor Green $Forest 
     Write-Host ""         
 } 
 function Schema-Info{ 
     $DEFINESCHEMA = "LDAP://CN=Schema,CN=Configuration" + ",$global:domainDN" 
     $SchemaVersion = ([adsi]$DEFINESCHEMA).Properties.objectVersion 
     Write-Host "Active Directory Schema Version" 
     Switch ($SchemaVersion) { 
         13 { Write-Host -ForegroundColor green $SchemaVersion "- Windows 2000 Server" } 
         30 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2003"  } 
         31 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2003 R2" } 
         44 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2008" } 
         47 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2008 R2" } 
         51 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 8 Developers Preview" } 
         52 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 8 Beta" } 
         56 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2012" } 
         69 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2012 R2" } 
         72 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server Technical Preview" } 
         87 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2016" } 
         88 { Write-Host -ForegroundColor green $SchemaVersion "- Windows Server 2019 or 2022" } 
         default { Write-Host -ForegroundColor red "unknown - "$SchemaVersion} 
         } 
     Write-Host "" 
     } 
 function Exchange-Info{ 
     $EXCHANGEDEFINE = "LDAP://CN=ms-Exch-Schema-Version-Pt" + ",$global:domainDN" 
     $ExchangeSchemaVersion = Write-Output([adsi]$EXCHANGEDEFINE).rangeUpper 
     if ($ExchangeSchemaVersion -ne $nul){ 
         switch ($ExchangeSchemaVersion){ 
                 15137 { Write-Host -ForegroundColor green "Exchange Server 2013" } 
                 15254 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 1" } 
                 15281 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 2" } 
                 15283 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 3" } 
                 15292 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 4 - Service Pack 1" } 
                 15300 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 5" } 
                 15303 { Write-Host -ForegroundColor green "Exchange Server 2013 Cumulative Update 6" } 
                 15312 { Write-Host -ForegroundColor green "Exchange Server 2013 w/ Cumulative Update 7-23" } 
                 15317 { Write-Host -ForegroundColor green "Exchange Server 2016" } 
                 15323 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 1" } 
                 15325 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 2" } 
                 15326 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 3" } 
                 15330 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 6" } 
                 15332 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 7-20" } 
                 15334 { Write-Host -ForegroundColor green "Exchange Server 2016 w/ Cumulative Update 21-22" } 
                 17000 { Write-Host -ForegroundColor green "Exchange Server 2019" } 
                 17001 { Write-Host -ForegroundColor green "Exchange Server 2019 w/ Cumulative Update 2-7" } 
                 17002 { Write-Host -ForegroundColor green "Exchange Server 2019 w/ Cumulative Update 8, or 9" } 
                 17003 { Write-Host -ForegroundColor green "Exchange Server 2019 w/ Cumulative Update 10, or 11" } 
                 default {  Write-Host -ForegroundColor red "unknown - "$ExchangeSchemaVersion.rangeUpper } 
             } 
         $ExchOrganization = Write-Output([adsi]"LDAP://CN=Microsoft Exchange,CN=Services,$configPartition").templateRoot 
         $ExchOrgName = Write-Output([adsi]$ExchOrganization).Name 
         Write-Host "" 
         Write-Host "Microsoft Exchange Organization name" 
         Write-Host -ForegroundColor Green $ExchOrgName 
     } 
     else{ 
         Write-Host -ForegroundColor Green "(not present)" 
         } 
 Write-Host "" 
 } 
 function Lync-Info{ 
     Write-Host "Microsoft Lync Server Version" 
     $LyncSchemaVersion = Write-Output(([adsisearcher]"(&(objectClass=attributeSchema)(name=ms-RTC-SIP-SchemaVersion))").Findall().Properties.rangeUpper) 
     if ($LyncSchemaVersion -ne $nul){ 
         switch ($LyncSchemaVersion) {    
                 1006 { Write-Host -ForegroundColor green "Live Communications Server 2005" } 
                 1007 { Write-Host -ForegroundColor green "Office Communications Server 2007 Release 1" } 
                 1008 { Write-Host -ForegroundColor green "Office Communications Server 2007 Release 2" } 
                 1100 { Write-Host -ForegroundColor green "Lync Server 2010" } 
                 1150 { Write-Host -ForegroundColor green "Lync Server 2013" } 
  
                 default {  Write-Host -ForegroundColor red "unknown - "$LyncSchemaVersion.rangeUpper } 
                 } 
     }        
     else{       
         Write-Host -ForegroundColor green "(not present)"        
     } 
     Write-Host "" 
 } 
 function FFL-Info{ 
     Write-Host "Forest Functional Level" 
     $ffl = $global:ForestInfo.ForestModeLevel 
     switch ($ffl) 
                                             {      
             0 { Write-Host -ForegroundColor green "Windows 2000" } 
             1 { Write-Host -ForegroundColor green "Windows Server 2003" } 
             2 { Write-Host -ForegroundColor green "Windows Server 2003" } 
             3 { Write-Host -ForegroundColor green "Windows Server 2008" } 
             4 { Write-Host -ForegroundColor green "Windows Server 2008 R2" } 
             5 { Write-Host -ForegroundColor green "Windows Server 2012" } 
             6 { Write-Host -ForegroundColor green "Windows Server 2012 R2" } 
             7 { Write-Host -ForegroundColor green "Windows Server 2016" } 
             default { Write-Host -ForegroundColor red "Unknown Forest Functional Level:"$ffl }       
         }     
     Write-Host "" 
     } 
 function Tombstone-Info{ 
     $configPartition = $global:ForestInfo.Schema.name.Replace("CN=Schema,","") 
     $tombstoneLifetime = ([adsi]"LDAP://CN=Directory Service,cn=Windows NT,cn=Services,$configPartition").Properties.tombstoneLifetime 
     Write-Host "Tombstone lifetime" 
     if ($tombstoneLifetime -ne $nul){ 
             Write-Host -ForegroundColor Green $tombstoneLifetime" day(s)" 
         } 
         else{       
             Write-Host -ForegroundColor Green "60 days (default setting)"       
         } 
     Write-Host "" 
     } 
 function Recyle-Info{ 
     $ffl = $global:ForestInfo.ForestModeLevel 
     $ADDEFINE = "LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration" + ",$global:domainDN" 
     $ADRecBinSupport="Feature not supported" 
     if ($ffl -like "8" -or $ffl -like "7" -or $ffl -like "6" -or $ffl -like "4"){ 
         $ADRecBin = (([adsi]"$ADDEFINE").name).count 
             if( $ADRecBin -ne 0 ){ 
                 $ADRecBinSupport="Enabled" 
             } 
             else{ 
                 $ADRecBinSupport="Disabled" 
             } 
     } 
     Write-Host "Active Directory Recycle Bin" 
     Write-Host -ForegroundColor Green $ADRecBinSupport 
     Write-host "" 
     } 
 function Trusts-Info{ 
     $allDomains = $global:ForestInfo.Domains 
     Write-Host "Domains in this forest" 
     $allDomains | Sort | %{Write-Host -ForegroundColor Green $_ } 
     Write-Host "" 
     Write-Host "List of Trusts" 
     $ADTrusts = dsquery * -filter "(objectClass=trustedDomain)" -attr cn,trustDirection 
     if ($ADTrusts.Count -gt 0) {         
             foreach ($Trust in $ADTrusts){ 
                     switch ($Trust.trustDirection){                        
                             3 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  <===>  ") } 
                             2 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  <----  ") } 
                             1 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  ---->  ") }                         
                         } 
                     Write-Host -ForegroundColor green $trustInfo 
                 } 
         } 
     else{       
         Write-Host -ForegroundColor green "(none)"        
     } 
     Write-Host "" 
 } 
 function Partition-Info{ 
     $partitions = $global:ForestInfo.ApplicationPartitions 
     Write-Host "List of all partitions" 
     Write-Host "" 
     foreach ($part in $partitions){ 
         Write-Host -BackgroundColor Yellow -ForegroundColor Black $part.DirectoryServers 
         Write-host -BackgroundColor Green $part.Name 
         Write-Host -BackgroundColor Red $part.DirectoryServers.Partitions 
         $DNSServers = ([adsi]"LDAP://RootDSE").dnsHostName 
             if ($DNSServers -ne $nul){    
                 Write-Host -ForegroundColor Yellow "DNS Servers"  
                 forEach ($DNSServer in $DNSServers){ 
                     Write-Host $DNSServer 
                 } 
             } 
         } 
     Write-Host "" 
     } 
 function Sites-Info{ 
     Write-Host "Sites and Subnets information" 
     Write-Host "" 
     #Sites Enumeration 
     $allsites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().sites 
     #loop for Sites and Subnets 
             foreach ($site in $allsites ){ 
                 Write-Host -ForegroundColor Black -BackgroundColor Yellow "Site:"$site.Name 
                 Write-host "" 
                 Write-Host -ForegroundColor Yellow "Server(s) in site:" 
                 Write-host "" 
                 $ServersInSite = $allsites.Servers.Name 
                 $DomainCall = [System.DirectoryServices.ActiveDirectory.domain]::GetComputerDomain().DomainControllers.Name  
                 Foreach ($Server in $ServersInSite){ 
                     #If any DC is in Site 
                     if ( $server -ne $nul ){ 
                     $dcDetails = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers       
                     #Declaring Searching Pattern to look for FRS and DFSR 
                     $defaultNamingContext = (([ADSI]"LDAP://$DomainCall/rootDSE").defaultNamingContext) 
                     $searcher = New-Object DirectoryServices.DirectorySearcher 
                     $searcher.Filter = "(&(objectClass=computer)(dNSHostName=$DomainCall))" 
                     $searcher.SearchRoot = "LDAP://" + $DomainCall + "/OU=Domain Controllers," + $defaultNamingContext 
                     $dcObjectPath = $searcher.FindAll() | %{$_.Path} 
  
                     # DFSR 
                     $searchDFSR = New-Object DirectoryServices.DirectorySearcher 
                     $searchDFSR.Filter = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))" 
                     $searchDFSR.SearchRoot = $dcObjectPath 
                     $dcDFSR = $searchDFSR.FindAll() 
                     $dcDFSRinfo = $dcDFSR.Properties 
                  
                     # FRS 
                     $searchFRS = New-Object DirectoryServices.DirectorySearcher 
                     $searchFRS.Filter = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))" 
                     $searchFRS.SearchRoot = $dcObjectPath 
                     $dcFSR = $searchFRS.FindAll() 
                      
                     #Display Domain Controller Details 
                     Write-Host -ForegroundColor Green "$($server.name) ($($DomainCall))" 
                     Write-Host "IP Address (v4)     : " (Get-NetIPAddress -AddressFamily IPv4).IPv4Address 
  
                     if ($dcDetails.IPaddress -ne $nul){ 
                         Write-Host "Link-Local (Iv6)    : "$dcDetails.IPAddress 
                         } 
                     else{ 
                         Write-Host "IP Address (v6)     :  (none)" 
                         } 
                     #End IPv6 address section 
          
                     #Operating System Type and its service pack level 
                     Write-host "OS type             : " $dcDetails.OSversion 
                     #End of Operating System and services pack level section 
          
                     #SYSVOL replication method on DC 
                     #SYSVOL FRS section 
                     if ($dcFRSinfo -ne $nul){ 
                         Write-Host "SYSVOL Replication  :  FRS" 
                         Write-Host "SYSVOL Location     : "$dcFRSinfo.FRSRootPath 
                             } 
                     if ($dcDFSRinfo -ne $nul){ 
                         Write-Host "SYSVOL Replication  :  DFS-R" 
                         Write-Host "SYSVOL Location     : "$dcDFSRinfo.'msdfsr-rootpath' 
                         if ($dcDFSRinfo."msDFSR-RootSizeInMB" -ne $nul){ 
                             Write-Host "SYSVOL quota          : "$dcDFSRinfo."msDFSR-RootSizeInMb" 
                                 } 
                         else{ 
                             Write-Host "SYSVOL quota        :  4GB (default setting)" 
                                     } 
                         #End of SYSVOL size 
                         } 
                     #End of SYSVOL DFS-R section 
                     } 
                     else{ 
                         Write-Host -ForegroundColor Green "(none)" 
                     } 
                 #End of section where DC is in Site 
                 Write-host "" 
         } 
                 $subnets = $Site.subnet 
                 Write-Host -ForegroundColor Yellow "Subnets:" 
                 if ( $subnets -ne $nul ){ 
                     foreach ($subnet in $subnets){ 
                         $SubnetSplit = $subnet.Split(",") 
                         Write-Host $SubnetSplit[0].Replace("CN=","") 
                     } 
                 #End of Listing Subnets 
                 } 
                 else{ 
                     Write-Host -ForegroundColor green "(none)" 
                 } 
                 Write-Host "" 
                 Write-Host "" 
             } 
     Write-Host -ForegroundColor Yellow -BackgroundColor Black "Site Link(s) information:" 
     Write-Host ""     
     $SiteLinks = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().sites.sitelinks 
     foreach ($link in $siteLinks){ 
                 Write-Host "Site link name       : " -NoNewLine 
                 Write-Host -ForegroundColor green $link.Name 
                 Write-Host "Replication cost     : " -NoNewLine 
                 Write-Host -ForegroundColor green $link.Cost 
                 Write-Host "Transport Type       : " -NoNewLine 
                 Write-Host -ForegroundColor green $link.TransportType 
                 Write-Host "Sites included       : " -NoNewLine 
                 foreach ($linkList in $link.Sites){ 
                     $siteName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().sites.Name 
                     Write-Host -ForegroundColor Green $siteName"; " -NoNewline 
                 } 
     Write-Host "" 
     } 
 } 
 function Catalog-Info{ 
     $ForestGC = $global:ForestInfo.GlobalCatalogs 
     Write-Host "Global Catalog Servers in the Forst" 
     $ForestGC.Name | Sort | % {Write-Host -ForegroundColor Green $_.toUpper()} 
     Write-Host "" 
     Write-Host "Additional UPN suffixes" 
     $UPNsuffix = $global:ForestInfo.UPNSuffixes 
     if ($UPNsuffix.Count -ne 0){ 
             $UPNsuffix | Sort | %{Write-Host -ForegroundColor green $_ } 
         } 
     else{ 
         Write-Host -ForegroundColor green "(none)" 
         } 
     Write-Host "" 
 } 
 function FSMO-Roles{ 
     $FSMODomainNaming = $global:ForestInfo.NamingRoleOwner 
     $FSMOSchema = $global:ForestInfo.SchemaRoleOwner 
     Write-Host -ForegroundColor Yellow -BackgroundColor Black "FSMO Roles Details" 
     Write-Host "" 
     Write-Host "Schema Master" 
     Write-Host -ForegroundColor Green $FSMOSchema 
     Write-Host "" 
     Write-Host "Domain Naming Master" 
     Write-Host -ForegroundColor Green $FSMODomainNaming 
     Write-Host "" 
     Write-Host "" 
 } 
 function Group-Info{ 
     Write-Host -ForegroundColor Yellow -BackgroundColor Black "Forest Wide Groups Details:" 
     Write-Host "" 
 #Schema Administrators 
     $schemaGroupIDBuilder= "LDAP://CN=Schema Admins,CN=Users,"+$DomainDN 
     $schemaAdminCount =  (([adsi]$schemaGroupIDBuilder).member).Count 
     if ($schemaAdminCount -eq 2){ 
         Write-Host "Total number of Schema Adminstrators      : " -NoNewline 
         Write-Host -ForegroundColor Green $schemaAdminCount 
     } 
     else{ 
         Write-Host "Total number of Schema Administrators     : " -NoNewLine 
         Write-Host -ForegroundColor Red $schemaAdminCount 
     } 
  
 #Enterprise Admins 
     $enterGroupIDbuilder = "LDAP://CN=Enterprise Admins,CN=Users,"+$DomainDN 
     $enterpriseAdminsNo = (([adsi]$enterGroupIDbuilder).member).Count 
     if ($entpriseAdminsNo -eq 1){ 
         Write-Host "Total number of Enterprise Administrators : " -NoNewline 
         Write-Host -ForegroundColor Green $enterpriseAdminsNo 
     } 
     else{ 
         Write-Host "Total number of Enterprise Administrator  : " -NoNewline 
         Write-Host -ForegroundColor Red $enterpriseAdminsNo 
     } 
     Write-Host "" 
     }  
 function Menu-Loop{ 
     $Exitor = Read-Host -Prompt "Would you Like Additional Information? Y/N" 
     if (($Exitor -like "y" -or $Exitor -like "Y" -or $Exitor -like "YES" )){ 
         DO{ 
             Show-Menu 
             $Selection = Read-Host "Please Make a Selection" 
                 switch($selection){ 
                 '1'{ 
                      DO{ 
                         Show-GroupMenu 
                         $Groupselector = Read-host "Please make a selection"  
                         $GroupBuilder = "'(memberOf:1.2.840.113556.1.4.1941:=cn=Domain Admins,CN=Users," + $DomainDN + ")'" 
                             switch($Groupselector){ 
                         '1'{([adsisearcher]$GroupBuilder).FindAll() ;continue} 
                         '2'{([adsisearcher]'(groupType=-2147483644)').FindAll() ;continue} 
                         '3'{([adsisearcher]'(groupType=2)').FindAll() ;continue} 
                         '4'{(Get-WmiObject win32_group -Recurse -ComputerName $global:COMPNAME | Where {$_.SID -match '-512$'}).GetRelated("win32_Group") ;continue} 
                         '5'{([adsisearcher]'(objectClass=trustedDomain)').FindAll() ;continue} 
                         'R'{Break} 
                         'Q'{Return} 
                         } 
                         pause 
                         } 
                     until($Groupselector -eq 'R' ) 
                         Break         
                } 
                 '2' 
                 { 
                  DO{ 
                     Show-ComputerMenu 
                     $Computerselector = Read-host "Please make a selection"  
                         switch($Computerselector){ 
                     '1'{([adsisearcher]'(objectCategory=computer)').FindAll() ;continue} 
                     '2'{([adsisearcher]'(&(objectCategory=computer)(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288)))').FindAll() ;continue} 
                     '3'{([adsisearcher]'(&(objectCategory=computer)(primaryGroupID=515))').FindAll() ;continue} 
                     '4'{([adsisearcher]'(&(objectCategory=computer)(operatingSystem=*server*))').FindAll() ;continue} 
                     '5'{([adsisearcher]'(&(objectCategory=computer)(ms-MCSAdmPwd=*))').FindAll().properties ;continue} 
                     'R'{Break} 
                     'Q'{Return} 
                     } 
                     pause 
                     } 
                 until($Computerselector -eq 'R' ) 
                     Break 
          
                } 
                 '3' 
                 { 
              DO{ 
                 Show-UserMenu 
                 $Userselector = Read-host "Please make a selection"  
                     switch($Userselector){ 
                 '1'{ Write-Output (Get-WmiObject win32_group -Recurse -ComputerName $global:COMPNAME | Where {$_.SID -match '-512$'}).GetRelated("win32_useraccount") ;continue} 
                 '2'{ Write-Output (Get-WmiObject win32_group -Recurse -ComputerName $global:COMPNAME | Where {$_.SID -match '-518$'}).GetRelated("win32_useraccount") ;continue} 
                 '3'{ ([adsisearcher]'(adminCount=1)').FindAll() ;continue} 
                 '4'{([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))').FindAll() ;continue} 
                 '5'{([adsisearcher]'(&(objectCategory=person)(objectClass=user)(|(accountExpires=0)(accountExpires=9223372036854775807)))').FindAll() ;continue} 
                 'R'{Break} 
                 'Q'{Return} 
                 } 
                 pause 
                 } 
             until($Userselector -eq 'R' ) 
                 break 
                     } 
                 } 
         } 
         until($Selection -eq 'Q') 
         Break 
         } 
     Else{ 
     } 
 } 
 function main{ 
     Start-Transcript
     Write-Host -ForegroundColor Cyan -BackgroundColor Black "Pulling Active Directory Objects.." 
     Group-Enum 
     User-Enum 
     Admin-Accounts 
     FSMO-Info 
     Default-Gpo 
     Display-Collection 
     Schema-Info 
     Exchange-Info 
     Lync-Info 
     FFL-Info 
     Tombstone-Info 
     Recyle-Info 
     Trusts-Info 
     Partition-Info 
     Sites-Info 
     Catalog-Info 
     FSMO-Roles 
     Group-Info 
     Domain-Statistics 
     Menu-Loop 
     Stop-Transcript
 }Main
