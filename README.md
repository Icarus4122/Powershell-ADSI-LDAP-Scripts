# Created off of ADReport by Krzysztof Pytko (iSiek)

# Formating Help by RpNull

# Additional One-Liners generated from base of audit_v1_wip.ps1 By. mr-r3b00t

# Additional Insperation from Blame Hue writing in ADSI



# ADSI-ADReport

   .NET Framwork / LDAP Active Directory Report

   Modified from version with the Imported Module "Active Directory"

   1-Click Run/Action Script



## PLEASE NOTE

-------------------------------

LDAP has a default search size limiter

To change the limiter to best suit you pleaes do the follow:

- ntdsutil "ldap pol" conn "con to server 'DomainControllerName'" q

- ldap policy: set MaxPageSize to 'size limit for Org'

- Commit Changes

   

-------------------------------



  

 *Additional movement on the project*

 - Added in automation and forest 

 - Error-Checking 

 - Recursive Parsing of Forests for Secondary Domains 

 - Parsing Groups and Users for Administrative permissions

 - Checking AD Forests/Sites for revocation cost/values

 - Menu Selector for additional Data mining

 - Scraping Groups for Nested groups


