#requires -Modules Pester
#requires -version 4.0
<#
.SYNOPSIS
    Run Pester Unit Tests against Azure AD Connect configuration and rules
.DESCRIPTION
    Actions:
TBC.NOTES
    Script Name     : AADConn.Tests.ps1
    Requires        : Powershell Version 5.0
    Tested          : Powershell Version 5.0
    Author          : Andrew.Auret
    Version         : 1.6
    Date            : 2017-08-02 (ISO 8601 standard date notation: YYYY-MM-DD) 
.VERSION
    1.0             : Initial version AAD Connect
.LINK
    
.PARAMETER
    None
.EXAMPLE

Change Mode to 'Secondary' for Staging server
------------------------------------------------------------------------------------------------------------------------------------
Runs PreRequisites tests Only - RUN 1st
    Invoke-Pester -Script @{Path = '.\.\AADConn.Tests.ps1'; Parameters = @{skip = $True;Mode = 'Primary'}} -Tag PreReqs
------------------------------------------------------------------------------------------------------------------------------------
Runs Iintial Install  tests Only - Run After Install of AADConnect
    Invoke-Pester -Script @{Path = '.\.\AADConn.Tests.ps1'; Parameters = @{skip = $True;Mode = 'Primary'}} -Tag Initial, Install
------------------------------------------------------------------------------------------------------------------------------------
Runs ADSyncConnector tests Only - Run after configuring Rules
    Invoke-Pester -Script @{Path = '.\.\AADConn.Tests.ps1'; Parameters = @{skip = $True;Mode = 'Primary'}} -Tag ADSync
------------------------------------------------------------------------------------------------------------------------------------
Runs ALL tests and skip InitialInstall check - Final Check after sync enabled
    Invoke-Pester -Script @{Path = '.\.\AADConn.Tests.ps1'; Parameters = @{skip = $True;Mode = 'Primary'}}  -ExcludeTag Initial
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory =$False)]
    $Skip,
    [Parameter(Mandatory =$True)]
    [ValidateSet("Primary", "Secondary")]
    $Mode
)

If ($Skip){
    $Skip = $true
}

#
$scriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
#region Function Get_CurrentUserType
Function Get-CurrentUserType {            
    [CmdletBinding()]         
    Param(            
    )            
            
    #Import Assembly            
            
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement            
    $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current            
    if($UserPrincipal.ContextType -eq "Machine") {            
        return "LocalUser"            
    } elseif($UserPrincipal.ContextType -eq "Domain") {            
        return "DomainUser"            
    }            
}            
#endregion Function Get_CurrentUserType
#region Function Software
Function Software{
    param(
        [Parameter(ValueFromPipelineByPropertyName=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$SoftwareSearchString
        )
    try{
        $reg=Get-WmiObject -List -Namespace root\default | Where-Object {$_.Name -eq "StdRegProv"}
        $Keys = $reg.EnumKey(2147483650,"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        Foreach($Key in $Keys.SNames)
        {
            $DN = $reg.GetStringValue(2147483650,"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + $Key, "DisplayName")
            If (-not $DN.SValue -eq ""){
            If ($DN.SValue -eq "$($SoftwareSearchString)"){
                Return "$($DN.SValue)"
		        }
	        }
        }
    }
    Catch{}
}
#endregion Function Software
#
Describe -Tag PreReqs "PreRequisites"{
    Context -Name "Server Specific Checks"{
        It "should be Windows Server 2012 R2 or later"{
            (Get-CimInstance -computername $Target Win32_OperatingSystem).Version | Should BeGreaterThan 6.3
        }
        It "has PowerShell Version 3.0 or later installed"{
            $PSVersionTable.PSVersion.Major | Should BeGreaterThan 3
        }
        It "has .NET Framework 4.5.1 or later installed"{
            (Get-ItemProperty 'REGISTRY::HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release | Should BeGreaterThan 378674
        }
        It "has full GUI installed"{
            (Get-WindowsFeature -Name "Server-Gui-Shell").InstallState | Should Be "Installed"
            (Get-WindowsFeature -Name "Server-Gui-Mgmt-Infra").InstallState | Should Be "Installed"
        }
        It "the Secondary Logon service is not disabled"{
            (Get-CimInstance Win32_Service -filter "Name='seclogon'").StartMode | Should Not Be "Disabled"
        }

        It "has connectivity with the Proxy / Internet"{
            $test = Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc -ErrorAction SilentlyContinue
             $test.StatusCode | Should Be 200
        }

        It "has TLS 1.2 enabled" -skip:$Skip{
            $regvalue = Invoke-Command -ScriptBlock {Test-path "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -ErrorAction SilentlyContinue}
            $regvalue | Should Be $True
        }
        It "has strong cryptography enabled" -skip:$Skip{
            $regvalue = Invoke-Command -ScriptBlock {(Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto  -ErrorAction Ignore).SchUseStrongCrypto}
            $regvalue | Should Be 1
        }
    }
}
Describe -Tag Install "Install"{
    Context -Name "AAD Connect Installation Specific Checks"{
        It "has 'Microsoft Azure AD Connect' listed as installed software" {
            (Software "Microsoft Azure AD Connect") | Should BeExactly "Microsoft Azure AD Connect"
        }
        It "has 'Microsoft Azure AD Connect synchronization services' listed as installed software" {
            (Software "Microsoft Azure AD Connect synchronization services") | Should BeExactly "Microsoft Azure AD Connect synchronization services"
        }
        It "has 'Microsoft Azure AD Connect Health agent for sync' listed as installed software" {
            (Software "Microsoft Azure AD Connect Health agent for sync") | Should BeExactly "Microsoft Azure AD Connect Health agent for sync"
        }
        It "the 'Azure AD Connect Health Sync Insights Service' is installed and running" {
            (Get-Service -Name AzureADConnectHealthSyncInsights -ErrorAction SilentlyContinue).Status | Should Be "Running"
        }
        It "the 'Azure AD Connect Health Sync Monitoring Service' is installed and running" {
            (Get-Service -Name AzureADConnectHealthSyncMonitor -ErrorAction SilentlyContinue).Status | Should Be "Running"
        }
        It "the AAD Connect auto upgrade state is disabled" {
            (Get-ADSyncAutoUpgrade -ErrorAction SilentlyContinue) | Should Be "Disabled"
        }
    }
}
Describe -Tag Initial "InitialInstall"{
    if ($Mode -eq "Primary"){
        Try{
            $Sync = (Get-ADSyncScheduler -ErrorAction SilentlyContinue)
            It "the SyncCycle should not be enabled"{$Sync.SyncCycleEnabled | Should Be $False}
            It "the StagingMode should not be enabled"{$Sync.StagingModeEnabled | Should Be $False}
        }
        Catch{
            Write-Host -ForegroundColor White -BackgroundColor Red "Error:: Getting Scheduler information - Please see URL below for more information: `n`nhttps://docs.microsoft.com/en-gb/azure/active-directory/connect/active-directory-aadconnect-troubleshoot-connectivity#verify-proxy-connectivity"
            $_.Exception.Message
            break
        }
    }
    Else{
        Try{
            $Sync = (Get-ADSyncScheduler -ErrorAction SilentlyContinue)
            It "the SyncCycle should not be enabled"{$Sync.SyncCycleEnabled | Should Be $False}
            It "the StagingMode should be enabled"{$Sync.StagingModeEnabled | Should Be $True}
        }
        Catch{
            Write-Host -ForegroundColor White -BackgroundColor Red "Error:: Getting Scheduler information - Please see URL below for more information: `n`nhttps://docs.microsoft.com/en-gb/azure/active-directory/connect/active-directory-aadconnect-troubleshoot-connectivity#verify-proxy-connectivity"
            $_.Exception.Message
            break
        }
    }
}
Describe -Tag Final "FinalCheck"{
    if ($Mode -eq "Primary"){
        Try{
            $Sync = (Get-ADSyncScheduler -ErrorAction SilentlyContinue)
            It "the SyncCycle should be enabled"{$Sync.SyncCycleEnabled | Should Be $True}
            It "the StagingMode should not be enabled"{$Sync.StagingModeEnabled | Should Be $False}
        }
        Catch{
            Write-Host -ForegroundColor White -BackgroundColor Red "Error:: Getting Scheduler information - Please see URL below for more information: `n`nhttps://docs.microsoft.com/en-gb/azure/active-directory/connect/active-directory-aadconnect-troubleshoot-connectivity#verify-proxy-connectivity"
            $_.Exception.Message
            break
        }
    }
    Else{
        Try{
            $Sync = (Get-ADSyncScheduler -ErrorAction SilentlyContinue)
            It "the SyncCycle should not be enabled"{$Sync.SyncCycleEnabled | Should Be $True}
            It "the StagingMode should be enabled"{$Sync.StagingModeEnabled | Should Be $True}
        }
        Catch{
            Write-Host -ForegroundColor White -BackgroundColor Red "Error:: Getting Scheduler information - Please see URL below for more information: `n`nhttps://docs.microsoft.com/en-gb/azure/active-directory/connect/active-directory-aadconnect-troubleshoot-connectivity#verify-proxy-connectivity"
            $_.Exception.Message
            break
        }
    }
}

Describe -Tag ADSync "ADSyncConnector Checks"{
    $XMLPath = join-path $scriptRoot "ADLDS_Rules.xml"
    $XmlData = [xml](Get-Content $XMLPath)
    $XMLPathAD = join-path $scriptRoot "ADDS_Rules.xml"
    $XmlDataAD = [xml](Get-Content $XMLPathAD)
    $Rules = ((Get-AdSyncRule -ErrorAction SilentlyContinue)|? { $_.ImmutableTag.Tagvalue -like 'CustomerName*' })
    $MSFTRuleSet = ((Get-AdSyncRule -ErrorAction SilentlyContinue) |? { $_.ImmutableTag.Tagvalue -like 'Microsoft*'})
    $GLDAPConn = ((Get-ADSyncConnector -ErrorAction SilentlyContinue) | Where-Object {$_.Subtype -eq "Generic LDAP (Microsoft)"})
    $aDDSConnector = ((Get-ADSyncConnector -ErrorAction SilentlyContinue) | ? { $_.Type -eq 'AD' })
    #Check that default Microsoft Rules are enabled
    Context -Name "Default Microsoft Rule Check"{
        Foreach($MSFTRule in $MSFTRuleSet){
            It "$($MSFTRule.Name) Rule is enabled"{
                $MSFTRule.Disabled | Should Be $False
            }
        }
    }
    #
   Context -Name "ADDS (Microsoft) Connector check"{
        #RunProfile Check
        $profilestocheck = @("Full Import",
                           "Full Synchronization",
                           "Delta Import",
                           "Delta Synchronization",
                           "Export")

        Foreach($profile in $profilestocheck){
            It "has a runprofile set named $profile"{
                $aDDSConnector.RunProfiles.Name.Contains($profile) | Should Be $true
            }
        }
        #ObjectInclusionList Check
        $ObjectInclusionList = @("group",
                                 "domainDNS",
                                 "inetOrgPerson",
                                 "container",
                                 "organizationalUnit",
                                 "msDS-Device",
                                 "user")

        Foreach($Object in $ObjectInclusionList){
            It "has correct ObjectInclusionList $Object set"{
                $aDDSConnector.ObjectInclusionList.Contains($Object) | Should Be $true
            }
        }
        #AttributeInclusionList Check
        $AttributeInclusionList = @("description",
                                    "displayName",
                                    "givenName",
                                    "objectSid",
                                    "postalCode",
                                    "preferredLanguage",
                                    "managedBy",
                                    "member",
                                    "employeeId",
                                    "employeeType",
                                    "pwdLastSet",
                                    "objectGUID",
                                    "userPrincipalName",
                                    "msDS-cloudExtensionAttribute8")

        Foreach($Attribute in $AttributeInclusionList){
            It "has the correct Attribute set:[$Attribute]"{
                $aDDSConnector.AttributeInclusionList.Contains($Attribute) | Should Be $true
            }
        }
    }
    #
    foreach ($item in $XmlDataAD.Rules.Name){
        Context -Name "ADDS Rule Checks - $($item.caption)"{
            $rule = (Get-ADSyncRule -ErrorAction SilentlyContinue) | Where-Object {$_.identifier -eq $($item.identifier)}
            It "has correct name value set:[$($item.caption)]"{
               $Rule.Name | should BeExactly $Item.caption
            }
            It "has Rule direction set correctly"{
               $Rule.direction | should BeExactly $Item.direction
            }
            It "has correct precedence value set"{
               $Rule.Precedence | should BeExactly $Item.Precedence
            }
            It "has correct immutableTag value set"{
               $($Rule.immutableTag).TagValue | should BeExactly $Item.immutableTag
            }
            It "has correct TargetObjectType set"{
               $Rule.TargetObjectType | should BeExactly $Item.TargetObjectType
            }
            It "has correct SourceObjectType set"{
               $Rule.SourceObjectType | should BeExactly $Item.SourceObjectType
            }
            It "has correct identifier set"{
               $Rule.identifier | should BeExactly $Item.identifier
            }
        }
    }
    #
    Context -Name "ADLDS Rule Check - Common"{
        It "has the correct amount of ADLDS Rules set"{
            $Rules.Count | Should Be 4
        }
    }
    #
    Context -Name "Generic LDAP (Microsoft) Connector check"{
        #RunProfile Check
        $profilestocheck = @("Full Import",
                           "Full Synchronization",
                           "Delta Import",
                           "Delta Synchronization",
                           "Export")

        Foreach($profile in $profilestocheck){
            It "has a runprofile set named $profile"{
                $GLDAPConn.RunProfiles.Name.Contains($profile) | Should Be $true
            }
        }
        #AnchorConstructionSettings Check
        $Anchors = @("group",
                    "userProxy")

        Foreach($Anchor in $Anchors){
            It "has correct Anchor $Anchor set"{
                $GLDAPConn.AnchorConstructionSettings.ObjectType.Contains($Anchor) | Should Be $true
            }
        }
        #ObjectInclusionList Check
        $ObjectInclusionList = @("group",
                                 "userProxy")

        Foreach($Object in $ObjectInclusionList){
            It "has correct ObjectInclusionList $Object set"{
                $GLDAPConn.ObjectInclusionList.Contains($Object) | Should Be $true
            }
        }
        #AttributeInclusionList Check
        $AttributeInclusionList = @("c",
                                    "cn",
                                    "company",
                                    "displayName",
                                    "facsimileTelephoneNumber",
                                    "givenName",
                                    "l",
                                    "CustomerName-ad-AuthManagerName",
                                    "CustomerName-ad-MobTelNo",
                                    "objectSid",
                                    "postalAddress",
                                    "sn",
                                    "telephoneNumber",
                                    "title",
                                    "userPrincipalName")

        Foreach($Attribute in $AttributeInclusionList){
            It "has the correct Attribute set:[$Attribute]"{
                $GLDAPConn.AttributeInclusionList.Contains($Attribute) | Should Be $true
            }
        }
    }
    foreach ($item in $XmlData.Rules.Name){
        Context -Name "ADLDS Rule Checks - $($item.caption)"{
            $rule = (Get-ADSyncRule -ErrorAction SilentlyContinue) | Where-Object {$_.identifier -eq $($item.identifier)}
            It "has correct name value set:[$($item.caption)]"{
               $Rule.Name | should BeExactly $Item.caption
            }
            It "has Rule direction set correctly"{
               $Rule.direction | should BeExactly $Item.direction
            }
            It "has correct precedence value set"{
               $Rule.Precedence | should BeExactly $Item.Precedence
            }
            It "has correct immutableTag value set"{
               $($Rule.immutableTag).TagValue | should BeExactly $Item.immutableTag
            }
            It "has correct TargetObjectType set"{
               $Rule.TargetObjectType | should BeExactly $Item.TargetObjectType
            }
            It "has correct SourceObjectType set"{
               $Rule.SourceObjectType | should BeExactly $Item.SourceObjectType
            }
            It "has correct identifier set"{
               $Rule.identifier | should BeExactly $Item.identifier
            }
        }
    }
    #
            
}


 