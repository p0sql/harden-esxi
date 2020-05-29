#Author : Warren POSTDAM

#Check PowerCLI module

if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Write-Host "[+] PowerCLI module exists`n"
} else {
    Write-Host "[-] Module does not exist. PowerCLI installation..."
    Install-Module -Name VMware.PowerCLI -Force
    Set-PowerCLIConfiguration -InvalidCertificateAction:Ignore
}

#Input for vSphere Environment
$vcenter = Read-Host 'Enter vCenter IP '
Connect-VIServer -Server $vcenter
Write-Host "`nSSO ESXi host credentials :"
$SSO = Get-Credential
$hosts = Get-VMHost 
$vms = Get-VM

#Harden Acceptance Level
Write-Host "`n############# Harden Install Configuration #############"
Foreach ($esxhost in $hosts) {
    $esxcli = Get-EsxCli -VMHost $esxhost
    Write-Host "[+] $esxhost : Change VIB acceptance level to 'PartnerSupported'"
    $esxcli.software.acceptance.Set("PartnerSupported")
    
}

#Harden NTP Configuration
Write-Host "############# Harden Communication Configuration #############"
[string[]] $_ntpservers= @()
$_ntpservers = Read-Host "NTP Servers (separated by ',' whithout space)"
$_ntpservers = $_ntpservers.Split(',').Split(' ')
Write-Host "[+] Add NTP Servers on ESXi Hosts"
if($_ntpservers.count -eq 0) {
    Write-Host "[+] ESXi Hosts already have NTP servers"
}
else {
    Write-Host "[+] Add NTP Servers on ESXi Hosts"
    Get-VMHost | Add-VmHostNtpServer $_ntpservers -Confirm:$false
}


#Disable MOB 
Write-Host "[+] Disable Managed Object Browser"
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -value "false" -Confirm:$false

#Harden SNMP
$check = Read-Host "Infrastructure need SNMP ? (yes/no)"
if($check -eq "yes") {
    $community = Read-Host "Enter Read Only Community "
    foreach ($esxhost in $hosts) {
        Connect-VIServer -Server $esxhost -Credential $SSO
        Get-VMHostSNMP | Set-VMHostSNMP -Enabled:$true -ReadOnlyCommunity $community
        Disconnect-VIServer -Server $esxhost -Confirm:$false
        Write-Host "[+] $esxhost : Add a RO community"
        
    }
}
else {
    foreach ($esxhost in $hosts) {
        Connect-VIServer -Server $esxhost -Credential $SSO
        Get-VMHostSNMP | Set-VMHostSNMP -Enabled:$false
        Disconnect-VIServer -Server $esxhost -Confirm:$false
        Write-Host "[+] $esxhost :  Disable SNMP"
    }
}

#Disable dvfilter
foreach ($esxhost in $hosts) {
    Get-VMHost -Name $esxhost| Get-AdvancedSetting Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value "" -Confirm:$false
    Write-Host "[+] $esxhost :  Disable dvfilter"
}


Write-Host "############# Harden Access Configuration #############"
#Set to 3 Account Failures
Write-Host "[+] Set maximum failed login attemps to 3"
Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3 -Confirm:$false

#Set to 15min lock time
Write-Host "[+] Set account lock time to 15 min"
Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false

Write-Host "[+] Set DCUI timeout to 10 min"
Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600

Write-Host "[+] Disable ESXi Shell"
Get-VMHost | Get-VMHostService | Where { $_.key -eq "TSM" } | Set-VMHostService -Policy Off

Write-Host "[+] Disable SSH"
Get-VMHost | Get-VMHostService | Where { $_.key -eq "TSM-SSH" } | Set-VMHostService -Policy Off

foreach ($esxhost in $hosts) {
    (Get-VMHost $esxhost | Get-View).EnterLockdownMode() 
    Write-Host "[+] $esxhost : Enter in Lockdown Mode"
}
Write-Host "[+] You can connect on hosts only with vCenter now"

Write-Host "[+] Set sessions timeout to 5 min"
Get-VMHost | Get-AdvancedSetting -Name 'UserVars.ESXiShellInteractiveTimeOut' | Set-AdvancedSetting -Value "300" -Confirm:$false

Write-Host "[+] Set services timeout to 1 hour"
Get-VMHost | Get-AdvancedSetting -Name 'UserVars.ESXiShellTimeOut' | Set-AdvancedSetting -Value "3600" -Confirm:$false


Write-Host "############# Harden vNetwork Configuration #############"
foreach ($esxhost in $hosts) {
    $vswitchs = Get-VirtualSwitch -VMHost $esxhost| select Name
    for($i=0; $i -lt $vswitchs.Length; $i++) {$esxcli.network.vswitch.standard.policy.security.set($false, $false, $false, $vswitchs[$i].Name)}
}
Write-Host "[+] Set all vNetwork options to false"


Write-Host "############# Harden Virtual Machines Configuration #############"

$array_settings_true = "isolation.device.edit.disable", "isolation.device.connectable.disable", "isolation.tools.ghi.autologon.disable",
"isolation.bios.bbs.disable", "isolation.tools.ghi.protocolhandler.info.disable", "isolation.tools.unity.taskbar.disable",
"isolation.tools.unityActive.disable", "isolation.tools.unity.windowContents.disable", "isolation.tools.unity.push.update.disable",
"isolation.tools.vmxDnDVersionGet.disable", "isolation.tools.guestDnDVersionSet.disable", "isolation.ghi.host.shellAction.disable",
"isolation.tools.dispTopoRequest.disable", "isolation.tools.trashFolderState.disable", "isolation.tools.ghi.trayicon.disable", 
"isolation.tools.unity.disable", "isolation.tools.unityInterlockOperation.disable", "isolation.tools.getCreds.disable", 
"isolation.tools.hgfsServerSet.disable", "isolation.tools.ghi.launchmenu.change", "isolation.tools.memSchedFakeSampleStats.disable",
"isolation.tools.copy.disable", "isolation.tools.dnd.disable", "isolation.tools.paste.disable", "isolation.tools.diskShrink.disable",
"isolation.tools.diskWiper.disable", "isolation.tools.vixMessage.disable" 


foreach ($setting in $array_settings_true) {
    Write-Host "[+] $setting : Set to true"
    Get-VM | New-AdvancedSetting -Name $setting -value $true -Force -Confirm:$false
}


$array_settings_false = "tools.guestlib.enableHostInfo", "isolation.tools.setGUIOptions.enable", "RemoteDisplay.vnc.enabled",
"mks.enable3d"

foreach ($setting in $array_settings_false) {
    Write-Host "[+] $setting : Set to false"
    Get-VM | New-AdvancedSetting -Name $setting -value $false -Force -Confirm:$false
}

Write-Host "[+] Limited log files for virtual machines"
Get-VM | New-AdvancedSetting -Name "log.keepOld" -value "10" -Force -Confirm:$false

Write-Host "[+] Limited informational messages from VM to VMX file"
Get-VM | New-AdvancedSetting -Name "tools.setInfo.sizeLimit" -value 1048576 -Force -Confirm:$false

Write-Host "[+] Set maximum remote display connections to 3"
Get-VM | New-AdvancedSetting -Name "RemoteDisplay.maxConnections" -value 3 -Force -Confirm:$false
