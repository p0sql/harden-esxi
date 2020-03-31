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
$vcenter = Read-Host 'Enter vcenter IP '
Connect-VIServer -Server $vcenter
$hosts = Get-VMHost 
$vms = Get-VM

#Check Acceptance Level 
Write-Host "`n############# Check VIB Acceptance Level #############"
Foreach ($esxhost in $hosts) {
    $esxcli = Get-EsxCli -VMHost $esxhost
    $acceptance = $esxcli.software.acceptance.get()

    if($acceptance -eq "PartnerSupported") {
        Write-Host "[+] $esxhost : Acceptance Level '$acceptance'`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Acceptance Level '$acceptance'`n" -ForegroundColor Red
    }
}

#Check NTP configuration
Write-Host "############# Check NTP Configuration #############"
foreach ($esxhost in $hosts) {
    $ntpservers = Get-VMHostNtpServer -VMHost $esxhost
    if(-Not $ntpservers.Length -eq 0) {
        Write-Host "[+] $esxhost : Has NTP Servers -> $ntpservers`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Not have NTP Servers`n" -ForegroundColor Red
    }
}

#Check firewall for restrict access to an ip address
Write-Host "############# Check Firewall Configuration #############"
foreach ($esxhost in $hosts) {
    $services = Get-VMHostFirewallException -VMHost $esxhost -Enabled 1 | Where {(-not $_.ExtensionData.AllowedHosts.AllIP)}
    if($services -eq $null) {
        Write-Host "[-] $esxhost : Not restrict services to a specific ip address`n" -ForegroundColor Red
    }
    else {
        Write-Host "[+] $esxhost : Restrict services with specific address`n" -ForegroundColor Green
    }
}

#Check if MOB is disabled
Write-Host "############# Check Managed Object Module #############"
foreach ($esxhost in $hosts) {
    $mob = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob
    if($mob.Value -eq $False) {
        Write-Host "[+] $esxhost : Managed Object Module is disabled`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Managed Object Module is enabled`n" -ForegroundColor Red
    }
}

#Check if SNMP has a properly configuration
Write-Host "############# Check SNMP Configuration #############"
foreach ($esxhost in $hosts) {
    $esxcli = Get-EsxCli -VMHost $esxhost
    $snmp = $esxcli.system.snmp.get()
    if($snmp.enable -eq $False) {
        Write-Host "[+] $esxhost : SNMP is disabled`n" -ForegroundColor Green
    }
    elseif ($snmp.communities.Length -gt 0) {
        Write-Host "[+] $esxhost : SNMP is in Read Only`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : SNMP is enabled without Read Only community`n" -ForegroundColor Red
    }
}

#Check if dvfilter is not configured
Write-Host "############# Check dvfilter API #############"
foreach ($esxhost in $hosts) {
    $dvfilter = Get-VMHost -Name $esxhost | Get-AdvancedSetting Net.DVFilterBindIpAddress
    if($dvfilter.Value.Length -eq 0) {
        Write-Host "[+] $esxhost : dvfilter is not configured`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : dvfilter is configured`n" -ForegroundColor Red
    }
}

#Check if esxi has a core dumps centralized collection 
Write-Host "############# Check Core Dumps centralized collection #############"
foreach ($esxhost in $hosts) {
    $esxcli = Get-EsxCli -VMHost $esxhost
    $coredumps = $esxcli.system.coredump.network.Get()
    if($coredumps.Enabled -eq $true -And $coredumps.NetworkServerIP -ne $null) {
        Write-Host "[+] $esxhost : Core Dumps centralized collection is configured`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Core Dumps centralized collection is not configured`n" -ForegroundColor Red
    }
}

#Check persistent logging
Write-Host "############# Check Persistent Logging #############"
foreach ($esxhost in $hosts) {
    $pslogging = Get-VMHost -Name $esxhost | Select Name, @{N="Syslog.global.logDir";E={$_ | Get-AdvancedConfiguration Syslog.global.logDir | Select -ExpandProperty Values}}
    if($pslogging.'Syslog.global.logDir'.Length -gt 0) {
        Write-Host "[+] $esxhost : Persistent logging is configured`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Persistent logging is not configured`n" -ForegroundColor Red
    }

}

#Check if remote logging is configured
Write-Host "############# Check Remote Logging #############"
foreach ($esxhost in $hosts) {
    $rlogging = Get-VMHost -Name $esxhost | Get-AdvancedSetting Syslog.global.logHost
    if($rlogging.Value.Length -gt 0) {
        Write-Host "[+] $esxhost : Remote logging is configured`n" -ForegroundColor Green
    }
    else {
       Write-Host "[-] $esxhost : Remote logging is not configured`n" -ForegroundColor Red
    }
}

#Check if a non root user exists for local admin
Write-Host "############# Check Non Root Users #############"
foreach ($esxhost in $hosts) {
    $array_accounts = New-Object System.Collections.ArrayList
    $esxcli = Get-EsxCli -VMHost $esxhost
    $accounts = $esxcli.system.account.list()
    for($i = 0;$i -lt $accounts.Length;$i++) {
        if($accounts[$i].Description -eq "Administrator" -And $accounts[$i].UserID -ne "root") {
            $array_accounts.Add($accounts[$i].UserID)
        }
    }
    if($array_accounts.Length -gt 0) {
        Write-Host "[+] $esxhost : Non-root users exists for local administration -> $array_accounts`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : No non-root user exists for local administration`n" -ForegroundColor Red
    }
}

#Check if Active Directory is used for local user auth
Write-Host "############# Check Active Directory Authentification #############"
foreach ($esxhost in $hosts) {
    $ad = Get-VMHost -Name $esxhost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus
    if($ad.Domain -eq $null) {
        Write-Host "[-] $esxhost : No Active Directory Athentification for local users`n" -ForegroundColor Red
    }
    else {
        Write-Host "[+] $esxhost : Connected to '$ad.Domain'`n" -ForegroundColor Green
    }
}

#Check the maximum loggin attempt
Write-Host "############# Check Maximum Login Attempt #############"
foreach ($esxhost in $hosts) {
    $max_login = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name Security.AccountLockFailures
    $value = $max_login.Value
    if($max_login.Value -le 3) {
        Write-Host "[+] $esxhost : The maximum login attempt is $value`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : The maximum login attempt is $value`n" -ForegroundColor Red
    }
}

#Check account lockout
Write-Host "############# Check Account Lockout #############"
foreach ($esxhost in $hosts) {
    $lockout = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name Security.AccountUnlockTime
    $value = $lockout.Value/60
    if($lockout.Value -ge 900) {
        Write-Host "[+] $esxhost : The account lockout set for $value min`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : The account lockout set for $value min. It should be set at least 15 min`n" -ForegroundColor Red
    }
}

#check DCUI timeout
Write-Host "############# Check DCUI Timeout #############"
foreach ($esxhost in $hosts) {
    $dcui = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut
    $value = $dcui.Value/60
    if($dcui.Value -le 600) {
        Write-Host "[+] $esxhost : The DCUI timeout is set for $value min`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : The DCUI timeout is set for $value min. It should be set at least 10 min`n" -ForegroundColor Red
    }
}

#Check if ESXi shell is disabled
Write-Host "############# Check ESXi Shell Policy #############"
foreach ($esxhost in $hosts) {
    $shell = Get-VMHost -Name $esxhost | Get-VMHostService | Where { $_.key -eq "TSM" } | Select Key, Label, Policy, Running, Required
    if($shell.Policy -eq "off") {
        Write-Host "[+] $esxhost : ESXi shell is disabled`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : ESXi shell is enabled. It should be disabled`n" -ForegroundColor Red
    }
}

#Check if SSH is disabled
Write-Host "############# Check SSH Policy #############"
foreach ($esxhost in $hosts) {
    $shell = Get-VMHost -Name $esxhost | Get-VMHostService | Where { $_.key -eq "TSM-SSH" } | Select Key, Label, Policy, Running, Required
    if($shell.Policy -eq "off") {
        Write-Host "[+] $esxhost : ESXi shell is disabled`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : ESXi shell is enabled. It should be disabled`n" -ForegroundColor Red
    }
}

#Check if lockdown mode is enable 
Write-Host "############# Check Lockdown Policy #############"
foreach ($esxhost in $hosts) {
    $lockdown = Get-VMHost -Name $esxhost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}
    if($lockdown.Lockdown -eq $true) {
        Write-Host "[+] $esxhost : Lockdown mode is enabled`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Lockdown mode is disabled. It should be enable`n" -ForegroundColor Red
    }
}

#Check ESXi shell and SSH sessions timeout
Write-Host "############# Check ESXi SHell & SSH Sessions Timeout #############"
foreach ($esxhost in $hosts) {
    $lockout = Get-VMHost -Name $esxhost | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut
    $value = $lockout.Value/60
    if($lockout.Value -le 300) {
        Write-Host "[+] $esxhost : ESXi Shell and SSH sessions timeout after $value min or less`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : ESXi Shell and SSH sessions timeout after $value min. It should be set at least 10 min`n" -ForegroundColor Red
    }
}

#Check shell services timeout is set to 1 hour or less
Write-Host "############# Check Shell Services Timeout #############"
foreach ($esxhost in $hosts) {
    $lockout = Get-VMHost -Name $esxhost | Get-AdvancedSetting UserVars.ESXiShellTimeOut
    $value = $lockout.Value/60
    if($lockout.Value -le 3600) {
        Write-Host "[+] $esxhost : Shell services timeout after $value min`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : Shell services timeout after $value min. It should be set to 1 hour or less`n" -ForegroundColor Red
    }
}

#Check if DCUI has a trusted users list to lockdown
Write-Host "############# Check DCUI Trusted Users List #############"
foreach ($esxhost in $hosts) {
    $trusted = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name DCUI.Access
    if($trusted.Value.Length -gt 0) {
        Write-Host "[+] $esxhost : DCUI Access List has at least one user`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : DCUI Access List has no users`n" -ForegroundColor Red
    }
}

#Check iscsi
Write-Host "############# Check iScsi Authentification #############"
foreach ($esxhos in $hosts) {
    $iscsi = Get-VMHostHba -VMHost $esxhost -Type IScsi
    if($iscsi -ne $null) {        
        $chaptest = $iscsi | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}
        if($chaptest.Value -eq "Bidirectional CHAP") {
            Write-Host "[+] $esxhost : Bidirectional CHAP is used`n" -ForegroundColor Green
        }
        else {
            Write-Host "[-] $esxhost : Bidirectional CHAP is not used`n" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[+] $esxhost : Not use iSCSi`n"
    }
}

#Check vswitch
Write-Host "############# Check vSwitch Security #############"
foreach ($esxhost in $hosts) {
    $counter = 0
    $bad_vswitchs = New-Object System.Collections.ArrayList
    $vswitchs = Get-VirtualSwitch -VMHost $esxhost | select Name
    for($i=0; $i -lt $vswitchs.Length; $i++) {
        $vswitch_opt = $esxcli.network.vswitch.standard.policy.security.get($vswitchs.Name[$i])
        if($vswitch_opt.AllowForgedTransmits -eq $false -And $vswitch_opt.AllowMACAddressChange -eq $false -And $vswitch_opt.AllowPromiscuous -eq $false) {
            $counter++
        }
        else {
            $bad_vswitch.Add($vswitchs.Name[$i])
        }
    }
    if($bad_vswitch.Length -eq 0) {
        Write-Host "[+] $esxhost : vSwitch options are disabled`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $esxhost : vSwitch options are enabled`n" -ForegroundColor Red
    }
}

#Check vlan id in vswitch
Write-Host "############# Check VLAN ID of PortGroups #############"
$vlans_cisco = (1001..10024)
$bad_portgroups = New-Object System.Collections.ArrayList
$portgroups = Get-VirtualPortGroup -Standard | Select virtualSwitch, Name, VlanID
for($i = 0;$i -lt $portgroups.Length;$i++) {
    if($portgroups[$i].VLanId -In $vlans_cisco -Or $portgroups[$i].VLanId -eq 4094) {
        $bad_portgroups.Add($portgroups[$i].Name)
    }
}
if($bad_portgroups.count -eq 0) {
    Write-Host "[+] Hosts Portgroups has a correct vlan ID configuration`n" -ForegroundColor Green
}
else {
    Write-Host "[-] Host portgroups vlan ID are not correct -> $bad_portgroups`n" -ForegroundColor Red
}

#Check informational messages
Write-Host "############# Check Informational Messages Limitation of VMX file  #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "tools.setInfo.sizeLimit" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "tools.setInfo.sizeLimit") {
            if($size[$i].Value -ne 1048576) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Size limit for informational messages is set correctly`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Size limit for informational messages is not set correctly`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Size limit for informational messages is not set correctly`n" -ForegroundColor Red
}

#Remote console connection
Write-Host "############# Check Remote Connection Limitation #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "RemoteDisplay.maxConnections" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "RemoteDisplay.maxConnectionst") {
            if($size[$i].Value -gt 3) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Max connections on VM is configured correctly`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Max connections on VM is not configured correctly`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Max connections on VM is not configured correctly`n" -ForegroundColor Red
}

#Check floppy drives

#Check unauthorized modification and disconnection of devices is disabled
Write-Host "############# Check Unauthorized Modification and Disconnection of Devices #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.device.edit.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.device.edit.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Users without authorization cannot disconnect devices in vitual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Users without authorization can disconnect devices in virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Users without authorization can disconnect devices in virtual machines`n" -ForegroundColor Red
}

#Check unauthorized connection
Write-Host "############# Check Unauthorized Connection of Devices #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.device.connectable.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.device.connectable.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Users without authorization cannot connect devices in vitual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Users without authorization can connect devices in vitual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Users without authorization can connect devices in vitual machines`n" -ForegroundColor Red
}

#Check if Autologon is disabled
Write-Host "############# Check Autologon #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.ghi.autologon.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.ghi.autologon.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Autologin is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Autologon is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Autologon is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if BIOS BBS is disabled
Write-Host "############# Check BIOS BBS #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.bios.bbs.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.bios.bbs.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] BIOS BBS is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] BIOS BBS is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] BIOS BBS is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if GHIP is disabled
Write-Host "############# Check Guest Host Interaction Protocol Handler #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.ghi.protocolhandler.info.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.ghi.protocolhandler.info.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] GHI Protocol is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] GHI Protocol is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] GHI Protocol is enabled on virtual machines`n" -ForegroundColor Red
}

#Check Unity Taskbar
Write-Host "############# Check Unity Taskbar #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.unity.taskbar.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.unity.taskbar.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Unity Taskbar is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Unity Taskbar is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Unity Taskbar is enabled on virtual machines`n" -ForegroundColor Red
}

#Check Unity Window Contents
Write-Host "############# Check Unity Window Contents #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.unity.windowContents.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.unity.windowContents.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Unity Window Contents is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Unity Window Contents is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Unity Window Contents is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Unity Push Update is disabled
Write-Host "############# Check Unity Push Update #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.unity.push.update.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.unity.push.update.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Unity Push Update is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Unity Push Update is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Unity Push Update is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if drag and drop version get is disabled
Write-Host "############# Check Drag and Drop Version Get #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.vmxDnDVersionGet.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.vmxDnDVersionGet.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Drag and Drop Version Get is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Drag and Drop Version Get is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Drag and Drop Version Get is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Drag and Drop Version Set is disabled
Write-Host "############# Check Drag and Drop Version Set #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.guestDnDVersionSet.disable" | Select Entity,Name, Value
for($i = 0;$i -lt $size.Length;$i++) {
    if($size[$i].Name -eq "isolation.tools.guestDnDVersionSet.disable") {
        if($size[$i].Value -eq $false) {
            $counter++
        }
    }
}
if($counter -eq 0) {
    Write-Host "[+] Drag and Drop Version Set is disabled on virtual machines`n" -ForegroundColor Green
}
else {
    Write-Host "[-] Drag and Drop Version Set is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if shell is disabled
Write-Host "############# Check Shell Action #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.ghi.host.shellAction.disable" | Select Entity,Name, Value
for($i = 0;$i -lt $size.Length;$i++) {
    if($size[$i].Name -eq "isolation.ghi.host.shellAction.disable") {
        if($size[$i].Value -eq $false) {
            $counter++
        }
    }
}
if($counter -eq 0) {
    Write-Host "[+] Shell Action is disabled on virtual machines`n" -ForegroundColor Green
}
else {
    Write-Host "[-] Shell Action is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if request topology is disabled
Write-Host "############# Check Request Disk Topology #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.dispTopoRequest.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.dispTopoRequest.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Request Disk Topology is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Request Disk Topology is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Request Disk Topology is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if trash folder is disabled
Write-Host "############# Check Trash Folder #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.trashFolderState.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.trashFolderState.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Trash Folder is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Trash Folder is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Trash Folder is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Tray Icon is disabled
Write-Host "############# Check Trash Folder #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.trashFolderState.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.ghi.trayicon.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Tray Icon is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Tray Icon is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Tray Icon is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Unity is disabled
Write-Host "############# Check Unity #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.unity.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.unity.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Unity is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Unity is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Unity is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Unity Interlock is disabled
Write-Host "############# Check Unity #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.unityInterlockOperation.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.unityInterlockOperation.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Unity Interlock is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Unity Interlock is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Unity Interlock is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if GetCreds is disabled
Write-Host "############# Check GetCreds #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.getCreds.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.getCreds.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] GetCreds is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] GetCreds is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] GetCreds is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Host Guest File System Server is disabled
Write-Host "############# Check Host Guest File System Server #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.hgfsServerSet.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.hgfsServerSet.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Host Guest File System Server is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Host Guest File System Server is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Host Guest File System Server is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Guest Host Interaction Launch Menu is disabled
Write-Host "############# Check Guest Host Interaction Launch Menu #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.ghi.launchmenu.change" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.ghi.launchmenu.change") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Guest Host Interaction Launch Menu is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Guest Host Interaction Launch Menu is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Guest Host Interaction Launch Menu is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if memSchedFakeSampleStats is disabled
Write-Host "############# Check memSchedFakeSampleStats #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.memSchedFakeSampleStats.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.memSchedFakeSampleStats.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] memSchedFakeSampleStats is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] memSchedFakeSampleStats is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] memSchedFakeSampleStats is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Console Copy Operations is disabled
Write-Host "############# Check Console Copy Operations #############"
$counter = 0
    $size = $vms | Get-AdvancedSetting -Name "isolation.tools.copy.disable" | Select Entity,Name, Value
    if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.copy.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Console Copy Operations is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Console Copy Operations is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Console Copy Operations is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Drag and Drop Operations is disabled
Write-Host "############# Check Drag and Drop Operations #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.dnd.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.dnd.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Drag and Drop Operations is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Drag and Drop Operations is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Drag and Drop Operations is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Console GUI Options is disabled
Write-Host "############# Check Console GUI Options #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.setGUIOptions.enable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.setGUIOptions.enable") {
            if($size[$i].Value -eq $true) {
                $counter++
            }
        }
    }   
    if($counter -eq 0) {
        Write-Host "[+] Drag and Drop Operations is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Drag and Drop Operations is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Drag and Drop Operations is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if Console Paste Operations is disabled
Write-Host "############# Check Console Paste Operations #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.paste.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.paste.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Console Paste Operations is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Console Paste Operations is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Console Paste Operations is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if VNC protocol is limited
Write-Host "############# Check VNC Protocol #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "RemoteDisplay.vnc.enabled" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "RemoteDisplay.vnc.enabled") {
            if($size[$i].Value -eq $true) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] VNC Protocol is disabled on virtual machines`n" -ForegroundColor Green
    }   
    else {
        Write-Host "[-] VNC Protocol is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] VNC Protocol is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if VGA mode is disabled
Write-Host "############# Check VGA Mode #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "svga.vgaOnly" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "svga.vgaOnly") {
            if($size[$i].Value -eq $false) {
            $counter++
        }
    }
}
if($counter -eq 0) {
    Write-Host "[+] VGA mode is disabled on virtual machines`n" -ForegroundColor Green
}
else {
    Write-Host "[-] VGA mode is enabled on virtual machines`n" -ForegroundColor Red
}
}
else {
    Write-Host "[-] VGA mode is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if 3D acceleration is enabled
Write-Host "############# Check 3D Acceleration #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "mks.enable3d" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "mks.enable3d") {
            if($size[$i].Value -eq $true) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] 3D Acceleration is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
    Write-Host "[-] 3D Accelration is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] 3D Accelration is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if disk shrinking is disabled 
Write-Host "############# Check Disk Shrinking #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.diskShrink.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.diskShrink.disable") {
            if($size[$i].Value -eq $false) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Disk shrinking is disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Disk shrinking is enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Disk shrinking is enabled on virtual machines`n" -ForegroundColor Red
}

#Check if VIX Messages from VM are disabled
Write-Host "############# Check VIX Messages from VM #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "isolation.tools.vixMessage.disable" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "isolation.tools.vixMessage.disable") {
            if($size[$i].Value -eq $false -or $size[$i].Value -eq $null) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] VIX Messages from VM are disabled on virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] VIX Messages from VM are enabled on virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] VIX Messages from VM are enabled on virtual machines`n" -ForegroundColor Red
}

#Check number VM log files
Write-Host "############# Check Number of VM Log Files  #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "log.keepOld" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "log.keepOld") {
            if($size[$i].Value -ne 10) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Number of VM log files is configured properly`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Number of VM log files is configured properly`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Number of VM log files is configured properly`n" -ForegroundColor Red
}

#Check bidirectionial sending
Write-Host "############# Check Bidirectionial Sending Between ESXi and VM #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "tools.guestlib.enableHostInfo" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "tools.guestlib.enableHostInfo") {
            if($size[$i].Value -eq $true) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] ESXi not send informations to virtual machines`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] ESXi not send informations to virtual machines`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] ESXi not send informations to virtual machines`n" -ForegroundColor Red
}

#Check VM log size
Write-Host "############# Check Number of VM Log Files  #############"
$counter = 0
$size = $vms | Get-AdvancedSetting -Name "log.rotateSize" | Select Entity,Name, Value
if($size -ne $null) {
    for($i = 0;$i -lt $size.Length;$i++) {
        if($size[$i].Name -eq "log.rotateSize") {
            if($size[$i].Value -ne 1024000) {
                $counter++
            }
        }
    }
    if($counter -eq 0) {
        Write-Host "[+] Number of VM log files is configured properly`n" -ForegroundColor Green
    }
    else {
        Write-Host "[-] Number of VM log files is configured properly`n" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Number of VM log files is configured properly`n" -ForegroundColor Red
}