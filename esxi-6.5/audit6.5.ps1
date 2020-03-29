#Author : Warren POSTDAM

#Check PowerCLI module

if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Write-Host "[+] Module exists"
} else {
    Write-Host "[-] Module does not exist. Installation of PowerCLI"
    Install-Module -Name VMware.PowerCLI -Force
    Set-PowerCLIConfiguration -InvalidCertificateAction:Ignore
}

#Input for vSphere Environment
$vcenter = Read-Host 'Enter vcenter IP '
Connect-VIServer -Server $vcenter
$hosts = Get-VMHost 

#Check Acceptance Level 
Write-Host "############# Check VIB Acceptance Level #############"
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
    elseif ($snmp.communities.Length -gt 0 ) {
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
        Write-Host "[+] $esxhost : The DCUI timeout is set for $value min. It should be set at least 10 min`n" -ForegroundColor Red
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
        Write-Host "[+] $esxhost : ESXi shell is enabled. It should be disabled`n" -ForegroundColor Red
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
        Write-Host "[+] $esxhost : ESXi shell is enabled. It should be disabled`n" -ForegroundColor Red
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
        Write-Host "[+] $esxhost : Lockdown mode is disabled. It should be enable`n" -ForegroundColor Red
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
        Write-Host "[+] $esxhost : Shell services timeout after $value min. It should be set to 1 hour or less`n" -ForegroundColor Red
    }
}