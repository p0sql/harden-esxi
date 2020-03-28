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
        Write-Host "[+] Acceptance Level for $esxhost is OK -> Acceptance is '$acceptance'`n"
    }
    else {
        Write-Host "[-] Acceptance Level for $esxhost -> Change it. Acceptance is '$acceptance'`n"
    }
}

#Check NTP configuration
Write-Host "############# Check NTP Configuration #############"
foreach ($esxhost in $hosts) {
    $ntpservers = Get-VMHostNtpServer -VMHost $esxhost
    if(-Not $ntpservers.Length -eq 0) {
        Write-Host "[+] $esxhost have NTP Servers -> $ntpservers`n"
    }
    else {
        Write-Host "[-] $esxhost doesn't have NTP Servers`n"
    }
}

#Check firewall for restrict access to an ip address
Write-Host "############# Check Firewall Configuration #############"
foreach ($esxhost in $hosts) {
    $services = Get-VMHostFirewallException -VMHost $esxhost -Enabled 1 | Where {(-not $_.ExtensionData.AllowedHosts.AllIP)}
    if($services -eq $null) {
        Write-Host "[-] $esxhost not restrict services to a specific ip address. Set it with the firewall panel`n"
    }
    else {
        Write-Host "[+] $esxhost restrict services with specific address -> OK`n"
    }
}

#Check if MOB is disabled
Write-Host "############# Check Managed Object Module #############"
foreach ($esxhost in $hosts) {
    $mob = Get-VMHost -Name $esxhost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob
    if($mob.Value -eq $False) {
        Write-Host "[+] $esxhost -> Managed Object Module is disabled"
    }
    else {
        Write-Host "[-] $esxhost -> Managed Object Module is enabled"
    }
}