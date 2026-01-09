$RootDomain = "ice.corp.com"
$RootDomainDN = "DC=ice,DC=corp,DC=com"
$NBRootDomain = "ice"
$ChildDomain = "hq.ice.corp.com"
$NBChildDomain = "hq"

if(!($HostGuard = Get-HgsGuardian -Name VMGuardian))
{
    $HostGuard = New-HgsGuardian -Name 'VMGuardian' -GenerateCertificates
}
$KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot

$LABConfig = @{
"DNS01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Add-WindowsFeature DNS -IncludeManagementTools

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.253 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Add-DnsServerPrimaryZone -Name "." -ZoneFile "root.dns"
Add-DnsServerPrimaryZone -Name $RootDomain -ZoneFile $RootDomain.dns -DynamicUpdate NonsecureAndSecure
Add-DnsServerResourceRecord -ZoneName $RootDomain -IPv4Address 10.0.0.1 -A -Name .
Add-DnsServerPrimaryZone -Name $ChildDomain -ZoneFile $ChildDomain.dns -DynamicUpdate NonsecureAndSecure
Add-DnsServerResourceRecord -ZoneName $ChildDomain -IPv4Address 10.0.0.11 -A -Name .
Add-DnsServerResourceRecord -ZoneName $ChildDomain -IPv4Address 10.0.0.21 -A -Name pki

"@

        }
    };
"ROOTDC01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the first Domain Controller for the domain $Rootdomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server is configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBRootDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.1 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSForest ``
-CreateDnSDelegation:`$false ``
-DatabasePath "C:\Windows\NTDS" ``
-DomainMode "WinThreshold" ``
-DomainName $RootDomain ``
-DomainNetbiosName $NBRootDomain ``
-ForestMode "WinThreshold" ``
-InstallDns:`$false ``
-LogPath "C:\Windows\NTDS" ``
-NoRebootOnCompletion:`$false ``
-SysvolPath "C:\Windows\SYSVOL" ``
-Force:`$true ``
-SafeModeAdministratorPassword `$Cred.Password
"@
        };
    AdditionalScripts=@(
    @{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@"
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

`$Policy = New-WBPolicy
Add-WBSystemState -Policy `$Policy
Add-WBBareMetalRecovery -Policy `$Policy
Set-WBVssBackupOptions -Policy `$Policy -VssCopyBackup
`$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy `$Policy -Target `$Backuplocation
Set-WBSchedule -Policy `$Policy -Schedule 01:00
Start-WBBackup -Policy `$policy
"@
        },@{
            Path="Install";
            Name="CreateNewAdmin.ps1";
            Content=@"
`$Cred = Get-Credential -Message "Please enter the password for the new admin account" -UserName Admin
New-ADUser -Name Admin -AccountPassword `$Cred.Password -UserPrincipalName Admin@$NBChildDomain -DisplayName Admin -Description "MasterOfDisaster" -Server $ChildDomain -Enabled `$true
`$User = Get-ADUser -Identity Admin -Server $ChildDomain
Start-Sleep -Seconds 30
`$Group = Get-ADGroup -Identity "Enterprise Admins"
Add-ADGroupMember -Identity `$Group -Members `$User
`$Group = Get-ADGroup -Identity "Administrators"
Add-ADGroupMember -Identity `$Group -Members `$User
`$Group = Get-ADGroup -Identity "Domain Admins" -Server $ChildDomain
Add-ADGroupMember -Identity `$Group -Members `$User
"@
        }
        )
    };
"ROOTDC02"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the second Domain Controller for the domain $Rootdomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server and ROOTDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBRootDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.2 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSDomainController ``
-Credential `$Cred ``
-CreateDnSDelegation:`$false ``
-DomainName $RootDomain ``
-InstallDns:`$false ``
-DatabasePath "C:\Windows\NTDS" ``
-SYSVOLPath "C:\Windows\SYSVOL" ``
-LogPath "C:\Windows\NTDS" ``
-NoRebootOnCompletion:`$false ``
-Force:`$true ``
-SafeModeAdministratorPassword `$Cred.Password
"@
        };
    AdditionalScripts=@(
    @{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@"
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

`$Policy = New-WBPolicy
Add-WBSystemState -Policy `$Policy
Add-WBBareMetalRecovery -Policy `$Policy
Set-WBVssBackupOptions -Policy `$Policy -VssCopyBackup
`$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy `$Policy -Target `$Backuplocation
Set-WBSchedule -Policy `$Policy -Schedule 01:00
Start-WBBackup -Policy `$policy
"@
        }
        )
    };
"CHILDDC01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the first Domain Controller for the domain $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server and ROOTDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBRootDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.11 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

`$params = @{
    Credential = `$Cred
    NewDomainName = "$NBChildDomain"
    ParentDomainName = "$RootDomain"
    InstallDNS = `$false
    CreateDNSDelegation = `$false
    DomainMode = "WinThreshold" 
    DatabasePath = "C:\Windows\NTDS"
    SYSVOLPath = "C:\Windows\SYSVOL"
    LogPath = "C:\Windows\NTDS"
    NoRebootOnCompletion = `$false
    Force = `$true
    SafeModeAdministratorPassword = `$Cred.Password
}
Install-ADDSDomain @params
"@
        };
    AdditionalScripts=@(
    @{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@"
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

`$Policy = New-WBPolicy
Add-WBSystemState -Policy `$Policy
Add-WBBareMetalRecovery -Policy `$Policy
Set-WBVssBackupOptions -Policy `$Policy -VssCopyBackup
`$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy `$Policy -Target `$Backuplocation
Set-WBSchedule -Policy `$Policy -Schedule 01:00
Start-WBBackup -Policy `$policy
"@
        }
        )
    };
"CHILDDC02"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the second Domain Controller for the domain $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.12 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSDomainController ``
-Credential `$Cred ``
-CreateDnSDelegation:`$false ``
-DomainName $ChildDomain ``
-InstallDns:`$false ``
-DatabasePath "C:\Windows\NTDS" ``
-SYSVOLPath "C:\Windows\SYSVOL" ``
-LogPath "C:\Windows\NTDS" ``
-NoRebootOnCompletion:`$false ``
-Force:`$true ``
-SafeModeAdministratorPassword `$Cred.Password
"@
        };
    AdditionalScripts=@(
    @{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@"
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

`$Policy = New-WBPolicy
Add-WBSystemState -Policy `$Policy
Add-WBBareMetalRecovery -Policy `$Policy
Set-WBVssBackupOptions -Policy `$Policy -VssCopyBackup
`$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy `$Policy -Target `$Backuplocation
Set-WBSchedule -Policy `$Policy -Schedule 01:00
Start-WBBackup -Policy `$policy
"@
        }
        )
    };
"DATA01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the backup-/webserver in $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.21 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName $ChildDomain -Restart -Credential `$Cred
"@

        };
    AdditionalScripts=@(
        @{
            Path="Install";
            Name="CreateBackupShare.ps1";
            Content=@"
New-Item -Path C:\Backup\ -ItemType Directory
`$Parameters = @{
    Name = 'Backup'
    Path = 'C:\Backup'
    ChangeAccess = "$NBChildDomain\Domain Admins","$NBChildDomain\Domain Controllers","$NBRootDomain\Domain Admins","$NBRootDomain\Domain Controllers"
}
New-SmbShare @Parameters
Grant-SmbShareAccess -Name "Backup" -AccountName "Everyone" -AccessRight Read

"@
        }
        @{
            Path="Install";
            Name="CreateHTTPCDP.ps1";
            Content=@"
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

Install-WindowsFeature Web-Mgmt-Service
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server\ -PSProperty EnableRemoteManagement -Value 1
Set-Service WMSVC -StartupType Automatic
Start-Service -Name WMSVC

New-Item -Path C:\PKI\ -ItemType Directory
`$Parameters = @{
    Name = 'PKI'
    Path = 'C:\PKI'
    ChangeAccess = "$NBChildDomain\Domain Admins","$NBChildDomain\Cert Publishers"
}
New-SmbShare @Parameters
Grant-SmbShareAccess -Name "Backup" -AccountName "Everyone" -AccessRight Read

New-Website -Name "PKI" -Port 80 -HostHeader ("$ChildDomain") -PhysicalPath "C:\PKI"
"@
        }
        )
    };
"MGMT01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016GUI.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the management server in $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.22 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name RSAT-AD-Tools,GPMC,RSAT-ADCS-Mgmt,RSAT-DNS-Server,Web-Mgmt-Tools

Add-Computer -DomainName $ChildDomain -Restart -Credential `$Cred

"@

        };
    FilesToCopy=@(
    @{
            Path="Install";
            Name="AdExplorer.zip";
            Source="C:\HyperV\ADRES\Files\Tools\AdExplorer.zip"},
    @{
            Path="Install";
            Name="AdInsight.zip";
            Source="C:\HyperV\ADRES\Files\Tools\AdInsight.zip"},
    @{
            Path="Install";
            Name="ADRestore.zip";
            Source="C:\HyperV\ADRES\Files\Tools\ADRestore.zip"},
    @{
            Path="Install";
            Name="ProcessExplorer.zip";
            Source="C:\HyperV\ADRES\Files\Tools\ProcessExplorer.zip"},
    @{
            Path="Install";
            Name="ProcessMonitor.zip";
            Source="C:\HyperV\ADRES\Files\Tools\ProcessMonitor.zip"},
    @{
            Path="Install";
            Name="PSTools.zip";
            Source="C:\HyperV\ADRES\Files\Tools\PSTools.zip"},
    @{
            Path="Install";
            Name="Windows System Image Manager-x86_en-us.msi";
            Source="C:\HyperV\ADRES\Files\Tools\Windows System Image Manager-x86_en-us.msi"},
    @{
            Path="Install";
            Name="SSMS-Setup-ENU.exe";
            Source="C:\HyperV\ADRES\Files\Tools\SSMS-Setup-ENU.exe"}
    )
    };
"CLIENT01"=@{
    BaseDisc="C:\HyperV\ADRES\11\Base11.vhdx";
    Memory=4GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\11\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the client in $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.31 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName $ChildDomain -Restart -Credential `$Cred

"@

        };
    AdditionalScripts=@(
    @{
            Path="Install";
            Name="CreateVirtualSmartCard.txt";
            Content=@"
tpmvscmgr.exe create /name TestVSC /pin default /adminkey random /generate
"@
        }
        );
    FilesToCopy=@(
    @{
            Path="Install";
            Name="VSCodeUserSetup-x64-1.108.0.exe";
            Source="C:\HyperV\ADRES\Files\Tools\VSCodeUserSetup-x64-1.108.0.exe"},
    @{
            Path="Install";
            Name="powershell-2025.4.0.vsix";
            Source="C:\HyperV\ADRES\Files\Tools\powershell-2025.4.0.vsix"},
    @{
            Path="Install";
            Name="Anaconda3-2025.12-1-Windows-x86_64.exe";
            Source="C:\HyperV\ADRES\Files\Tools\Anaconda3-2025.12-1-Windows-x86_64.exe"},
    @{
            Path="Install";
            Name="ProcessExplorer.zip";
            Source="C:\HyperV\ADRES\Files\Tools\ProcessExplorer.zip"},
    @{
            Path="Install";
            Name="ProcessMonitor.zip";
            Source="C:\HyperV\ADRES\Files\Tools\ProcessMonitor.zip"},
    @{
            Path="Install";
            Name="PSTools.zip";
            Source="C:\HyperV\ADRES\Files\Tools\PSTools.zip"},
    @{
            Path="Install";
            Name="Windows System Image Manager-x86_en-us.msi";
            Source="C:\HyperV\ADRES\Files\Tools\Windows System Image Manager-x86_en-us.msi"}
    )
    };
"ENTRA01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016GUI.vhdx";
    Memory=4GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the entra connect server in $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.23 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName $ChildDomain -Restart -Credential `$Cred

"@

        };
    FilesToCopy=@(
    @{
            Path="Install";
            Name="AzureADConnect.msi";
            Source="C:\HyperV\ADRES\Files\Tools\AzureADConnect.msi"}
    )
    };
"CA01"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@"
Write-Host "This will install the certificate authority in $ChildDomain"
Read-Host -Prompt "Press Enter to continue only after the DNS Server, ROOTDC01 and CHILDDC01 are configured."
`$Cred = Get-Credential -Message "Please enter the password" -UserName $NBChildDomain\Administrator 

`$Adapter = Get-NetAdapter -Physical | Where-Object {`$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias `$Adapter.Name -IPAddress 10.0.0.24 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias `$Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName $ChildDomain -Restart -Credential `$Cred

"@

        };
    AdditionalScripts=@(
        @{
            Path="Install";
            Name="capolicy.inf";
            Content=@'
[Version]
Signature = "$Windows NT$"
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod="Years"
RenewalValidityUnits=5
LoadDefaultTemplates = 0
AlternateSignatureAlgorithm = 0
'@
        },
        @{
            Path="Install";
            Name="ConfigureCertificateAuthority.txt";
            Content=@"
Certutil -setreg CA\CRLPeriodUnits 2 
Certutil -setreg CA\CRLPeriod "Weeks" 

Certutil -setreg CA\CRLOverlapUnits 1 
Certutil -setreg CA\CRLOverlapPeriod "Weeks" 

Certutil -setreg CA\CRLDeltaPeriodUnits 0 
Certutil -setreg CA\CRLDeltaPeriod "Hours" 

certutil -setreg CA\CRLDeltaOverlapUnits 0
certutil -setreg CA\CRLDeltaOverlapPeriod "Hours"	

Certutil -setreg CA\ValidityPeriodUnits 2 
Certutil -setreg CA\ValidityPeriod "Years" 

Certutil -setreg CA\AuditFilter 127

certutil -setreg CA\CACertPublicationURLs "1:%windir%\system32\CertSrv\CertEnroll\%3%4.crt\n2:http://pki.$ChildDomain/aia/%3%4.crt"
certutil -setreg CA\CRLPublicationURLs "65:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl\n6:http://pki.$ChildDomain/crl/%3%8%9.crl\n"

auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

net stop certsvc && net start certsvc
certutil –crl

"@
        },
        @{
            Path="Install";
            Name="InstallCertificateAuthority.ps1";
            Content=@'

Install-WindowsFeature ADCS-Cert-Authority,RSAT-ADDS-Tools

Copy-Item -Path C:\install\capolicy.inf -Destination c:\Windows\capolicy.inf

Install-AdcsCertificationAuthority `
-CACommonName SECURECA01 `-CAType EnterpriseRootCA `
-CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
-HashAlgorithmName SHA512 `
-KeyLength 4096 `
-ValidityPeriod Years `
-ValidityPeriodUnits 5
'@
        },
        @{
            Path="Install";
            Name="CreateTemplate.txt";
            Content=@"
ldifde -i -f C:\Install\kerberosoid.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v
ldifde -i -f C:\Install\kerberos.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v

ldifde -i -f C:\Install\webserveroid.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v
ldifde -i -f C:\Install\webserver.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v

ldifde -i -f C:\Install\smartcardoid.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v
ldifde -i -f C:\Install\smartcard.ldf -k -c "RootDomain" "$RootDomainDN" -j C:\Install -v

"@
        }
        );
    FilesToCopy=@(
    @{
            Path="Install";
            Name="kerberos.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\kerberos.ldf"},
    @{
            Path="Install";
            Name="kerberosoid.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\kerberosoid.ldf"},
    @{
            Path="Install";
            Name="smartcard.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\smartcard.ldf"},
    @{
            Path="Install";
            Name="smartcardoid.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\smartcardoid.ldf"},
    @{
            Path="Install";
            Name="webserver.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\webserver.ldf"},
    @{
            Path="Install";
            Name="webserveroid.ldf";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\webserveroid.ldf"},
    @{
            Path="Install";
            Name="createoid.ps1";
            Source="C:\HyperV\ADRES\Files\Certificate Templates\createoid.ps1"}
    )
    };
"ROOTDR"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Restore";
    Path="C:\HyperV\ADRES";
    DVD="C:\HyperV\Windows_Server_2016.iso";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml"
    };
"CHILDDR"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Restore";
    Path="C:\HyperV\ADRES";
    DVD="C:\HyperV\Windows_Server_2016.iso";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml"
    };
"DNSDR"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;
    Switch="Restore";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml"
    }
}


$LABConfig.Keys | ForEach-Object {
    $VMName = $_
    $VMPath = "{0}\{1}" -f $VMConfig.Path,$VMName
    New-Item -Path $VMPath -ItemType Directory -Force
    $VMConfig = $LABConfig[$VMName]
    $VHDPath = "{0}\{1}.vhdx" -f $VMPath,$VMName
    New-VHD -ParentPath $VMConfig.BaseDisc -Path $VHDPath -Differencing 

    New-VM `
    -Name $VMName `
    -MemoryStartupBytes $VMConfig.Memory `
    -BootDevice VHD `
    -VHDPath $VHDPath `
    -Path $VMConfig.Path `
    -Generation 2 `
    -Switch $VMConfig.Switch

    Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
    Enable-VMTPM -VMName $VMName
    
    Set-VMProcessor -VMName $VMName -Count $VMConfig.CPU

    if($VMConfig.DVD)
    {
        Add-VMDvdDrive -VMName $VMName -Path $VMConfig.DVD
    }

    $VMDisk = Mount-VHD -Path $VHDPath -Passthru | Get-Disk 
    $VMVolume = $VMDisk | Get-Partition | Get-Volume
    $VMVolume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $DestinationFile = ("{0}:\Windows\Panther\unattend.xml" -f $_.DriveLetter)
        Copy-Item -Path $VMConfig.UnattendFile -Destination $DestinationFile
        $UnattendConfig = Get-Content -Path $DestinationFile
        $UnattendConfig = $UnattendConfig -replace "SYSNAMETEMP",$VMName
        $UnattendConfig | Set-Content $DestinationFile
        if($VMConfig.InstallScript)
        {
            $InstallScriptFileName = ("{0}:\{1}\{2}" -f $_.DriveLetter,$VMConfig.InstallScript.Path,$VMConfig.InstallScript.Name)
            New-Item -Path ("{0}:\{1}" -f $_.DriveLetter,$VMConfig.InstallScript.Path) -Name $VMConfig.InstallScript.Name -ItemType File -Force
            Set-Content -Path $InstallScriptFileName -Value $VMConfig.InstallScript.Content -Force
        }
        if($VMConfig.AdditionalScripts)
        {
            foreach($Script in $VMConfig.AdditionalScripts)
            {
                $ScriptFileName = ("{0}:\{1}\{2}" -f $_.DriveLetter,$Script.Path,$Script.Name)
                New-Item -Path ("{0}:\{1}" -f $_.DriveLetter,$Script.Path) -Name $Script.Name -ItemType File -Force
                Set-Content -Path $ScriptFileName -Value $Script.Content -Force
            }
        }
        if($VMConfig.FilesToCopy)
        {
            foreach($File in $VMConfig.FilesToCopy)
            {
                if(!(Test-Path -Path ("{0}:\{1}" -f $_.DriveLetter,$File.Path)))
                {
                    New-Item -Path ("{0}:\{1}" -f $_.DriveLetter,$File.Path) -ItemType Directory -Force
                }
                $DestFileName = ("{0}:\{1}\{2}" -f $_.DriveLetter,$File.Path,$File.Name)
                Copy-Item -Path $File.Source -Destination $DestFileName -Force
            }
        }
    }
    Dismount-VHD -DiskNumber $VMDisk.DiskNumber
}

