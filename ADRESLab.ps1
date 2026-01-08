$LABConfig = @{
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.1 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
-CreateDnSDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "ice.corp.com" `
-DomainNetbiosName "ice" `
-ForestMode "WinThreshold" `
-InstallDns:$false `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
'@
        };
    AdditionalScripts=@(@{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@'
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

$Policy = New-WBPolicy
Add-WBSystemState -Policy $Policy
Add-WBBareMetalRecovery -Policy $Policy
Set-WBVssBackupOptions -Policy $Policy -VssCopyBackup
$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy $Policy -Target $Backuplocation
Set-WBSchedule -Policy $Policy -Schedule 01:00
Start-WBBackup -Policy $policy
'@
        })
    };
"ROOTDC02"=@{
    BaseDisc="C:\HyperV\ADRES\2016\Base2016Core.vhdx";
    Memory=2GB;Switch="Intern";
    Path="C:\HyperV\ADRES";
    CPU=2;
    UnattendFile="C:\HyperV\ADRES\2016\unattend.xml";
    InstallScript=@{
            Path="Install";
            Name="Setup.ps1";
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.2 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSDomainController `
-Credential (Get-Credential ice\Administrator) `
-CreateDnSDelegation:$false `
-DomainName ice.corp.com `
-InstallDns:$false `
-DatabasePath "C:\Windows\NTDS" `
-SYSVOLPath "C:\Windows\SYSVOL" `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-Force:$true
'@

        };
    AdditionalScripts=@(@{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@'
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

$Policy = New-WBPolicy
Add-WBSystemState -Policy $Policy
Add-WBBareMetalRecovery -Policy $Policy
Set-WBVssBackupOptions -Policy $Policy -VssCopyBackup
$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy $Policy -Target $Backuplocation
Set-WBSchedule -Policy $Policy -Schedule 01:00
Start-WBBackup -Policy $policy
'@
        })
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.11 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

$params = @{
    Credential = (Get-Credential ice\Administrator)
    NewDomainName = "hq"
    ParentDomainName = "ice.corp.com"
    InstallDNS = $false
    CreateDNSDelegation = $false
    DomainMode = "WinThreshold" 
    DatabasePath = "C:\Windows\NTDS"
    SYSVOLPath = "C:\Windows\SYSVOL"
    LogPath = "C:\Windows\NTDS"
    NoRebootOnCompletion = $false
    Force = $true
}
Install-ADDSDomain @params
'@

        };
    AdditionalScripts=@(@{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@'
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

$Policy = New-WBPolicy
Add-WBSystemState -Policy $Policy
Add-WBBareMetalRecovery -Policy $Policy
Set-WBVssBackupOptions -Policy $Policy -VssCopyBackup
$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy $Policy -Target $Backuplocation
Set-WBSchedule -Policy $Policy -Schedule 01:00
Start-WBBackup -Policy $policy
'@
        })
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.12 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSDomainController `
-Credential (Get-Credential hq\Administrator) `
-CreateDnSDelegation:$false `
-DomainName hq.ice.corp.com `
-InstallDns:$false `
-DatabasePath "C:\Windows\NTDS" `
-SYSVOLPath "C:\Windows\SYSVOL" `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-Force:$true
'@

        };
    AdditionalScripts=@(@{
            Path="Install";
            Name="CreateBackupSchedule.ps1";
            Content=@'
Install-WindowsFeature Windows-Server-Backup -IncludeAllSubFeature -IncludeManagementTools

$Policy = New-WBPolicy
Add-WBSystemState -Policy $Policy
Add-WBBareMetalRecovery -Policy $Policy
Set-WBVssBackupOptions -Policy $Policy -VssCopyBackup
$Backuplocation = New-WBBackupTarget -NetworkPath "\\DATA01\Backup"
Add-WBBackupTarget -Policy $Policy -Target $Backuplocation
Set-WBSchedule -Policy $Policy -Schedule 01:00
Start-WBBackup -Policy $policy
'@
        })
    };
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
            Content=@'
Add-WindowsFeature DNS -IncludeManagementTools

$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.253 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Add-DnsServerPrimaryZone -Name "." -ZoneFile "root.dns"
Add-DnsServerPrimaryZone -Name "ice.corp.com" -ZoneFile "ice.corp.com.dns" -DynamicUpdate NonsecureAndSecure
Add-DnsServerResourceRecord -ZoneName ice.corp.com -IPv4Address 10.0.0.1 -A -Name .
Add-DnsServerPrimaryZone -Name "hq.ice.corp.com" -ZoneFile "hq.ice.corp.com.dns" -DynamicUpdate NonsecureAndSecure
Add-DnsServerResourceRecord -ZoneName hq.ice.corp.com -IPv4Address 10.0.0.11 -A -Name .
Add-DnsServerResourceRecord -ZoneName hq.ice.corp.com -IPv4Address 10.0.0.21 -A -Name pki

'@

        }
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.21 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName hq.ice.corp.com -Restart
'@

        };
    AdditionalScripts=@(
        @{
            Path="Install";
            Name="CreateBackupShare.ps1";
            Content=@'
New-Item -Path C:\Backup\ -ItemType Directory
$Parameters = @{
    Name = 'Backup'
    Path = 'C:\Backup'
    ChangeAccess = 'hq\Domain Admins','hq\Domain Controllers','ice\Domain Admins','ice\Domain Controllers'
}
New-SmbShare @Parameters
Grant-SmbShareAccess -Name "Backup" -AccountName "Everyone" -AccessRight Read

'@
        }
        @{
            Path="Install";
            Name="CreateHTTPCDP.ps1";
            Content=@'
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

New-Item -Path C:\PKI\ -ItemType Directory
$Parameters = @{
    Name = 'PKI'
    Path = 'C:\PKI'
    ChangeAccess = 'hq\Domain Admins','hq\Cert Publishers'
}
New-SmbShare @Parameters
Grant-SmbShareAccess -Name "Backup" -AccountName "Everyone" -AccessRight Read

New-Website -Name "PKI" -Port 80 -HostHeader "pki.ice.corp.com" -PhysicalPath "C:\PKI"
'@
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.22 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Install-WindowsFeature -Name RSAT-AD-Tools,GPMC,RSAT-ADCS-Mgmt,RSAT-DNS-Server,Web-Mgmt-Tools

Add-Computer -DomainName hq.ice.corp.com -Restart

'@

        }
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.23 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName hq.ice.corp.com -Restart

'@

        }
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
            Content=@'
$Adapter = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceAlias $Adapter.Name -IPAddress 10.0.0.24 -PrefixLength 24 -DefaultGateway 10.0.0.254
Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("10.0.0.253")

Add-Computer -DomainName hq.ice.corp.com -Restart

'@

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
            Content=@'
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

certutil -setreg CA\CACertPublicationURLs "1:%windir%\system32\CertSrv\CertEnroll\%3%4.crt\n2:http://pki.hq.ice.corp.com/aia/%3%4.crt"
certutil -setreg CA\CRLPublicationURLs "65:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl\n6:http://pki.hq.ice.corp.com/crl/%3%8%9.crl\n"

auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

net stop certsvc && net start certsvc
certutil –crl

'@
        },
        @{
            Path="Install";
            Name="InstallCertificateAuthority.ps1";
            Content=@'

Install-WindowsFeature ADCS-Cert-Authority

Install-AdcsCertificationAuthority `
-CACommonName COBASEC01 `
-CAType EnterpriseRootCA `
-CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
-HashAlgorithmName SHA512 `
-KeyLength 4096 `
-ValidityPeriod Years `
-ValidityPeriodUnits 5 
'@
        }
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
    }
    Dismount-VHD -DiskNumber $VMDisk.DiskNumber
}


