$Cred = Get-Credential -Message "Please enter a password for the administrator accounts" -UserName "Administrator"$Password = $Cred.GetNetworkCredential().Passwordif(!($HostGuard = Get-HgsGuardian -Name VMGuardian))
{
    $HostGuard = New-HgsGuardian -Name 'VMGuardian' -GenerateCertificates
}
$KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot$Config = Get-Content .\Config.json | ConvertFrom-Json

$Config.VMConfig | ForEach-Object { 
    $VMConfig = $_
    $VMName = $_.Name
    if(Get-VM -Name $VMName -ea SilentlyContinue)
    {
        "Attention: VM {0} already exists" -f $VMName
    }
    else
    {
        $VMPath = "{0}\{1}" -f $VMConfig.Path,$VMName
        $VHDPath = "{0}\{1}.vhdx" -f $VMPath,$VMName

        New-Item -Path $VMPath -ItemType Directory -Force
    
        New-VHD -ParentPath $VMConfig.BaseDisc -Path $VHDPath -Differencing

        New-VM `
        -Name $VMName `
        -MemoryStartupBytes ($VMConfig.Memory / 1) `
        -BootDevice VHD `
        -VHDPath $VHDPath `
        -Path $VMConfig.Path `
        -Generation 2 `

        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMName $VMName

        Set-VMProcessor -VMName $VMName -Count $VMConfig.CPUCount

        $VMConfig.NetworkInterfaces | ForEach-Object { 
            $Switch = $_
            $DisconnectedAdapter = Get-VMNetworkAdapter -VMName $VMName | Where-Object { !($_.SwitchName) } 
            if($DisconnectedAdapter) {
                $DisconnectedAdapter | Connect-VMNetworkAdapter -SwitchName $Switch
            }
            else {
                Add-VMNetworkAdapter -VMName $VMName -SwitchName $_
            }
        }

        if($VMConfig.DVD)
        {
            Add-VMDvdDrive -VMName $VMName -Path $VMConfig.DVD
        }

        $VMDisk = Mount-VHD -Path $VHDPath -Passthru | Get-Disk 
        $VMVolume = $VMDisk | Get-Partition | Get-Volume
        $VMVolume | Where-Object { $_.DriveLetter } | ForEach-Object {
            $OSDrive = $_.DriveLetter
            $DestinationFile = ("{0}:\Windows\Panther\unattend.xml" -f $OSDrive)
            Copy-Item -Path $VMConfig.unattend -Destination $DestinationFile
            $UnattendConfig = Get-Content -Path $DestinationFile
            $UnattendConfig = $UnattendConfig -replace "SYSNAMETEMP",$VMName
            $UnattendConfig | Set-Content $DestinationFile
            If($VMConfig.Scripts)
            {
                foreach($Script in $VMConfig.Scripts)
                {
                    $ScriptFileName = ("{0}:\{1}\{2}" -f $OSDrive,$Script.Path,$Script.Name)
                    New-Item -Path ("{0}:\{1}" -f $OSDrive,$Script.Path) -Name $Script.Name -ItemType File -Force

                    $ScriptContent = $Script.Content `                        -replace "<NBChildDomain>",$Config.NBChildDomain `                        -replace "<ChildDomain>",$Config.ChildDomain `                        -replace "<NBRootDomain>",$Config.NBRootDomain `                        -replace "<RootDomainDN>",$Config.RootDomainDN `                        -replace "<RootDomain>",$Config.RootDomain `                        -replace "<Password>",$Password

                    Set-Content -Path $ScriptFileName -Value $ScriptContent -Force
                }
            }
            if($VMConfig.FilesAndFolders)
            {
                foreach($Item in $VMConfig.FilesAndFolders)
                {
                    if(!(Test-Path -Path ("{0}:\{1}" -f $OSDrive,$Item.Path)))
                    {
                        New-Item -Path ("{0}:\{1}" -f $OSDrive,$Item.Path) -ItemType Directory -Force
                    }
                    $DestItemName = ("{0}:\{1}\{2}" -f $OSDrive,$Item.Path,$Item.Name)
                    Copy-Item -Path $Item.Source -Destination $DestItemName -Force -Recurse
                }
            }
        }
        Dismount-VHD -DiskNumber $VMDisk.DiskNumber
    }
}



