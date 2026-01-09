$DomainSID = (Get-ADDomain).DomainSID.Value 
$oidComponent1 = $DomainSID -replace "S-1-5-21-","" -replace "-","."
$oidComponent2 = [System.Convert]::ToUInt32(([guid]::NewGuid().Guid -split "-")[0],16)
$customOID = "1.3.6.1.4.1.311.21.8.$oidComponent1.$oidComponent2"
$customOID

$CNComponent1 = [System.Convert]::ToUInt32(([guid]::NewGuid().Guid -split "-")[1],16)
$CNComponent2 = [guid]::NewGuid().Guid -replace "-",""
$CN = ("{0}.{1}" -f $CNComponent1,$CNComponent2).ToUpper()
$CN
