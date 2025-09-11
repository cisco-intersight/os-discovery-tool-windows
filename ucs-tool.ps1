<#PSScriptInfo

.VERSION 1.0.0

.GUID 199b5aa1-060e-4c45-a2f7-84fd5ec08e25

.AUTHOR Parthiban

.COMPANYNAME CISCO Systems

.COPYRIGHT Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.

.TAGS UCS, UCSTool, Intersight, Windows

.LICENSEURI https://github.com/cisco-intersight/os-discovery-tool-windows/blob/main/LICENSE

.PROJECTURI https://github.com/cisco-intersight/os-discovery-tool-windows

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 The Cisco Intersight ucs-tool is used to collect operating system and driver information for Hardware Compliance Validation. 

#>

#Requires -Version 7.2

param(
	[Parameter(Mandatory=$true)]
	[string]$ipmiutilpath
)

$file = "host-inv.yaml"
$templog = "temp.log"
$ucsToolVersion = "1.0.0"

# ---------------------------------------------------------
# -------------------- INVENTORY Block --------------------
# ---------------------------------------------------------

$storage_device_map = @{
    "SWRAID"         = "RAID";
    "AHCI"           = "ahci";
    "Modular Raid"   = "SAS RAID";
    "SAS HBA"        = "SAS HBA";
    "NVMe"           = "Flash";
    "QLogic"         = "Fibre Channel";
    "mpi3x"          = "mpi3x";
    "Ethernet"       = "Ethernet";
}

Function GetTAGPrefix {
    Return "intersight.server."
}

Function GetISO8601Time {
    return ((Get-Date).ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ss.fffZ" ))
}

Function GetOSDetails{
    Param([string]$hostname)
    Write-Host "[$hostname]: Retrieving OS Inventory..."
    $prefix = GetTAGPrefix
    $updateTS = GetISO8601Time

    $osClass = Get-CimInstance -ClassName Win32_OperatingSystem -Computer $hostname
    $osString = $osClass.caption
    $sp = $osClass.ServicePackMajorVersion
    $arch = $osClass.osarchitecture

    $vendor, $name, $type, $version, $release, $level = $osString.split(' ')
    $osInvCollection = New-Object System.Collections.ArrayList
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.updateTimestamp"
    $osInv | Add-Member -type NoteProperty -name Value -Value $updateTS
    $count = $osInvCollection.Add($osInv)

    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.vendor"
    $osInv | Add-Member -type NoteProperty -name Value -Value $vendor
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.name"
    $osInv | Add-Member -type NoteProperty -name Value -Value $name
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.arch"
    $osInv | Add-Member -type NoteProperty -name Value -Value $arch
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.type"
    $osInv | Add-Member -type NoteProperty -name Value -Value $type
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.kernelVersionString"
    if($release -ne "") {
        $osInv | Add-Member -type NoteProperty -name Value -Value $name" "$type" "$version" "$release
    }
    else
    {
        $osInv | Add-Member -type NoteProperty -name Value -Value $name" "$type" "$version
    }
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.releaseVersionString"
    $osInv | Add-Member -type NoteProperty -name Value -Value $release
    $count = $osInvCollection.Add($osInv)
    Clear-Variable -Name osInv
    $osInv = New-Object System.Object
    $osInv | Add-Member -type NoteProperty -name Key -Value $prefix"os.updateVersionString"
    if($sp -ne "0") {
        $osInv | Add-Member -type NoteProperty -name Value -Value "SP"$sp.ToString()
    }
    else
    {
        $osInv | Add-Member -type NoteProperty -name Value -Value ""
    }
    $count = $osInvCollection.Add($osInv)

    Return $osInvCollection
}

Function GetDriverDetails {
    Param([string]$hostname)
    $prefix = GetTAGPrefix
    $osInvCollection = New-Object System.Collections.ArrayList
    $driverList = New-Object Collections.Generic.List[string]
    $driverNameList = New-Object Collections.Generic.List[string]
    #vNIC details
    Write-host "[$hostname]: Retrieving Network Driver Inventory..."
    $netDevList = Get-CimInstance Win32_PnPSignedDriver -Computer $hostname | select DeviceName, FriendlyName, DriverVersion, Description, DeviceClass |
                    where {
                        $_.Devicename -like "*Ethernet*" -or
                        $_.Devicename -like "*FCoE*" -or
                        $_.Devicename -like "*LOM*" -or
                        $_.Devicename -like "*Intel(R) i350*" -or
                        $_.devicename -like "*I710*" -or
                        $_.devicename -like "*XXV710*" -or
                        $_.devicename -like "*XL710*" -or
                        $_.devicename -like "*X710*" -or
                        $_.devicename -like "*V710*" -or
                        $_.devicename -like "*X550*" -or
                        $_.devicename -like "*X540*" -or
                        $_.devicename -like "*X520*" -or
                        $_.devicename -like "*X557*" -or
                        $_.devicename -like "*I226*" -or
                        $_.devicename -like "*I225*" -or
                        $_.devicename -like "*I350*" -or
                        $_.devicename -like "*I210*" -or
                        $_.devicename -like "*E810*" -or
                        $_.Devicename -like "*Nvidia*" -or
                        $_.Devicename -like "*Mellanox*"
                    }
    $devcount = 0

    foreach ($netdev in $netDevList) {
        $key = $prefix+"os.driver."+$devcount+".name"
        $osInv = New-Object System.Object
        $osInv | Add-Member -type NoteProperty -name Key -Value $key
        if($netdev.DeviceName -like "*Ethernet*") {
            $netdrivername = (Get-CimInstance -class "Win32_NetworkAdapter" -namespace "root\CIMV2" -ComputerName $hostname) | select Name, MACAddress, ServiceName |
                    where { $_.Name -eq $netdev.FriendlyName -and $_.MACAddress}

            if($netdrivername.ServiceName -eq "ENIC") {
                $osInv | Add-Member -type NoteProperty -name Value -Value "enic"
            }
            elseif($netdrivername.ServiceName -eq "NENIC")
            {
                $osInv | Add-Member -type NoteProperty -name Value -Value "nenic"
            }
            elseif($netdrivername.ServiceName)
            {
                $osInv | Add-Member -type NoteProperty -name Value -Value $netdrivername.ServiceName
            }
            else
            {
                continue
            }
        }
        elseif($netdev.DeviceName -like "*FCoE*")
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value "fnic"
        }
        elseif(($netdev.DeviceName -like "*Intel(R) i350*") -or
               ($netdev.DeviceName -like "*I710*") -or
               ($netdev.DeviceName -like "*XXV710*") -or
               ($netdev.DeviceName -like "*XL710*") -or
               ($netdev.DeviceName -like "*X710*") -or
               ($netdev.DeviceName -like "*V710*") -or
               ($netdev.DeviceName -like "*X550*") -or
               ($netdev.DeviceName -like "*X540*") -or
               ($netdev.DeviceName -like "*X520*") -or
               ($netdev.DeviceName -like "*X557*") -or
               ($netdev.DeviceName -like "*I226*") -or
               ($netdev.DeviceName -like "*I225*") -or
               ($netdev.DeviceName -like "*I350*") -or
               ($netdev.DeviceName -like "*I210*") -or
               ($netdev.DeviceName -like "*E810*") -or 
               ($netdev.DeviceName -like "*Mellanox*") -or
               ($netdev.DeviceName -like "*LOM*"))
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value "Ethernet"
        }
        elseif($netdev.DeviceName -like "*Nvidia*" -and $netdev.DeviceClass -eq "NET")
        {
            $netdrivername = (Get-CimInstance -class "Win32_NetworkAdapter" -namespace "root\CIMV2" -ComputerName $hostname) | select Name, MACAddress, ServiceName |
                    where { $_.Name -eq $netdev.FriendlyName -and $_.MACAddress}
            $osInv | Add-Member -type NoteProperty -name Value -Value $netdrivername.ServiceName
        }
        elseif($netdev.DeviceName -like "*Nvidia*" -and $netdev.DeviceClass -eq "DISPLAY")
        {
            Write-host "[$hostname]: NVIDIA GPU Detected, retrieving GPU inventory..."

            # Nvidia-smi will be installed either under 'Program Files' folder or the 'System32' folder in C drive
            $nvidiasmi =  Invoke-Command -ComputerName $hostname -ScriptBlock{Get-ChildItem -Path 'C:\Program Files\', 'C:\Windows\System32\DriverStore\' -Recurse -Include nvidia-smi.exe}

            if($nvidiasmi)
            {
                foreach($cmd in $nvidiasmi)
                {
                    # Determine if Graphics driver or compute driver is installed
                    $command = "'$cmd' --query-gpu=driver_model.current --format='csv,noheader'"
                    $mode = Invoke-Command -ComputerName $hostname -ScriptBlock ([ScriptBlock]::Create("& $command"))

                    if($mode -contains "WDDM")
                    {
                        Write-host "[$hostname]: NVIDIA Graphics Driver is installed"
                        $osInv | Add-Member -type NoteProperty -name Value -Value "nvidia(graphics)"
                    }
                    elseif($mode -contains "TCC")
                    {
                        Write-host "[$hostname]: NVIDIA Compute Driver is installed"
                        $osInv | Add-Member -type NoteProperty -name Value -Value "nvidia(compute)"
                    }
                    else
                    {
                        Write-Host -ForegroundColor Yellow "[$hostname]: NVIDIA GPU mode is unidentified. Skipping adding the driver information."
                    }

                    # avoid traversing multiple paths of nvidia-smi.exe
                    break
                }
            }
            else
            {
                Write-Host -ForegroundColor Yellow "[$hostname]: No NVIDIA GPU driver found"
            }

        }
        else
        {
            continue
        }
        if((!$driverList.Contains($osInv.Value)) -or (!$driverNameList.Contains($netdev.DeviceName))) {
            $driverList.Add($osInv.Value)
            $driverNameList.Add($netdev.DeviceName)
            $count = $osInvCollection.Add($osInv)
            Clear-Variable -Name osInv
            $osInv = New-Object System.Object
            $key = $prefix+"os.driver."+$devcount+".description"
            $osInv | Add-Member -type NoteProperty -name Key -Value $key
            $osInv | Add-Member -type NoteProperty -name Value -Value $netdev.Description
            $count = $osInvCollection.Add($osInv)
            Clear-Variable -Name osInv
            $osInv = New-Object System.Object
            $key = $prefix+"os.driver."+$devcount+".version"

            # Nvidia GPU driver version needs special reformatting
            if($netdev.DeviceName -like "*Nvidia*" -and $netdev.DeviceClass -eq "DISPLAY")
            {
                $osInv | Add-Member -type NoteProperty -name Key -Value $key

                # Last five digits in DriverVersion value is the actual Nvidia GPU Driver Version
                $nvidiaDriverVersion = $netdev.DriverVersion -replace '\.', ''
                $nvidiaDriverVersion = $nvidiaDriverVersion.Substring($nvidiaDriverVersion.Length - 5).Insert(3,".")

                $osInv | Add-Member -type NoteProperty -name Value -Value $nvidiaDriverVersion
            }
            else
            {
                $osInv | Add-Member -type NoteProperty -name Key -Value $key
                $osInv | Add-Member -type NoteProperty -name Value -Value $netdev.DriverVersion
            }

            $count = $osInvCollection.Add($osInv)
            $devcount = $devcount + 1
        }
    }

    #storage controller details:
    Write-host "[$hostname]: Retrieving Storage Driver Inventory..."
    $storageControllerList = Get-CimInstance Win32_PnPSignedDriver -Computer $hostname | select DeviceName, DriverVersion |
                    where {
                        $_.devicename -like "*RAID SAS*" -or
                        $_.devicename -like "*Compute RAID Controller*" -or
                        $_.devicename -like "*SAS RAID*" -or
                        $_.devicename -like "*SWRAID*" -or
                        $_.devicename -like "*AHCI*" -or
                        $_.devicename -like "*Modular Raid*" -or
                        $_.devicename -like "*NVMe*" -or
                        $_.devicename -like "*NVM Express*" -or
                        $_.devicename -like "*U.2*" -or
                        $_.devicename -like "*SAS HBA*" -or
                        $_.devicename -like "*S3260 Dual Raid*" -or
                        $_.devicename -like "*S3260 Dual Pass Through*" -or
                        $_.devicename -like "*QLogic*" -or
                        $_.devicename -like "*Cisco*" -or
                        $_.devicename -like "*Emulex*" -or
                        $_.devicename -like "*Intel(R) SSD*"
                    }

    foreach ($storageController in $storageControllerList) {
        $stdrivername = (Get-CimInstance -class "Win32_SCSIController" -namespace "root\CIMV2" -ComputerName $hostname) | select Name, DriverName |
                where { $_.Name -like $storageController.DeviceName }

        $key = $prefix+"os.driver."+$devcount+".name"
        Clear-Variable -Name osInv
        $osInv = New-Object System.Object
        $osInv | Add-Member -type NoteProperty -name Key -Value $key
        if(($storageController.DeviceName -like "*LSI*" -and
                $storageController.DeviceName -like "*Mega*") -or
                $storageController.DeviceName -like "*SAS RAID*" -or
                $storageController.DeviceName -like "*RAID SAS*" -or
                $storageController.DeviceName -like "*RAID Controller*")
        {
            if ($storageController.DeviceName -like "*Tri-Mode*")
            {
                $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["mpi3x"]
            }
            else
            {
                $osInv | Add-Member -type NoteProperty -name Value -Value $stdrivername.DriverName
            }
        }
        elseif($storageController.DeviceName -like "*AHCI*")
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["AHCI"]
        }
        elseif(($storageController.DeviceName -like "*Modular Raid*") -or
               ($storageController.DeviceName -like "*S3260 Dual Raid*"))
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["Modular Raid"]
        }
        elseif(($storageController.DeviceName -like "*SAS HBA*") -or
               ($storageController.DeviceName -like "*S3260 Dual Pass Through*"))
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["SAS HBA"]
        }
        elseif(($storageController.DeviceName -like "*NVMe*") -or
               ($storageController.DeviceName -like "*U.2*") -or
               ($storageController.DeviceName -like "*NVM Express*") -or
               ($storageController.DeviceName -like "*Intel(R) SSD*"))
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["NVMe"]
        }
        elseif($storageController.DeviceName -like "*SWRAID*")
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["SWRAID"]
        }
        elseif($storageController.DeviceName -like "*QLogic*")
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $storage_device_map["QLogic"]
        }
        elseif($storageController.DeviceName -like "*Emulex*")
        {
			if ($stdrivername.DriverName -is [System.Collections.IEnumerable])
			{
				$osInv | Add-Member -type NoteProperty -name Value -Value $stdrivername.DriverName[0]
			}
			else
			{
				$osInv | Add-Member -type NoteProperty -name Value -Value $stdrivername.DriverName
			}
        }
        # Ideally this condition should be sufficient to fetch driver name for storage controller
        # storageController DeviceName and $stdriverName.Name will be same so this condition will always make sure 
        # it fetches te correct driver name, Kept the previous condition as it to support backward compatibility
        elseif($storageController.DeviceName -like $stdrivername.Name)
        {
            $osInv | Add-Member -type NoteProperty -name Value -Value $stdrivername.DriverName
        }
        else
        {
            continue
        }


        if((!$driverList.Contains($osInv.Value)) -or (!$driverNameList.Contains($storageController.DeviceName))) {
            $driverList.Add($osInv.Value)
            $driverNameList.Add($storageController.DeviceName)
            $count = $osInvCollection.Add($osInv)
            Clear-Variable -Name osInv
            $osInv = New-Object System.Object
            $key = $prefix+"os.driver."+$devcount+".description"
            $osInv | Add-Member -type NoteProperty -name Key -Value $key
            $osInv | Add-Member -type NoteProperty -name Value -Value $storageController.DeviceName
            $count = $osInvCollection.Add($osInv)
            Clear-Variable -Name osInv
            $osInv = New-Object System.Object
            $key = $prefix+"os.driver."+$devcount+".version"
            $osInv | Add-Member -type NoteProperty -name Key -Value $key
            $driverversion = $storageController.DriverVersion
            $major, $minor, $version, $suffix = $driverversion.split(".")

            $driverversion = $major+"."+$minor+"."+$version+"."+$suffix
            $osInv | Add-Member -type NoteProperty -name Value -Value $driverversion

            $count = $osInvCollection.Add($osInv)
            $devcount = $devcount + 1
        }
    }

    Return $OsInvCollection
}

Function ProcessHostOsInventory {
    Param([object]$env, [string]$hostname)
    $osInvCollection = GetOSDetails $hostname
    $driverInvCollection = GetDriverDetails $hostname
    $combinedCollection = New-Object System.Collections.ArrayList
    $combinedCollection += $osInvCollection
    $combinedCollection += $driverInvCollection
    $osInvJson = ConvertTo-Json -Depth 2 @{ "Tags"=foreach ($item in $combinedCollection) {@{Key=$item.Key; Value=$item.Value}}}
    Return $combinedCollection
}

Function SaveInventory {
	$inventory = ProcessHostOsInventory -env $null -hostname "localhost"
	Write-Output "annotations:" | Out-File -FilePath $file
	foreach ($x in $inventory) {
		Write-Output " -kv:" | Out-File -FilePath $file -Append
		Write-Output "  key: $($x.Key.substring(18))" | Out-File -FilePath $file -Append
		Write-Output "  value: $($x.Value)" | Out-File -FilePath $file -Append
	}
    Write-Output " -kv:" | Out-File -FilePath $file -Append
	Write-Output "  key: os.ucsToolVersion" | Out-File -FilePath $file -Append
	Write-Output "  value: $ucsToolVersion" | Out-File -FilePath $file -Append
	Write-Output " -kv:" | Out-File -FilePath $file -Append
	Write-Output "  key: os.InvEndKey" | Out-File -FilePath $file -Append
	Write-Output "  value: InvEndValue" | Out-File -FilePath $file -Append
	
	#Remove Windows EOL characters and make inventory file *nix compliant
	((Get-Content $file) -join "`n") + "`n" | Set-Content -NoNewline $file

	#Script tested with max file size of 65535
	if ((Get-Item $file).Length -ge 65535) {
		Write-Host "Error!  host-inv.yaml filesize is too large, exiting.."
		break
	}
}

# ---------------------------------------------------------
# -------------------- IPMI Tool Block --------------------
# ---------------------------------------------------------

Function CheckIpmiUtilPath {
	Param([string]$ipmiutilpath)
	if (-not(Test-Path -Path $ipmiutilpath -PathType Leaf)) {
		try {
			$null = New-Item -ItemType File -Path $file -Force -ErrorAction Stop
		}
		catch {
			Write-Host "Error! IPMIutil binary not found at" $ipmiutilpath
			break
		}
	}
}

Function SendInventoryToIMC {
    $netfunction="0x36"
    $smodel = GetServerModel
    if ($smodel -eq "CAI-845A-M8") {
        $netfunction="0x34"
    }
	#Send IPMI command to delete host-inv.yaml off IMC
	$cmd = "cmd -d " + $netfunction + " 0x77 0x03 0x68 0x6f 0x73 0x74 0x2d 0x69 0x6e 0x76 0x2e 0x79 0x61 0x6d 0x6c"
	Start-Process -FilePath $ipmiutilpath -ArgumentList $cmd -Wait -WindowStyle hidden
	
	#Send IPMI command to get a file descriptor for host-inv.yaml from CIMC and save it to a file
	Start-Process -FilePath $ipmiutilpath -ArgumentList "cmd -d " + $netfunction + " 0x77 0x00 0x68 0x6f 0x73 0x74 0x2d 0x69 0x6e 0x76 0x2e 0x79 0x61 0x6d 0x6c" -Wait -RedirectStandardOutput $templog -WindowStyle hidden
	$filedescriptor = Get-Content $templog | Select -Index 4
	
	try{
		[int]$filedescriptor.Substring($filedescriptor.Length - 3) -ge 0
	}
	catch {
		Write-Host "Error! Cannot get file descriptor from IMC via IPMI, exiting.."
		break
	}
	
	$filedescriptor = "0x" + $filedescriptor.Substring($filedescriptor.Length - 3)
	Remove-Item $templog

	#Read in the inventory file created by OS Discovery Tool classes
	$content = Get-Content $file -AsByteStream
	
	#Convert file to hex and break into 40 byte chunks to send via IPMI, (add error handling in future to break on failure)
	$counter = 0 
	$payload = ""
	$filelocationcounter = 0
	$payloadlength = "0x28"
	Write-Host "Writing host inventory file to IMC"
	foreach ($byte in $content) {
		$counter += 1
		if ($counter -le 39){
			$payload += "0x" + '{0:X}' -f $byte + " "
		}
		else
		{
			$payload += "0x" + '{0:X}' -f $byte
			$filepointer = '{0:X8}' -f $filelocationcounter
			$filepointer = "0x" + $filepointer.tostring().substring(6,2) + " 0x" + $filepointer.tostring().substring(4,2) + " 0x" + $filepointer.tostring().substring(2,2) + " 0x" + $filepointer.tostring().substring(0,2)
			$cmd = "cmd -d " + $netfunction + " 0x77 0x02" + " " + $filedescriptor +  $payloadlength + " " +  $filepointer + " " + $payload
			Start-Process -FilePath $ipmiutilpath -ArgumentList $cmd -Wait -WindowStyle hidden
			$filelocationcounter += 40
			$counter = 0
			$payload = ""
		}
	}
	# Writing host inventory file last chunk to IMC
	$filepointer = '{0:X8}' -f $filelocationcounter
	$filepointer = "0x" + $filepointer.tostring().substring(6,2) + " 0x" + $filepointer.tostring().substring(4,2) + " 0x" + $filepointer.tostring().substring(2,2) + " 0x" + $filepointer.tostring().substring(0,2)
	$cmd = "cmd -d " + $netfunction + " 0x77 0x02" + " " + $filedescriptor +  "0x" + '{0:X}' -f $counter + " " +  $filepointer + " " + $payload
	Start-Process -FilePath $ipmiutilpath -ArgumentList $cmd -Wait -WindowStyle hidden

	# Closing IMC host-inv.yaml file descriptor
	$cmd = "cmd -d " + $netfunction + " 0x77 0x01 " + $filedescriptor
	Start-Process -FilePath $ipmiutilpath -ArgumentList $cmd -Wait -WindowStyle hidden
	Write-Host "Inventory file has been successfully written to IMC"
}

# ---------------------------------------------------------
# ---------------------- Utils Block ----------------------
# ---------------------------------------------------------
Function GetWindowHostSerial {
    $hostserial = (Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber).SerialNumber.ToString()
    Write-Host "Serial Number: $hostserial"
}

Function GetServerModel {
    $servermodel = (Get-CimInstance -ClassName Win32_ComputerSystem | select Model).Model
    return $servermodel
}

# ---------------------------------------------------------
# ---------------------- Main Block -----------------------
# ---------------------------------------------------------

# Check the given IPMIUtil binary exists or not.
CheckIpmiUtilPath -ipmiutilpath $ipmiutilpath

#Gather inventory and save it locally in host-inv.yaml file
$smodel = GetServerModel
Write-Host "Server Model: $smodel"
GetWindowHostSerial
SaveInventory

# Send the inventory file host-inv.yaml file to IMC.
SendInventoryToIMC