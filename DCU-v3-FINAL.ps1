function write-DRMMDiag ($messages) {
    Write-Host  '<-Start Diagnostic->'
    foreach ($Message in $Messages) { $Message }
    Write-Host '<-End Diagnostic->'
} 

function write-DRMMAlert ($message) {
    Write-Host '<-Start Result->'
    Write-Host "Alert=$message"
    Write-Host '<-End Result->'
}



# Requires Chocolatey
# Reboot disable switch doesn't seem to work 100%, so schedule after hours
# Some code borrowed from https://www.cyberdrain.com/monitoring-with-powershell-monitoring-dell-driver-updates-dcu-3-1/
# TODO:
# failure catching
# handling needed reboots
# CLI Reference: https://www.dell.com/support/manuals/en-us/command-update/dellcommandupdate_rg/dell-command-|-update-cli-commands?guid=guid-92619086-5f7c-4a05-bce2-0d560c15e8ed&lang=en-us
 
$dcu = "${env:ProgramFiles(x86)}\Dell\CommandUpdate"
$choco = "choco.exe"
$homepath = "c:\temp"
$dcuAlreadyInstalled=0
$minDcuVersion=4.6


 
if (-not (Test-Path "$homepath")) { mkdir "$homepath" | Out-Null }
if ((Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer -notlike 'Dell*') {
    Write-Host "System Manufacturer is not Dell, exiting"
    exit 0
}
$model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
if ($model -notlike '*OptiPlex*' -and $model -notlike '*Latitude*' -and $model -notlike '*Precision*' -and $model -notlike '*Venue*' -and $model -notlike '*XPS*'){
    Write-Host "Model not supported, installing Dell Update instead and exiting"
    &$choco upgrade dell-update -y --no-progress
    exit 0
}


#  LET'S DETERMINE IF DCU IS ALREADY INSTALLED
write-host "Checking whether DCU is installed"
$32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
# Empty array to store applications
$Apps = @()
# Retreive globally installed applications
$Apps += Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\$32BitPath"
$Apps += Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\$64BitPath"
$returnVal = @()
foreach ($app in $Apps) {
  if ($app.DisplayName -like "Dell Command*") {
	$version = (Get-ItemProperty $app.PsPath).DisplayVersion
	$dcu = (Get-ItemProperty $app.PsPath).InstallLocation
	$dcu = $dcu.TrimEnd('\')
	Write-Host "Dell software version: $version"
	write-host "DCU is installed at:  $dcu"
	$dcuAlreadyInstalled=1
  }
}

if ($dcuAlreadyInstalled -eq 0 -or $version -lt $minDcuVersion ) {
	# WE NEED TO INSTALL OR UPGRADE DCU
	
	# CHECK IF CHOCOLATEY IS INSTALLED
	$testchoco = powershell choco -v
	if(-not($testchoco)){
		Write-Output "Seems Chocolatey is not installed, installing now"
		Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	} else {
		write-host "Choco is installed.  Continuing..."
	}

# ONE MORE TEST TO MAKE SURE CHOCO INSTALLED
$testchoco = powershell choco -v
if(-not($testchoco)){
	# IT STILL ISN'T INSTALLED - BAIL OUT
	write-DRMMAlert "Chocolatey didn't install"
	exit 1
}


	write-host "using choco to install/upgrade DCU"
	# Install/Upgrade DCU
	&$choco upgrade dellcommandupdate -y --no-progress --force
	if ($LastExitCode -ne 0 ) {
		# UPGRADE ACTION FAILED - BAIL
		write-DRMMAlert "Chocolatey failed to install or upgrade Command Update"
		write-DRMMDiag $LastExitCode
		exit 1
	}
	
	
} 
 

 
# See what updates are available
# Start-Process "$($dcu)\dcu-cli.exe" -ArgumentList "/scan -report=$homepath" -Wait
write-host "DCU is running the initial scan"
& "$dcu\dcu-cli.exe" /scan -report="$homepath"
if ($LastExitCode -notin (0,500)) {
	# SCAN ACTION FAILED - BAIL
	write-DRMMAlert "Command Update Failed to Scan"
	write-DRMMDiag $LastExitCode
	exit 1
}
	

write-host "exit code from initial scan is $LastExitCode"
$scanExitCode = $LastExitCode

[xml]$XMLReport = get-content "$homepath\DCUApplicableUpdates.xml"
 
# Delete report because we don't need it anymore, and sometimes fails to overwrite
Remove-Item "$homepath\DCUApplicableUpdates.xml" -Force
 
$AvailableUpdates = $XMLReport.updates.update
$BIOSUpdates        = ($XMLReport.updates.update | Where-Object {$_.type -eq "BIOS"}).name.Count
$ApplicationUpdates = ($XMLReport.updates.update | Where-Object {$_.type -eq "Application"}).name.Count
$DriverUpdates      = ($XMLReport.updates.update | Where-Object {$_.type -eq "Driver"}).name.Count
$FirmwareUpdates    = ($XMLReport.updates.update | Where-Object {$_.type -eq "Firmware"}).name.Count
$OtherUpdates       = ($XMLReport.updates.update | Where-Object {$_.type -eq "Other"}).name.Count
$PatchUpdates       = ($XMLReport.updates.update | Where-Object {$_.type -eq "Patch"}).name.Count
$UtilityUpdates     = ($XMLReport.updates.update | Where-Object {$_.type -eq "Utility"}).name.Count
$UrgentUpdates      = ($XMLReport.updates.update | Where-Object {$_.Urgency -eq "Urgent"}).name.Count
Write-Host "BIOS Updates: $BIOSUpdates"
Write-Host "Application Updates: $ApplicationUpdates"
Write-Host "Driver Updates: $DriverUpdates"
Write-Host "Firmware Updates: $FirmwareUpdates"
Write-Host "Other Updates: $OtherUpdates"
Write-Host "Patch Updates: $PatchUpdates"
Write-Host "Utility Updates: $UtilityUpdates"
Write-Host "Urgent Updates: $UrgentUpdates"

 
# Exit code 500 means no updates found, exit 0 so script doesn't fail
if ($LastExitCode -eq 500) {
	#  NO UPDATES FOUND
	$UpdatesFound = "NO"
} else {
	#  UPDATES ARE FOUND.  LET'S APPLY THEM
	$UpdatesFound = "YES"
    Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom8" 2>$null
	 New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom8" -PropertyType String -Value 
	Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom9" 2>$null
    New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom9" -PropertyType String -Value "YES"
	# Find and Apply Updates
	& "$dcu\dcu-cli.exe" /applyupdates -updateSeverity="critical,recommended" -autoSuspendBitLocker=enable -reboot=disable
	
	if ($LastExitCode -ne 0 ) {
	# INSTALL ACTION FAILED - BAIL
	write-DRMMAlert "Command Update failed to install updates"
	write-DRMMDiag $LastExitCode
	exit 1
	}
	

}

#  DOCUMENT THE LAST TIME THIS SCRIPT HAS RUN
$currentTimeTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom8" 2>$null
New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom8" -PropertyType String -Value "$currentTimeTime"

Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom9" 2>$null
New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom9" -PropertyType String -Value $UpdatesFound


# REBOOT NO MATTER WHAT
restart-computer -force
exit 0