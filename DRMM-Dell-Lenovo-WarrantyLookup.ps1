##### Warranty Vendor API Keys
$DellClientID = "<YOUR-DELL-CLIENT-ID>"
$DellClientSecret = "<YOUR-DELL-CLIENT-SECRET>"
$ServiceTag=get-ciminstance win32_bios | Select -ExpandProperty SerialNumber
$Mfg= Get-CimInstance -ClassName Win32_ComputerSystem | Select -ExpandProperty Manufacturer
$Lenovo="LENOVO*"
$Dell="DELL*"
$today = Get-Date -Format yyyy-MM-dd

write-output ($Mfg )

switch -Wildcard ($Mfg) {
 $Lenovo{
    $APIURL = "https://warrantyapiproxy.azurewebsites.net/api/Lenovo?Serial=$ServiceTag"
    $WarReq = Invoke-RestMethod -Uri $APIURL -Method get
 
        $warlatest = $WarReq.EndDate | ForEach-Object { [datetime]$_ } | sort-object | select-object -last 1 
        $WarrantyState = if ($warlatest -le $today) { "Expired" } else { "OK" }
        $WarObj = [PSCustomObject]@{
            'Serial'                = $WarReq.Serial
            'Warranty Product name' = $WarReq.WarProduct
            'StartDate'             = [DateTime]($WarReq.StartDate)
            'EndDate'               = [DateTime]($WarReq.EndDate)
            'Warranty Status'       = $WarrantyState
        }
	$warStartDate=[DateTime]($WarReq.StartDate)
	$warStartDate=$warStartDate.ToShortDateString()
	$warEndDate=[DateTime]($WarReq.EndDate)
	$warEndDate=$warEndDate.ToShortDateString()
 }
 $Dell {
     $AuthURI = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
    if ($Global:TokenAge -lt (get-date).AddMinutes(-55)) { $global:Token = $null }
    If ($null -eq $global:Token) {
        $OAuth = "$global:DellClientID`:$global:DellClientSecret"
		$OAuth = "l78d0a875ac05d493d8c90b64456c17ff1:0197297bb4ff46a7908c26d30f9288ed"
        $Bytes = [System.Text.Encoding]::ASCII.GetBytes($OAuth)
        $EncodedOAuth = [Convert]::ToBase64String($Bytes)
        $headersAuth = @{ "authorization" = "Basic $EncodedOAuth" }
        $Authbody = 'grant_type=client_credentials'
        $AuthResult = Invoke-RESTMethod -Method Post -Uri $AuthURI -Body $AuthBody -Headers $HeadersAuth
        $global:token = $AuthResult.access_token
        $Global:TokenAge = (get-date)
    }
 
    $headersReq = @{ "Authorization" = "Bearer $global:Token" }
    $ReqBody = @{ servicetags = $ServiceTag }
    $WarReq = Invoke-RestMethod -Uri "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements" -Headers $headersReq -Body $ReqBody -Method Get -ContentType "application/json"
    $warlatest = $warreq.entitlements.enddate | sort-object | select-object -last 1 
    $WarrantyState = if ($warlatest -le $today) { "Expired" } else { "OK" }
    if ($warreq.entitlements.serviceleveldescription) {
        $WarObj = [PSCustomObject]@{
            'Serial'                = $SourceDevice
            'Warranty Product name' = $warreq.entitlements.serviceleveldescription -join "`n"
            'StartDate'             = (($warreq.entitlements.startdate | sort-object -Descending | select-object -last 1) -split 'T')[0]
            'EndDate'               = (($warreq.entitlements.enddate | sort-object | select-object -last 1) -split 'T')[0]
            'Warranty Status'       = $WarrantyState
            'Client'                = $Client
        }
		$warStartDate=(($warreq.entitlements.startdate | sort-object -Descending | select-object -last 1) -split 'T')[0]
		$warEndDate=(($warreq.entitlements.enddate | sort-object | select-object -last 1) -split 'T')[0]
    }
    else {
        $WarObj = [PSCustomObject]@{
            'Serial'                = $SourceDevice
            'Warranty Product name' = 'Could not get warranty information'
            'StartDate'             = $null
            'EndDate'               = $null
            'Warranty Status'       = 'Could not get warranty information'
            'Client'                = $Client
        }
    }
 }
 default {}
 
 }

Write-Output ($warStartDate)

    Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom6" 2>$null
    New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom6" -PropertyType String -Value "$warStartDate"
    Remove-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom7" 2>$null
    New-ItemProperty -Path HKLM:\SOFTWARE\CentraStage\ -Name "Custom7" -PropertyType String -Value "$warEndDate"
    return $WarObj