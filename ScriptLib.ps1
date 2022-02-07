<#
.SYNOPSIS
script library
Much of this is very old with some bad practices, only sharing in the event that parts are useful to others.
#>
<#
ToDo:
	Create a proper description for this file
	Create synopsis, description and parameter help for functions
# create aliases for original function names to updated conventional verb-noun names
# checkout https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md for more standards i haven't followed yet
#>
Set-Alias Right Get-RightString
Set-Alias GetTimestamp Get-LogTimestamp
Set-Alias SetDefaultLog New-DefaultLogFile
Set-Alias LogIt Add-LogEntry
Set-Alias GetArchivePath Get-ArchivePath
Set-Alias FindCollectionIndex Get-CollectionIndex
Set-Alias LogCheck Test-LogStatus
Set-Alias ArchiveCheck Test-ArchiveStatus
Set-Alias Convert-From-UxTime ConvertFrom-UxTime
Set-Alias UploadViaCurl Invoke-CurlUpload
Set-Alias ValidateTermCode Get-ValidTermcode
Set-Alias Get-Password-FromFile Get-PasswordFromSecureStringFile
Set-Alias FlatFileUrlBuilderByType Get-BbFlatFileUrl
Set-Alias SetDefaultArchivePath Set-DefaultArchive
Set-Alias SetArchivePath Set-ArchivePath
Set-Alias PwGen Get-RandomText

Add-Type -AssemblyName System.Web

function Get-RightString(){
	Param(
		[string]$SourceString
		,[uint16]$CharacterCount
	)
	if ($CharacterCount -ge $SourceString.length){
			return $SourceString
	}
	else {
		return $SourceString.substring($SourceString.length - $CharacterCount, $CharacterCount)
	}
}

function Get-LogTimestamp {
	$strTimestamp = get-date -uFormat %Y-%m-%d_%H.%M.%S
	$strTimestamp = "[" + $strTimestamp + "]"
	return $strTimestamp
}

function New-DefaultLogFile {
	# check for c:\logs
	[string]$strLogPrefix = ""
	[string]$strCLogs = $env:systemdrive + "\logs"
	if ( (Exists $strCLogs) -eq $false){
		mkdir $strCLogs | out-null
	}
	# structure log name
	if (!$global:LogPrefixFilename){
		$strLogPrefix = "PowerShellLog"
	}
	else {
		$strLogPrefix = $global:LogPrefixFilename
	}
	$global:strPathLogFile = $strCLogs + "\" + $strLogPrefix + "-" + (get-date -uformat %Y-%m-%d_%H%M).ToString() + ".log"
	Add-LogEntry "Default log created at $global:strPathLogFile"
}


function Add-LogEntry {
<#
.SYNOPSIS
	Adds a timestamped log entry to the globally configured log file
.PARAMETER strLogMsg
	message to be logged
#>
	Param(
		[string]$strLogMsg
	)
	$stamp=GetTimestamp
	add-content -path $global:strPathLogFile -value "$stamp $strLogMsg"
	write-verbose "$stamp$strLogMsg"
}

function Exists() {
    Param(
        [string]$strFilePath
    )
    $bRetValue = $false;
	if ($strFilePath -ne "") {
    if ( (test-path -LiteralPath $strFilePath) -eq $true) {
        $bRetValue=$true
    }}
    return $bRetValue
}


function Test-LogStatus() {
	<#
	.SYNOPSIS
		tests for the existance of the log setting and creates the file if needed.
	#>
	#check for log spefication
	$strPathLogFile=$LogFile
	if ( [string]::IsNullOrEmpty($strPathLogFile)) {
		# no log path specified, use default
		New-DefaultLogFile
	}
	# since the log path was specified, let's verify the path
	else {
		# if the file already exists, append with notation and move on
		if ((Exists $strPathLogFile) -eq $true){
			Add-LogEntry "..."
			Add-LogEntry "$global:LogPrefixFilename attempt."
		}
		else {
			write-host "checking log path parent"
			# get path parts
			$strLogPathInfo=$strPathLogFile.Split('\')
			$strLogPathFile=$strLogPathInfo[($strExtractFilePathInfo.Length - 1)]
			$strLogPathDir=$strPathLogFile.Replace("$strLogPathFile","")
			# make sure directory for specified path exists
			if ((Exists $strLogPathDir) -eq $false){
				# it doesn't, revert to default log setting
				New-DefaultLogFile
			}
		} # end file does not exist
	} # end specified log check
}

function Set-ArchivePath(){
	Param([string]$strNewArchivePath)
	$strNewArchivePath = $strNewArchivePath + "\" + (get-date -uformat %Y-%m-%d_%H%M).ToString()
	try {
		Add-LogEntry "Creating archive directory $strNewArchivePath"
		new-item -path $strNewArchivePath -itemType Directory -errorAction stop | out-null
		$global:strPathArchive = $strNewArchivePath
		$global:bArchiveOn = $true
	}
	catch {
		$errMsg = $_.Exception.Message
		Add-LogEntry $errMsg
		Add-LogEntry "could not create archive folder."
		Add-LogEntry "controller files will not be archived."
		$global:bArchiveOn = $false
	}
}

function Set-DefaultArchive(){
# set the archive path to default relative path
	[string]$strDefaultArchiveRoot = (get-item $PSScriptRoot).parent.FullName + "\Archive"
	Add-LogEntry "Setting archive to default location"
	Add-LogEntry "Default archive root is $strDefaultArchiveRoot"
	Set-ArchivePath $strDefaultArchiveRoot
}

function Test-ArchiveStatus{
	# check for archive setting and folder existance
	Add-LogEntry "Archive option check"
	if ($global:bArchiveOn -ne $true){
		# check if an archive location was requested
		if ( [string]::IsNullOrEmpty($ArchiveDirectory)) {
			Add-LogEntry "Archive location not specified."
			SetDefaultArchivePath
		}
		else {
			if ((Exists $ArchiveDirectory) -eq $true) {
				# try to use the specified location if it exists
				SetArchivePath $ArchiveDirectory
			}
			else {
				Add-LogEntry "Archive directory, $ArchiveDirectory is not reachable"
				SetDefaultArchivePath
			}
		}
	} # end archive off if
	else {
		Add-LogEntry "Archive on."
	}
} # end archivecheck function

function Get-ArchivePath(){
	[string]$strArchResponse = "none"
	if ($global:bArchiveOn -eq $true){
		$strArchResponse = $global:strPathArchive
	}
	return $strArchResponse
}

function ConvertFrom-UxTime() {
	param (
		[Parameter(Mandatory=$true)]$UnixTime
		,[Parameter(Mandatory=$false)]$TimeFormat=""
	)
	$EpochSeconds = $UnixTime / 1000
	$objTime = [TimeZone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($EpochSeconds))
	[string]$strHumanTime = ""
	 # examples from 1427964343362
	switch ($TimeFormat) {
		"logPrefix" {
			# [2015-04-02_03.45.43]
			$strHumanTime = get-date $objTime -uFormat [%Y-%m-%d_%H.%M.%S]
		}
		"utc" {
			# Thursday, April 02, 2015 8:45:43 AM
			$strHumanTime = $objTime.ToUniversalTime()
		}
		"date" {
			# 04/02/2015
			$strHumanTime = get-date $objTime -uFormat %x
		}
		default {
			# Thursday, April 02, 2015 3:45:43 AM
			$strHumanTime = $objTime
		}
	}
	return $strHumanTime
}

function urlencode() {
	param(
		[Parameter(Mandatory=$true)]$TextToEncode
	)
	return [System.Web.HttpUtility]::URLEncode($TextToEncode);
}

function Get-PasswordFromSecureStringFile {
	param(
		[Parameter(Mandatory=$true)]$strPasswordFile,
		[Parameter(Mandatory=$false)]$Classic=$false
	)
	$UserPwSecured = Get-Content $strPasswordFile| ConvertTo-SecureString
	<# old code - these two lines were entire function
	$UserPwBinaryString = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserPwSecured)
	$UserPwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($UserPwBinaryString)
	#>
    # determin if pwsh or powershell
    $psv = $PSVersionTable.PSVersion.Major
    $min = 7
    if ($psv -lt $min){
        $Classic = $true        
    }
    # run the parsing based on powershell env
    if ($Classic){
        $UserPwBinaryString = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserPwSecured)
        $UserPwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($UserPwBinaryString) 
    }
    else {
        $UserPwPlainText = ConvertFrom-SecureString -SecureString $UserPwSecured -AsPlainText
    }	
	return $UserPwPlainText
}

function Get-SecureStringFromSecureStringFile {
	param(
		[Parameter(Mandatory=$true)]$strPasswordFile
	)
	$PwSecured = Get-Content $strPasswordFile | ConvertTo-SecureString
	return $PwSecured
}

function New-PasswordFile {
   # prompt for file location - Dialog may be more friendly
   $strNewPasswordFilePath = Read-Host -Prompt "Enter or paste path for the new password file"
   Write-Host "Saving password via secure string to $strNewPasswordFilePath"

   # remove the extra parameters from get-credential on older powershell
	if ( ($PSVersionTable.PsVersion.Major) -ge 3) {
		(get-credential -UserName "Password Saver" -Message "Only the password field is required.").password | convertFrom-SecureString | set-content $strNewPasswordFilePath
	}
   else {
		(get-credential).password | convertFrom-SecureString | set-content $strNewPasswordFilePath
	}

   Write-Host "Credential operation complete."
}

function Send-AutomationCompletedMail() {
	param(
		$MsgSubject
		,$MsgBody
	)
	# splat message arguments
	$argsMsg = @{}
	$argsMsg.Add("to","genericadmin@instituion.edu")
	$argsMsg.Add("from","noreply-LMSAutomation@instituion.edu")
	$argsMsg.Add("subject","$MsgSubject")
	$argsMsg.Add("body","$MsgBody")
	$argsMsg.Add("Attachments",$global:strPathLogFile)
	$argsMsg.Add("smtpserver","smtp.fqdn")	
	# send notification of rewrite completion
	send-mailmessage @argsMsg 
}

function Invoke-CurlUpload() {
		Param (
		[string]$CurlAppFile
		,[string]$CurlUploadFile
		,[string]$CurlUploadUrl
		,[string]$CurlUsername
		,[string]$CurlPassword
		)
	  # create path for cURL output
	  #  -can't use log file because cURL output replaces entire contents of file with output.
	  # grab directory of current log file
	  $strLogDirectory = (get-item -literalpath "$global:strPathLogFile").Directory.FullName
	  $strPathCurlOutputFile = $strLogDirectory + "\cURLout.xml"

	  # build cURL arguments
		$CurlCreds = $CurlUsername + ":" + $CurlPassword
		# execute cURL
		& $CurlAppFile -o $strPathCurlOutputFile -H "Content-Type:text/plain" -u $CurlCreds --data-binary @$CurlUploadFile $CurlUploadUrl

		# read and log output
		$strResultCurl = get-content -path $strPathCurlOutputFile
		Add-LogEntry $strResultCurl
}

function Get-BbFlatFileUrl {
	Param (
		[string]$UrlType
	)
	$strUploadUrl=""
	$UrlType = $UrlType.ToLower();

	switch ($UrlType) {
		"coursestore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/course/store"
			break;
		}
		"coursetemplate" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/course/store"
			break;
		}
		"userstore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/person/store"
			break;
		}
		"userrefresh" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/person/refreshlegacy"
			break;
		}
		"enrollmentstore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/membership/store"
			break;
		}
		"enrollmentrefresh" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/membership/refreshlegacy"
			break;
		}
		"orgenrollstore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/organizationmembership/store"
			break;
		}
		"orgenrollrefresh" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/organizationmembership/refreshlegacy"
			break;
		} 
		"categorystore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/coursecategory/store "
			break;
		}
		"categorylink" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/coursecategorymembership/store"
			break;
		}
		"term" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/term/store"
			break;
		}
		"rolestore" {
			$strUploadUrl = "https://$BbSite/webapps/bb-data-integration-flatfile-BbInstanceId/endpoint/secondaryinstrole/store"
			break;
		}
		default {
			break;
		}
	}
	return $strUploadUrl
}

function Get-RandomText(){
	Param ([uint16]$intPasswordLength)
	# init return string
	$strPasswordText = ""

	for ($i=0;$i -lt $intPasswordLength;$i++){
		# mixed case      capital    lower       integer
		$PasswordRange = (65..90) + (97..122) + (48..57)
		# select random number from the range(s)
		[uint16]$PasswordPath = Get-Random -InputObject $PasswordRange
		# add the random character to the return string
		[string]$strPasswordText += [char]($PasswordPath)
	}
	return $strPasswordText
}

function Get-CollectionIndex() {
# obtain the index number for a search on specified field
	Param(
		$CollectionToSearch
		,$searchColumn
		,$searchValue
	)
	$intUserSearchResult = -1
	for ($n=0; $n -lt $CollectionToSearch.count; $n++) {
		if ($CollectionToSearch[$n].$searchColumn -eq $searchValue) {
			$intUserSearchResult = $n
		}
	}
	return $intUserSearchResult
}

function Get-ValidTermcode(){
    Param(
        [string]$strTermCode
    )
	$strTermYear="0"
	$strTermDesc="fail"

	if ($strTermCode.Length -eq 6) {
		$strTermYear = $strTermCode.substring(0,4)
		$strTermId = $strTermCode.substring(4,2)
		switch ($strTermId) {
			"10" {$strTermDesc = "Spring"}
			"20" {$strTermDesc = "Summer"}
			"30" {$strTermDesc = "Fall"}
			default{$strTermDesc="fail:Unknown"}
		}
		$strTermDesc = "$strTermYear $strTermDesc"
	}
	else {
		$strLen = $strTermCode.Length.ToString()
		$strTermDesc = "fail: Inappropriate length for Termcode.  $strTermCode is $strLen characters"
	}
	return $strTermDesc
}
function Get-BbRestToken {
    Param(
        [string]
        $BbRESTKey

        ,[string]
        $BbRESTSecret

        ,[string]
        $BbRESTHost
    )
    $TokenResult = @{}
    $TokenResult.TokenStatus = $false
	$TokenResult.TokenString = ""
	$TokenResult.TokenExpires = ""

    $creds="$($BbRESTKey):$($BbRESTSecret)"
	$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($creds))
	$basicAuthValue = "Basic $encodedCreds"
	$Headers = @{Authorization = $basicAuthValue}
	$strBody = "grant_type=client_credentials"
	$strUrl="https://" + $BbRESTHost + "/learn/api/public/v1/oauth2/token"
	$TokenArgs = @{}
	$TokenArgs.Add("Headers",$Headers)
	$TokenArgs.Add("URI",$strUrl)
	$TokenArgs.Add("Method", "POST")
	$TokenArgs.Add("ContentType",$RestContType)
    $TokenArgs.Add("Body",$strBody)
    try {
        $TokenResponse = Invoke-WebRequest @TokenArgs
        if ($TokenResponse.StatusCode)	{
            if ($TokenResponse.StatusCode -eq 200){
                $BbCurentToken = ConvertFrom-Json -InputObject $TokenResponse.Content
                $TokenResult.TokenStatus = $true
				$TokenResult.TokenString = $BbCurentToken.access_token
				$TokenResult.TokenExpires = (Get-Date).AddSeconds($BbCurentToken.expires_in)
            }
            else {
                $TokenResult.TokenStatus = $false
            }
        }
    }
    catch {
        $script:BbTokenStatus = $false
    }
    return $TokenResult
}
function Update-BbUserREST {
	Param(
		[string]
		$ObjectIdentifier

		,[string]
		$ObjectId

		,$UserPatch
		
		,[string]
		$BbRESTHost
		
		,[string]
		$BbRESTToken
	)
	switch ($ObjectIdentifier) {
		"eeid" { 
			$UrlUserUpdate = "https://" + $BbRESTHost + "/learn/api/public/v1/users/externalId:" + $ObjectId
			$UrlUserUpdate += "?fields=userName,name,contact"
			$jsonPatch = $UserPatch|ConvertTo-Json
			Invoke-RestMethod -Headers @{Authorization="Bearer $BbRESTToken"} -uri $UrlUserUpdate -Method PATCH -Body $jsonPatch -ContentType "application/json" -Verbose
		 }
		 "username" { 
			$UrlUserUpdate = "https://" + $BbRESTHost + "/learn/api/public/v1/users/userName:" + $ObjectId
			$UrlUserUpdate += "?fields=userName,name,contact"
			$jsonPatch = $UserPatch|ConvertTo-Json
			Invoke-RestMethod -Headers @{Authorization="Bearer $BbRESTToken"} -uri $UrlUserUpdate -Method PATCH -Body $jsonPatch -ContentType "application/json" -Verbose
		 }		 
		Default { 
			Write-Host "unhandled identifier"
		}
	}
}