<#
.SYNOPSIS
script library
#>
# checkout https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md for more standards

Set-Alias Right Get-RightString
Set-Alias LogIt Add-LogEntry
Set-Alias GetArchivePath Get-ArchivePath
Set-Alias FindCollectionIndex Get-CollectionIndex
Set-Alias LogCheck Test-LogStatus
Set-Alias ArchiveCheck Test-ArchiveStatus

Add-Type -AssemblyName System.Web

function Get-RightString {
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

function Exists {
    Param(
        [string]$strFilePath
    )
    $bRetValue = $false;
	if ($strFilePath -ne "") {
		if ( (test-path -LiteralPath $strFilePath) -eq $true) {
			$bRetValue=$true
		}
	}
    return $bRetValue
}

function Test-LogStatus {
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

function Set-ArchivePath {
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
	if ($global:bArchiveOn){Write-Host ("Archive path is created {0}" -f $global:strPathArchive)}
}

function Set-DefaultArchive {
# set the archive path to default relative path
	[string]$strDefaultArchiveRoot = (get-item $PSScriptRoot).parent.FullName + "\Archive"
	Add-LogEntry "Setting archive to default location"
	Add-LogEntry "Default archive root is $strDefaultArchiveRoot"
	Set-ArchivePath $strDefaultArchiveRoot
}

function Test-ArchiveStatus {
	# check for archive setting and folder existance
	Add-LogEntry "Archive option check"
	if ($global:bArchiveOn -ne $true){
		# check if an archive location was requested
		if ( [string]::IsNullOrEmpty($global:strPathArchive)) {
			Add-LogEntry "Archive location not specified."
			Set-DefaultArchive
		}
		else {
			if ((Exists $global:strPathArchive) -eq $true) {
				# try to use the specified location if it exists
				Add-LogEntry ("Archive already on: {0}" -f $global:strPathArchive)
			}
			else {
				Add-LogEntry ("Archive directory, {0} is not reachable" -f $global:strPathArchive)
				Set-DefaultArchive
			}
		}
	} # end archive off if
	else {
		Add-LogEntry ("Archive on.{0}" -f $global:strPathArchive)
	}
} # end archivecheck function

function Get-ArchivePath {
	[string]$strArchResponse = "none"
	if ($global:bArchiveOn -eq $true){
		$strArchResponse = $global:strPathArchive
	}
	return $strArchResponse
}

function ConvertFrom-UxTime {
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

function urlencode {
	param(
		[Parameter(Mandatory=$true)]$TextToEncode
	)
	return [System.Web.HttpUtility]::URLEncode($TextToEncode);
}

function Get-PasswordFromSecureStringFile {
	param(
		[Parameter(Mandatory=$true)]$strPwFile,
		[Parameter(Mandatory=$false)]$Classic=$false
	)
	$UserPwSecured = Get-Content $strPwFile| ConvertTo-SecureString
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

function New-PasswordFile {
   # prompt for file location - Dialog may be more friendly
   $strNewPasswordFilePath = Read-Host -Prompt "Enter or paste path for the new password file"
   Write-Host "Saving password via secure string to $strNewPasswordFilePath"

   # remove the extra parameters from get-credential on older powershell
	if ( ($PSVersionTable.PsVersion.Major) -ge 5) {
		(get-credential -UserName "Password Saver" -Message "Only the password field is required.").password | convertFrom-SecureString | set-content $strNewPasswordFilePath
		Write-Host "Credential operation complete."
	}
   else {
		Write-Host "use a current version of PowerShell"
	}
}

function Send-AutomationCompletedMail {
	param(
		$MsgSubject
		,$MsgBody
		,$MsgRecipient = "bbadmin@stlcc.edu"
		,$MsgSender = "noreply-LMSAutomation@stlcc.edu"
	)
	# splat message arguments
	$argsMsg = @{}
	$argsMsg.Add("To",$MsgRecipient)
	$argsMsg.Add("From",$MsgSender)
	$argsMsg.Add("Subject","$MsgSubject")
	$argsMsg.Add("Body","$MsgBody")
	$argsMsg.Add("Attachments",$global:strPathLogFile)
	$argsMsg.Add("SmtpServer","smtp.stlcc.edu")	
	# use args to send message
	if (Get-Module -ListAvailable -Name PoshMailKit){
		Send-MKMailMessage @argsMsg
	}
	else {
		Send-MailMessage @argsMsg
	}
}

function Get-RandomText {
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

function Get-CollectionIndex {
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
