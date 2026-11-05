# not setting TLS can cause issues by using system default so always set preferred level
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
# add system.web component for url string manipulation
Add-Type -AssemblyName System.Web
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## configure in profile or task script after including this file/module
<#
$DirectoryDomain = "domain.tld"
$DirectoryUserPath = "OU=User Org Unit,DC=domain,DC=tld"
$DirectoryGroupPath = "OU=Groups Org Unit,DC=domain,DC=tld"
#>
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################

# ## ### #### ##### ###### ####### ########################################################################################
# ## Secrets functions
# ## ### #### ##### ###### ####### ########################################################################################

function New-AutomationTokenFile {
    try {
        # prompt for file location
        $NewPasswordFilePath = Read-Host -Prompt "Enter or paste path for the new token file"
        Write-Host "Saving token via secure string to $NewPasswordFilePath"
        # save the password text as a secure string to the path provided
        (get-credential -UserName "Token Saver" -Message "Only the password field is required.").password | convertFrom-SecureString | set-content $NewPasswordFilePath
        Out-Host "Token saved to file."
    }
    catch {
        <# Do this if an exception #>
    }
}

function Get-AutomationTokenStringPlainText {
	[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("KeeperFile")]
        [string]$Path
    )
    # setup return var
    [string]$PwPlainText = ""
    # validate the provided path
    if (Test-Path -Path $Path){
        # read the content of the file
        $PwSecured = Get-Content $Path | ConvertTo-SecureString
        $PwPlainText = ConvertFrom-SecureString -SecureString $PwSecured -AsPlainText
    }
    else {
        $PwPlainText = "Error: token path, $($Path) not found"
        Write-Error "Error: token path, $($Path) not found"
    }
    # send the text back
    return $PwPlainText
}

function Get-AutomationTokenStringSecured {
	[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("KeeperFile")]
        [string]$Path
    )
    if (Test-Path $Path){
        # read the content of the file
        $PwSecured = Get-Content $Path | ConvertTo-SecureString
        # send the data back as a secure string
        return $PwSecured
    }
    else {
        Write-Error "Error: token path $($Path) not found."
    }
}

# ## ### #### ##### ###### ####### ########################################################################################
# ## String functions
# ## ### #### ##### ###### ####### ########################################################################################
function Compress-String {
    <#
    .Synopsis
    minifies - takes a string and returns it with whitespace removed
    
    .Description 
    Cleans a string by removing all whitespace using the regex \s which includes space, carriage return, tab, new line, and more
    #>
    [CmdletBinding()]
    param (
        [string]$InputString
    )
    return ($InputString -replace '\s+', ' ').Trim()
}

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

function Get-UrlEncodedString {
    <#
    .SYNOPSIS
    Converts text into URL friendly string. 

    .DESCRIPTION
    Converts text into URL friendly string using path encoding instead 
    of plain URL encoding. The difference is to use %20 instead of + for 
    spaces. Microsoft's documentation describes this method of the HttpUtility 
    as deprecated.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$StringText
    )
    [string]$UrlText = [System.Web.HttpUtility]::UrlPathEncode($StringText)
    return $UrlText
}

function Get-StringHash {
    <#
    .SYNOPSIS
    returns a hash for a string value.
    .DESCRIPTION
    convert the supplied string into a stream then pipes that into the get-filehash commandlet
    .PARAMETER HashAlgorithm
    supports any hash algorithm that Get-FileHash supports. Defaults to SHA1
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$StringToHash,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MD5")]
        [string]$HashAlgorithm = "SHA1"
    )
    # create custom object to store the hash info
    $HashResult = [PSCustomObject]@{
        Hash = ""
    }
    #
    # create a memory space for the string data
    $StringIO = [System.IO.MemoryStream]::new()
    # initialize the io writer
    $MemWriter = [System.IO.StreamWriter]::new($StringIO)
    # write the string data into the memory stream
    $MemWriter.write($StringToHash)
    # empty the writer
    $MemWriter.Flush()
    # move streamer position to the start to process the string data in full, in order
    $StringIO.Position = 0
    # hash and populate the custom object with the hash results
    $HashResult = Get-FileHash -InputStream $StringIO -Algorithm "$HashAlgorithm" | Select-Object Hash
    return $HashResult.Hash
}

function Get-Base64String {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$InputString
    )
    $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputString))
    return $EncodedText
}

function New-PasswordText {
	Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [uint16]$intPasswordLength
    )
	# init return string
	$PasswordText = ""

	for ($i=0;$i -lt $intPasswordLength;$i++){
		# mixed case      capital    lower       integer
		$PasswordRange = (65..90) + (97..122) + (48..57)
		# select random number from the range(s)
		[uint16]$PasswordPath = Get-Random -InputObject $PasswordRange
		# add the random character to the return string
		[string]$PasswordText += [char]($PasswordPath)
	}
	return $PasswordText
}
Set-Alias -Name Get-NewPasswordText -Value New-PasswordText

function Set-FileTimeToNow {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Path
    )
    process {        
        if (Test-Path -Path $Path) {
            (Get-Item -Path $Path).LastWriteTime = (Get-Date)
        } 
        else {
            New-Item -Path $Path -ItemType File | Out-Null
        }
    }
}
Set-Alias -Name touch -Value Set-FileTimeToNow

function Add-UrlQueryParameter {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$ExistingUrl

        ,[Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$QueryAddition
    )
    [string]$ReturnUrl = $ExistingUrl
    if ($ReturnUrl.ToCharArray() -contains '?'){
        $ReturnUrl = $ReturnUrl + "&" + $QueryAddition
    }
    else {
        $ReturnUrl = $ReturnUrl + "?" + $QueryAddition
    }
    return $ReturnUrl
}

function Remove-LineFromFile {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
        
        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Pattern
        
        ,[Parameter(Mandatory=$false)]
        [switch]$ExactMatch
        
        ,[Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }
    
    $lines = Get-Content $FilePath
    $originalCount = $lines.Count
    
    if ($ExactMatch) {
        $filteredLines = $lines | Where-Object { $_ -ne $Pattern }
    } else {
        $filteredLines = $lines | Where-Object { $_ -notmatch $Pattern }
    }
    
    $removedCount = $originalCount - $filteredLines.Count
    
    if ($WhatIf) {
        Write-Host "Would remove $removedCount line(s) matching '$Pattern'"
        return
    }
    
    if ($removedCount -gt 0) {
        $filteredLines | Set-Content $FilePath
        Write-Host "Removed $removedCount line(s) from $FilePath"
    } else {
        Write-Host "No matching lines found"
    }
}

# ## ### #### ##### ###### ####### ########################################################################################
# ## Date functions
# ## ### #### ##### ###### ####### ########################################################################################

function ConvertTo-IsoDate {
    <#
    .SYNOPSIS
    converts time to UTC then formats to ISO 8601 YYYY-MM-DDTHH:MM:SSZ
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DateInputString
    )
    $DateString = Get-Date $DateInputString -AsUTC -Format u
    return $DateString.ToString()
}
Set-Alias -Name Get-IsoDate -Value ConvertTo-IsoDate

function ConvertTo-IsoDateFormat {
    <#
    .SYNOPSIS
    converts date to ISO 8601 format YYYY-MM-DDTHH:MM:SSZ 
    does not shift time to UTC - just formats
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DateInputString
    )
    $DateString = Get-Date $DateInputString -Format u
    return $DateString.ToString()
}
Set-Alias -Name Get-IsoDateFormat -Value ConvertTo-IsoDateFormat

function ConvertTo-LocalTime {
    <#
    .SYNOPSIS
    converts date-time to culture format and timezone where executed. 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DateInputString
    )
    $DateString = (Get-Date $DateInputString).ToLocalTime()
    return $DateString.ToString()
}
Set-Alias -Name Get-LocalDate -Value ConvertTo-LocalTime

function ConvertFrom-UxTime {
	param (
		[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        $UnixTime
		
        ,[Parameter(Mandatory=$false)]
        [string]$TimeFormat=""
        
        ,[Parameter(Mandatory=$false)]
        [switch]$SecondsOnly
	)
	$EpochOffset = $UnixTime / 1000
    if ($SecondsOnly){
        $EpochOffset = $UnixTime
    }
    $objTime = [TimeZone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($EpochOffset))
	[string]$HumanTime = ""
	 # examples from 1427964343362
	switch ($TimeFormat) {
		"logPrefix" {
			# [2015-04-02_03.45.43]
			$HumanTime = get-date $objTime -uFormat [%Y-%m-%d_%H.%M.%S]
		}
		"utc" {
			# Thursday, April 02, 2015 8:45:43 AM
			$HumanTime = $objTime.ToUniversalTime()
		}
		"date" {
			# 04/02/2015
			$HumanTime = get-date $objTime -uFormat %x
		}
		default {
			# Thursday, April 02, 2015 3:45:43 AM
			$HumanTime = $objTime
		}
	}
	return $HumanTime
}

function ConvertFrom-ExcelDateNumber {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [double]
        $ExcelDateNumber
    )
    return (Get-Date "1/1/1900").AddDays($ExcelDateNumber)
}

# ## ### #### ##### ###### ####### ########################################################################################
# ## Log functions
# ## ### #### ##### ###### ####### ########################################################################################

function Get-ScriptLogPath {
	return $global:LogFilePath
}

function Get-LogTimestamp {
	$Timestamp = get-date -uFormat %Y-%m-%d_%H.%M.%S
	$Logstamp = "[{0}]" -f $Timestamp
	return $Logstamp
}

function New-DefaultLogFile {
	# check for c:\logs
	[string]$LogPrefix = ""
	[string]$CLogs = $env:systemdrive + "\logs"
	if ( (Test-Path -Path $CLogs) -eq $false){
		mkdir $CLogs | out-null
	}
	# structure log name
	if (!$global:LogPrefixFilename){
		$LogPrefix = "PowerShellLog"
	}
	else {
		$LogPrefix = $global:LogPrefixFilename
	}
	$global:LogFilePath = $CLogs + "\" + $LogPrefix + "-" + (get-date -uformat %Y-%m-%d_%H%M).ToString() + ".log"
	Add-LogEntry "Default log created at $global:LogFilePath"
}

function Add-LogEntry {
    <#
    .SYNOPSIS
        Adds a timestamped log entry to the globally configured log file
    .DESCRIPTION
        Adds a timestamped log entry to the globally configured log file. Also prints to screen based on verbosity.
    .PARAMETER LogMsg
        message to be logged
    #>
    Param(
        [Alias("strLogMsg")]
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$LogMsg
    )
    $LogTimestamp = Get-LogTimestamp
    $StampdMsg = "$($LogTimestamp) $($LogMsg)"
    $TranscriptionCheck = Get-ActiveTranscript
    if (!$TranscriptionCheck){
        Add-Content -path $global:LogFilePath -value $StampdMsg
    }
    if ($VerbosePreference -eq "SilentlyContinue"){
        Write-Host $StampdMsg
    } 
    elseif ($VerbosePreference -eq "Continue") {
        Write-Verbose $StampdMsg
    }
}

function Test-LogStatus {
    <#
    .SYNOPSIS
        tests for the existance of the log setting and creates the file if needed.
    #>
    if ( [string]::IsNullOrEmpty($global:LogFilePath)) {
        # no log path specified, create default
        New-DefaultLogFile
    }
    # since the log path was specified, let's verify the path
    else {
        # if the file already exists, append with notation and move on
        if ((Test-Path $LogFilePath) -eq $true){
            Add-LogEntry "..."
            Add-LogEntry "$global:LogPrefixFilename attempt."
        }
        else {
            Write-Host "checking log path parent"
            # get path parts
            $LogPathInfo=$LogFilePath.Split('\')
            $LogPathFile=$LogPathInfo[($LogPathInfo.Length - 1)]
            $LogPathDir=$LogFilePath.Replace("$LogPathFile","")
            # make sure directory for specified path exists
            if ((Test-Path $LogPathDir) -eq $false){
                # it doesn't, revert to default log setting
                New-DefaultLogFile
            }
        } # end file does not exist
    } # end specified log check
}

function Test-LogExistence {
    [bool]$logexists = $false
    if (!([string]::IsNullOrEmpty($global:LogFilePath))) {
        $logexists = $true
    }
    return $logexists
}

function Get-ActiveTranscript {
    <#
    .SYNOPSIS
    test for presences of transcript data
    .DESCRIPTION
    test for presences of transcript data. returns transcript path if present
    #>
    $Flags = [System.Reflection.BindingFlags]'Instance, NonPublic'
    $TranscriptionData = $Host.Runspace.GetType().GetProperty('TranscriptionData', $Flags).GetValue($Host.Runspace)
    $Transcripts = $transcriptionData.GetType().GetProperty('Transcripts', $Flags).GetValue($TranscriptionData)
    return $Transcripts | ForEach-Object { $_.GetType().GetProperty('Path', $Flags).GetValue($_) }
}

# ## ### #### ##### ###### ####### ########################################################################################
# ## Archive functions
# ## ### #### ##### ###### ####### ########################################################################################

function Set-ArchivePath {
	Param([string]$NewArchivePath)
	$NewArchivePath = $NewArchivePath + "\" + (get-date -uformat %Y-%m-%d_%H%M).ToString()
	try {
		Add-LogEntry "Creating archive directory $NewArchivePath"
		New-Item -Path $NewArchivePath -ItemType Directory -ErrorAction stop | Out-Null
		$global:ArchivePath = $NewArchivePath
		$global:bArchiveOn = $true
	}
	catch {
		$errMsg = $_.Exception.Message
		Add-LogEntry $errMsg
		Add-LogEntry "could not create archive folder."
		Add-LogEntry "automation files will not be archived."
		$global:bArchiveOn = $false
	}
	if ($global:bArchiveOn){Write-Verbose ("Archive path is created {0}" -f $global:ArchivePath)}
}

function Set-DefaultArchive {
# set the archive path to default relative path
	[string]$DefaultArchiveRoot = (get-item $PSScriptRoot).parent.FullName + "\Archive"
	Add-LogEntry "Setting archive to default location"
	Add-LogEntry "Default archive root is $DefaultArchiveRoot"
	Set-ArchivePath $DefaultArchiveRoot
}

function Test-ArchiveStatus {
	<#
    .SYNOPSIS
    tests if the archive status is on and attempts to configure it on if not.
    #>
    # check for archive setting and folder existance
	Add-LogEntry "Archive option check"
	if ($global:bArchiveOn -ne $true){
		# check if an archive location was requested
		if ( [string]::IsNullOrEmpty($global:ArchivePath)) {
			Add-LogEntry "Archive location not specified."
			Set-DefaultArchive
		}
		else {
			if ((Exists $global:ArchivePath) -eq $true) {
				# try to use the specified location if it exists
				Add-LogEntry ("Archive already on: {0}" -f $global:ArchivePath)
			}
			else {
				Add-LogEntry ("Archive directory, {0} is not reachable" -f $global:ArchivePath)
				Set-DefaultArchive
			}
		}
	} # end archive off if
	else {
		Add-LogEntry ("Archive on.{0}" -f $global:ArchivePath)
	}
} # end archivecheck function

function Get-ArchivePath {
	[string]$ArchResponse = "none"
	if ($global:bArchiveOn -eq $true){
		$ArchResponse = $global:ArchivePath
	}
	return $ArchResponse
}

# ## ### #### ##### ###### ####### ########################################################################################
# ## Directory Services Functions
# ## ### #### ##### ###### ####### ########################################################################################

function ConvertFrom-ADGroupMembers {
    <#
    .SYNOPSIS
    Creates custom object for members found in group

    .DESCRIPTION
    Creates PowerShell custom object for members found in an Active Directory security group
    *Requires the AD powershell tools found in RSAT
    #>
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [String]$ADGroup
    )
    Add-LogEntry "Querying AD Group $ADGroup"
    [PSCustomObject]$colGroupPeople = Get-ADGroupMember $ADGroup
    return $colGroupPeople
}

function Get-EmailAddressFromAD {
    <#
    .SYNOPSIS
    retrieve a user's email address by searching Active directory. Requires the RSAT Active Directory PowerShell tools

    .PARAMETER CollegeUsername
    username to lookup in AD
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$CollegeUsername
    )
    $EmamilSearchResult = "not found"
    try {
        $ADSearchResult = Get-ADUser -Identity $CollegeUsername -Properties EmailAddress
        if (($null -ne $ADSearchResult) -and ($null -ne $ADSearchResult.EmailAddress) -and ($ADSearchResult.EmailAddress -ne "")){
            $EmamilSearchResult = $ADSearchResult.EmailAddress.ToLower()
        }
    } catch { 
        #log error conditions 
    }
    return $EmamilSearchResult
}
Set-Alias Get-CollegeEmailAddressFromAD -Value Get-EmailAddressFromAD

function Get-EmailAddressFromLdap {
    <#
    .SYNOPSIS
    retrieve a user's email address by searching Active directory via LDAP.

    .PARAMETER CollegeUsername
    username to lookup
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [Alias("CollegeUsername","username")]
        [string]$DsUsername,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DsDomain,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DsLdapPath
    )
    $EmamilSearchResult = "not found"
    try {
        $DsSearchResult = Get-UserInfoFromLDAP -DsUsername $DsUsername -DsDomain $DsDomain -DsLdapPath $DsLdapPath
        if (($null -ne $DsSearchResult) -and ($null -ne $DsSearchResult.mail) -and ($DsSearchResult.mail -ne "")){
            $EmamilSearchResult = $DsSearchResult.mail.ToLower()
        }
    } catch { 
        #log error conditions 
    }
    return $EmamilSearchResult
}
Set-Alias -Name Get-CollegeEmailAddressFromLdap -Value Get-EmailAddressFromLdap

function Get-UserInfoFromLDAP {
    <#
    .SYNOPSIS
    retrieve email address using LDAP to query the identity directory
    Still depends on Windows libraries. Not a cross-platform function
    useraccountcontrol: 512=enabled, 514=disabled

    .PARAMETER DsUsername
    username to lookup in AD

    .PARAMETER DsDomain
    domain for the directory

    .PARAMETER DsLdapPath
    LDAP organization unit path for the directory tree to search
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [Alias("CollegeUsername","username")]
        [string]$DsUsername,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsDomain,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsLdapPath
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)/$($DsLdapPath)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.PropertiesToLoad.AddRange(@("samAccountName","displayName","givenName","sn","title","userprincipalname","mail","userAccountControl","memberof","department","distinguishedname"))
    $DSSearcher.Filter = "(&(objectClass=user)(samaccountname=$($DsUsername)))"
    $SearchResult = $DSSearcher.FindOne()
    return $SearchResult.Properties
}
Set-Alias -Name Get-CollegeUserInfoFromLDAP -Value Get-UserInfoFromLDAP

function Get-DirectoryGroupMembershipFromLDAP {
    <#
    .SYNOPSIS
    retrieve direct group members of a group by group name
    .PARAMETER DirectoryGroupName
    directory group name to validate membership, example lmsusers
    .PARAMETER DsDomain
    fqnd path for ldap domain example domain.tld
    .PARAMETER DsLdapPath
    root ou path, example OU=users,DC=domain,DC=tld
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DirectoryGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsDomain,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsLdapPath
    )
    $GroupInfo = Get-DirectoryGroupInformation $DirectoryGroupName -DsDomain $DsDomain -DsLdapPath $DsLdapPath
    return $GroupInfo.Properties.member
}

function Get-DirectoryGroupInformation {
    <#
    .SYNOPSIS
    retrieve information about a group by group name
    .PARAMETER DirectoryGroupName
    directory group name, example lmsusers
    .PARAMETER DsDomain
    fqnd path for ldap domain example domain.tld
    .PARAMETER DsLdapPath
    root ou path, example OU=users,DC=domain,DC=tld
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DirectoryGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsDomain

       # [Parameter(Mandatory)]
       # [ValidateNotNullorEmpty()]
       # [string]$DsLdapPath
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.Filter = "(& (objectCategory=group) (name=$($DirectoryGroupName)))"
    $SearchResult = $DSSearcher.FindOne()
    return $SearchResult    
}

function Test-DirectoryGroupMembership {
    <#
    .SYNOPSIS
    tests username direct memberships in a group by group name
    .PARAMETER DsUsername
    username to validate against group, example jdoe123
    .PARAMETER DirectoryGroup
    directory group name to validate membership, example lmsusers
    .PARAMETER DsDomain
    fqnd path for ldap domain example domain.tld
    .PARAMETER DsLdapPath
    root ou path, example OU=users,DC=domain,DC=tld
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DsUsername,

        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [string]$DirectoryGroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DsDomain,

        [Parameter(Mandatory=$false)]
        [string]$DsLdapPathUsers,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DsLdapPathGroups
    )
    # !! only tests direct membership, does not check nested groups
    [bool]$TestResult = $false
    
    # retrieve user and group info from the directory
    $UserInfo = Get-UserInfoFromLDAP -DsUsername $DsUsername -DsDomain $DsDomain -DsLdapPath $DsLdapPathUsers
    $GroupInfo = Get-DirectoryGroupInformation -DirectoryGroupName $DirectoryGroup -DsLdapPath $DsLdapPathGroups

    # check the list
    if ($GroupInfo.Properties.distinguishedname -in $UserInfo.memberof){
        $TestResult = $true
    }
    return $TestResult
}

<#
User Properties available in LDAP queries:
msexchpoliciesincluded
company
sidhistory
badpasswordtime
msexchwhenmailboxcreated
distinguishedname
msds-authenticatedatdc
countrycode
lastlogoff
msexchblockedsendershash
terminalserver
msexchtextmessagingstate
userparameters
targetaddress
instancetype
msexchversion
replicatedobjectversion
primarygroupid
telephonenumber
msexchumdtmfmap
replicationsignature
whenchanged
displayname
proxyaddresses
protocolsettings
mapirecipient
extensionattribute1
mstsmanagingls
usnchanged
garbagecollperiod
msexchalobjectversion
usncreated
msexchmailboxguid
msexchadcglobalnames
badpwdcount
legacyexchangedn
msexchrecipienttypedetails
employeenumber
useraccountcontrol
msexchhidefromaddresslists
whencreated
msds-externaldirectoryobjectid
adspath
initials
department
comment
msexchmobilemailboxflags
mstslicenseversion2
samaccountname
mailnickname
codepage
objectcategory
objectsid
msexchsafesendershash
memberof
msexchrecipientdisplaytype
mstsexpiredate
objectclass
logoncount
mstslicenseversion3
msexchuseraccountcontrol
pwdlastset
title
msexchremoterecipienttype
dlmemdefault
lastlogon
mstslicenseversion
sn
samaccounttype
extensionattribute2
mail
msnpallowdialin
usercertificate
showinaddressbook
physicaldeliveryofficename
userprincipalname
cn
name
givenname
accountexpires
lockouttime
objectguid
dscorepropagationdata
lastlogontimestamp
textencodedoraddress
employeeid

#>

# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
