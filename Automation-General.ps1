# not sure if PowerShell or Windows issue but not setting TLS can cause issues randomly by using default so always set it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13

# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## Shared vars, configure in profile or task script after including this file
$global:DirectoryDomain = "domain.tld"
$global:DirectoryUserPath = "OU=User Org Unit,DC=domain,DC=tld"
$global:DirectoryGroupPath = "OU=Groups Org Unit,DC=domain,DC=tld"
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## String functions

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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$StringText
    )
    $UrlText = [System.Web.HttpUtility]::UrlEncode($StringText).Replace(".", "%2E").Replace("/","%2F")
    return $UrlText
}

function Get-StringHash {
    <#
    .SYNOPSIS
    returns a hash for a string value.

    .DESCRIPTION
    convert the supplied string into a stream then pipes that into the get-filehash commandlet

    .PARAMETER HashAlgorithm
    supports any hash algorithm that Get-FileHash supports. Defaults to MD5
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$StringToHash,
        
        [Parameter(Mandatory = $false)]
        [string]$HashAlgorithm = "MD5"
    )
    
    $HashResult = [PSCustomObject]@{
        Hash = ""
    }
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.write($StringToHash)
    $writer.Flush()
    $stringAsStream.Position = 0
    $HashResult = Get-FileHash -InputStream $stringAsStream -Algorithm "$HashAlgorithm" | Select-Object Hash
    return $HashResult.Hash
}

function Get-Base64String {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$InputString
    )
    $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputString))
    return $EncodedText
}

function New-PasswordText {
	Param ([uint16]$intPasswordLength)
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

# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## Date functions

function ConvertTo-IsoDate {
    <#
    .SYNOPSIS
    converts time to UTC then formats to ISO 8601 YYYY-MM-DDTHH:MM:SSZ
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DateInputString
    )
    $DateString = Get-Date $DateInputString -AsUTC -Format u
    return $DateString.ToString()
}
Set-Alias -Name Get-IsoDate -Value ConvertTo-IsoDate

function Get-IsoDateFormat {
    <#
    .SYNOPSIS
    converts date to ISO 8601 format YYYY-MM-DDTHH:MM:SSZ 
    does not shift time to UTC - just formats
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DateInputString
    )
    $DateString = Get-Date $DateInputString -Format u
    return $DateString.ToString()
}
Set-Alias -Name ConvertTo-IsoDateFormat -Value Get-IsoDateFormat

function Get-LocalDate {
    <#
    .SYNOPSIS
    converts date-time to culture format and timezone where executed. 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DateInputString
    )
    $DateString = (Get-Date $DateInputString).ToLocalTime()
    return $DateString.ToString()
}
Set-Alias -Name ConvertTo-LocalTime -Value Get-LocalDate

function ConvertFrom-UxTime {
	param (
		[Parameter(Mandatory=$true)]$UnixTime
		,[Parameter(Mandatory=$false)]$TimeFormat=""
        ,[Parameter(Mandatory=$false)][switch]$SecondsOnly
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

# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## Log functions

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
        Adds a timestamped log entry to the globally configured log file. Also prints to screen when verbose.
    .PARAMETER LogMsg
        message to be logged
    #>
    Param(
        [Alias("strLogMsg")]
        [Parameter(Mandatory)]
        [string]$LogMsg
    )
    $stamp = Get-LogTimestamp
    $stampdMsg = "$($stamp) $($LogMsg)"
    Add-Content -path $global:LogFilePath -value $stampdMsg
    if ($VerbosePreference -eq "SilentlyContinue"){
        Write-Host $stampdMsg
    } 
    elseif ($VerbosePreference -eq "Continue") {
        Write-Verbose $stampdMsg
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
            if ((Exists $LogPathDir) -eq $false){
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
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## Archive functions

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
# ## ### #### ##### ###### ####### ########################################################################################
# ## ### #### ##### ###### ####### ########################################################################################
# ## Directory Services Functions
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
        [string]$CollegeUsername
    )
    $EmamilSearchResult = "not found"
    try {
        $DsSearchResult = Get-UserInfoFromLDAP -CollegeUsername $CollegeUsername
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

    .PARAMETER CollegeUsername
    username to lookup in AD

    .PARAMETER DsDomain
    domain for the directory

    .PARAMETER DsLdapPath
    LDAP organization unit path for the directory tree to search
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollegeUsername,

        [Parameter(Mandatory=$false)]
        [string]$DsDomain="$($global:DirectoryDomain)",

        [Parameter(Mandatory=$false)]
        [string]$DsLdapPath="$($global:DirectoryUserPath)"
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)/$($DsLdapPath)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.PropertiesToLoad.AddRange(@("samAccountName","displayName","givenName","sn","title","userprincipalname","mail","userAccountControl","memberof"))
    $DSSearcher.Filter = "(&(objectClass=user)(samaccountname=$($CollegeUsername)))"
    $SearchResult = $DSSearcher.FindOne()
    return $SearchResult.Properties
}
Set-Alias -Name Get-CollegeUserInfoFromLDAP -Value Get-UserInfoFromLDAP
<#
function Get-DirectoryGroupMembershipFromLDAP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$DirectoryGroupCn,

        [Parameter(Mandatory=$false)]
        [string]$DsDomain="$($global:DirectoryDomain)",

        [Parameter(Mandatory=$false)]
        [string]$DsLdapPath="$($global:DirectoryUserPath)"
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.Filter = "(&(objectCategory=user)(memberOf=$($DirectoryGroupCn)))"
    $SearchResult = $DSSearcher.FindAll()
    return $SearchResult
}
#>
function Get-DirectoryGroupInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$DirectoryGroupName,

        [Parameter(Mandatory=$false)]
        [string]$DsDomain="$($global:DirectoryDomain)",

        [Parameter(Mandatory=$false)]
        [string]$DsLdapPath="$($global:DirectoryGroupPath)"
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.Filter = "(& (objectCategory=group) (name=$($DirectoryGroupName)))"
    $SearchResult = $DSSearcher.FindOne()
    return $SearchResult    
}

<#
function Test-DirectoryGroupMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollegeUsername,

        [Parameter(Mandatory)]
        [string]$DirectoryGroup,

        [Parameter(Mandatory=$false)]
        [string]$DsDomain="$($global:DirectoryDomain)",

        [Parameter(Mandatory=$false)]
        [string]$DsLdapPath="$($global:DirectoryUserPath)"
    )
    $DSEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DsDomain)")
    $DSSearcher = New-Object System.DirectoryServices.DirectorySearcher($DSEntry)
    $DSSearcher.Filter = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$($DirectoryGroup))(|(sAMAccountName=$($CollegeUsername))))"
    $SearchResult = $DSSearcher.FindOne()
    return $SearchResult
}
#>

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
