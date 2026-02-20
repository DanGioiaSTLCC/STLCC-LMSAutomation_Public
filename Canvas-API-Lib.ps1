<#
.SYNOPSIS 
Canvas REST API functions as well as integration upload
All functions tested against PowerShell 7 only
Most if not all functions included assume the token is or will be stored in a secure string file
Set VerbosePreference equal to Continue to read details of operations

.DESCRIPTION
Canvas tokens can be retrieved by running Get-CanvasTokenString
Canvas token files can be created by running New-CanvasTokenFile
Generic GET requests can be made by using a fully formed API route in Get-CanvasItem or Get-CanvasItemList

The following objects support SIS IDs in the API:
sis_account_id
sis_course_id
sis_group_id
sis_group_category_id
sis_integration_id (for users and courses)
sis_login_id
sis_section_id
sis_term_id
sis_user_id
#>
Add-Type -AssemblyName System.Web

# include the general functions, specifically for date stuff and string hashing
Import-Module $PSScriptRoot\Automation-General.ps1

# not sure if PowerShell or Windows issue but not setting TLS can cause issues randomly by using default so always set it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13

# setup global stuff
$global:CanvasSite = "institution.beta.instructure.com"
$global:LorSite = "lor.instructure.com"
$global:CourseRoleIds = @()

function Send-CanvasUpdate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$false)]
        [string]$RequestBody="",

        [Parameter(Mandatory=$false)]
        [string]$ApiVerb="POST",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $TokenStringSecured = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    $RestParams = @{
        Method = $ApiVerb
        Uri = $CanvasApiUrl
        Authentication = "Bearer"
        Token = $TokenStringSecured
        ResponseHeadersVariable = "ResponseHeaders"
    }
    if ($RequestBody -ne ""){
        $RestParams.Add("Body",$RequestBody)
        $RestParams.Add("ContentType","application/json")
    }
    $result = Invoke-RestMethod @RestParams
    if ($ResponseHeaders.Status -like "40*"){
        $ResponseHeaders
        Exit 55
    }
    # clear token data
    $TokenStringSecured = $null
    Remove-Variable -Name "TokenStringSecured"
    return $result
}

function Send-CanvasUpdateWithVars {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$false)]
        [string]$RequestBody="",

        [Parameter(Mandatory=$false)]
        [string]$ApiVerb="POST",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $RestParams = @{
        Method = $ApiVerb
        Uri = $CanvasApiUrl
        Authentication = "Bearer"
        Token = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
        Headers = @{
            Authorization = "Bearer $TokenString"
        }
        ResponseHeadersVariable = "ResponseHeaders"
        StatusCodeVariable = "StatusCodeInfo"
        SkipHttpErrorCheck = $true
    }
    if ($RequestBody -ne ""){
        $RestParams.Add("Body",$RequestBody)
        $RestParams.Add("ContentType","application/json")
    }
    $result = Invoke-RestMethod @RestParams
    <#
    if ($ResponseHeaders.Status -like "40*"){
        $ResponseHeaders
        Exit 55
    }
    #>
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"
    $ReturnData = @{
        result = $result
        StatusCode = $StatusCodeInfo
        Headers = $ResponseHeaders
    }
    return $ReturnData
}

function Send-CanvasUpdateFormDataWithVars {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        $RequestBody, 

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    
    $ReturnData = @{
        result = "Error - No Data Provided"
        StatusCode = "XxX"
        Headers = ""
    }
    $RestParams = @{
        Method = "POST"
        Uri = $CanvasApiUrl
        Form = $RequestBody
        Authentication = "Bearer"
        Token = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
        ResponseHeadersVariable = "ResponseHeaders"
        StatusCodeVariable = "StatusCodeInfo"
        SkipHttpErrorCheck = $true
    }
    $result = Invoke-RestMethod @RestParams
    
    $ReturnData = @{
        result = $result
        StatusCode = $StatusCodeInfo
        Headers = $ResponseHeaders
    }

    return $ReturnData
}

function Get-CanvasSisSshaPasswordText {
    <#
    .SYNOPSIS
    creaet a hashed value to include in an SIS user file to upload
    see https://canvas.instructure.com/doc/api/file.sis_csv.html
    one can use Get-NewPasswordText to generate a salt value
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$PassPlainText

        ,[Parameter(Mandatory=$true)]
        [string]$PassTheSalt
    )
    $SisPw = "{SSHA}" + (Get-Base64String -InputString ("{0}{1}" -f (Get-StringHash -StringToHash ("{0}{1}" -f $PassPlainText,$PassTheSalt) -HashAlgorithm SHA1).ToLower(),$PassTheSalt))
    return $SisPw
}

function Get-CanvasItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    $result = Invoke-RestMethod -Method GET -Authentication Bearer -Token $TokenString -Uri $CanvasApiUrl -ResponseHeadersVariable ResponseHeaders
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"    
    return $result
}

function Get-CanvasItemWithVars {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    $result = Invoke-RestMethod -Method GET -Authentication Bearer -Token $TokenString -Uri $CanvasApiUrl -ResponseHeadersVariable ResponseHeaders -StatusCodeVariable StatusCodeInfo -SkipHttpErrorCheck
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"    
    $ReturnData = @{
        result = $result
        StatusCode = $StatusCodeInfo
        Headers = $ResponseHeaders
    }
    return $ReturnData
}

function Get-CanvasItemList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [int32]$PerPage=10,

        [Parameter(Mandatory=$false)]
        [int32]$MaxResults=1000
    )
    # set maximum "next" link follows
    $MaxPages = 100
    # determine page size for results
    if (($PerPage -ne 10) -or ($MaxResults -ne 1000)){
        # check if remainder exists max/per, set pages accordingly
        if (0 -eq $MaxResults % $PerPage){
            $MaxPages = $MaxResults / $PerPage
        }
        else {
            $MaxPages = [int]($MaxResults / $PerPage) + 1
        }
    }
    # if paging specified add it the url
    if ($PerPage -ne 10){
        if (($CanvasApiUrl.Contains("per_page")) -eq $false){
            # check if there are already query parameters
            if ($CanvasApiUrl.Contains("`?") -eq $false){
                $CanvasApiUrl += "?per_page={0}" -f $PerPage.ToString()
            }
            else {
                $CanvasApiUrl += "&per_page={0}" -f $PerPage.ToString()
            }
        }
    }
    Write-Verbose "original URL is $CanvasApiUrl"
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    # add follow rel link for the command to automatically follw the next result set link
    $result = Invoke-RestMethod -Method GET -Authentication Bearer -Token $TokenString -Uri $CanvasApiUrl -FollowRelLink -MaximumFollowRelLink $MaxPages
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"    
    return $result
}

function Get-CanvasItemListWithVars {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [int32]$PerPage=10,

        [Parameter(Mandatory=$false)]
        [int32]$MaxResults=1000
    )
    # set maximum "next" link follows
    $MaxPages = 100
    # determine page size for results
    if (($PerPage -ne 10) -or ($MaxResults -ne 1000)){
        # check if remainder exists max/per, set pages accordingly
        if (0 -eq $MaxResults % $PerPage){
            $MaxPages = $MaxResults / $PerPage
        }
        else {
            $MaxPages = [int]($MaxResults / $PerPage) + 1
        }
    }
    # if paging specified add it the url
    if ($PerPage -ne 10){
        if (($CanvasApiUrl.Contains("per_page")) -eq $false){
            # check if there are already query parameters
            if (($CanvasApiUrl.Contains("`?")) -eq $false){
                $CanvasApiUrl += "?per_page={0}" -f $PerPage.ToString()
            }
            else {
                $CanvasApiUrl += "&per_page={0}" -f $PerPage.ToString()
            }
        }
    }
    Write-Verbose "original URL is $CanvasApiUrl"

    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    # add follow rel link for the command to automatically follw the next result set link
    $result = Invoke-RestMethod -Method GET -Authentication Bearer -Token $TokenString -Uri $CanvasApiUrl -FollowRelLink -MaximumFollowRelLink $MaxPages -ResponseHeadersVariable ResponseHeaders -StatusCodeVariable StatusCodeInfo -SkipHttpErrorCheck
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"
    $ReturnData = @{
        result = $result
        StatusCode = $StatusCodeInfo
        Headers = $ResponseHeaders
    }
    return $ReturnData
}

function Get-CanvasItemListFlattened {
    <#
    .SYNOPSIS
    Returns an unpaginated list when multiple API calls are required to retrieve all items

    .DESCRIPTION
    Returns an unpaginated list when multiple API calls are required to retrieve all items. 
    Uses custom header parsing to determine next page when handling paginated results and 
    places all results into a "flattened" list. This obviates dealing with the paginated 
    groups of results returned by using the FollowRelLink option of Invoke-RestMethod.

    .PARAMETER ApiUrl
    full API route including protocol, domain and path

    .PARAMETER TokenFilePath
    path of the file containing the token text stored as a secure string

    .PARAMETER ResultsPerCall
    page size of results to return for each API call

    .PARAMETER MaxApiCalls
    maximum number of times to allow results API calls
    #>
    param (
        [Alias("CanvasApiUrl")]
        [Parameter(Mandatory)]
        [string]$ApiUrl
        
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
        
        ,[Alias("PerPage")]
        [Parameter(Mandatory=$false)]
        [int32]$ResultsPerCall=50

        ,[Parameter(Mandatory=$false)]
        [int32]$MaxApiCalls=20

        ,
        [Alias("MaxResults")]
        [Parameter(DontShow)]
        $OldParams
    )
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    $AllResults = @()
    $LoopMax = $MaxApiCalls
    $LoopI = 1
    do {
        $LoopI ++
        
        # update API url with result size per page
        if ($ResultsPerCall -ne 10){
            if (($ApiUrl.Contains("per_page")) -eq $false){
                # check if there are already query parameters
                if (($ApiUrl.Contains("`?")) -eq $false){
                    $ApiUrl += "?per_page={0}" -f $ResultsPerCall.ToString()
                }
                else {
                    $ApiUrl += "&per_page={0}" -f $ResultsPerCall.ToString()
                }
            }
        }

        $response = Invoke-RestMethod -Uri $ApiUrl -Authentication Bearer -Token $TokenString -Method Get -ResponseHeadersVariable HeadersResp
        
        # Append retrieved pages to the result list
        $AllResults += $response
        
        # Check for pagination link in response headers
        if($HeadersResp.Link){
            $HeaderLinks = $HeadersResp.Link.split(',')
            # hash table to store header links
            $HeaderLinkDetails = @{}
            foreach ($HeaderLink in $HeaderLinks){
                <# example link header: 
                    <https://domain/api_route?page=bookmark:GUID&per_page=20>; rel="next",
                    <https://domain/api_route?page=bookmark:GUID&per_page=20>; rel="current",
                    <https://domain/api_route?page=first&per_page=20>; rel="first
                #>
                $parts = $HeaderLink.split('; ');
                $partsKey = $parts[1].replace('rel=','').replace('"','')
                $partsValue = $parts[0].replace('<','').replace('>','')
                $HeaderLinkDetails.Add($partsKey,$partsValue);
            }
            $ApiUrl = $HeaderLinkDetails['next']
            # Write-Verbose "Next: $($ApiUrl)"
        }
    } while ($ApiUrl -and ($LoopI -le $LoopMax) -and $HeadersResp.Link)
    return $AllResults
}

function Send-CanvasSisFile {
    <#
    .Synopsis
    upload SIS csv files to Canvas.  Use Zip parameter if bundling
    
    .Description
    upload SIS csv files to Canvas.  Use Zip parameter (PowerShell boolean) if bundling multiple files into a .zip file

    for a full reference of formatting the CSV files see https://canvas.instructure.com/doc/api/file.sis_csv.html
    
    .Parameter UploadFilePath
    full file path of the file to be uploaded
    
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    
    .Parameter SkipDeletes
    defaults to true (boolean)
    
    .Parameter Zip
    indicate if uploading a zip file instead of a csv.  use PowerShell boolean.  defaults to false.
    
    .Parameter DropMode
    specify diffing drop mode.  options are inactive, deleted, completed. defaults to inactive
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UploadFilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$TokenFilePath,
        
        [Parameter(Mandatory = $false)]
        [bool]$SkipDeletes = $true,

        [Parameter(Mandatory = $false)]
        [bool]$Zip = $false,

        # Diffing Drop Modes (inactive, deleted, completed)
        [Parameter(Mandatory = $false)]
        [string]$DropMode = "inactive",

        [Parameter(Mandatory = $false)]
        [bool]$OverrideStickiness = $true,
        
        [Parameter(Mandatory = $false)]
        [string]$OtherArguments = ""
    )
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    # format the upload url
    [string]$UploadRoute = "https://{0}/api/v1/accounts/1/sis_imports.json" -f  $global:CanvasSite;
    $UploadRoute += "?import_type=instructure_csv"
    if ($Zip){$UploadRoute += "&extension=zip"} else {$UploadRoute += "&extension=csv"}
    if ($SkipDeletes) {
        $UploadRoute += "&skip_deletes=true"
    } else {
        $UploadRoute += "&diffing_drop_status=" + $DropMode
    }
    if ($OtherArguments -ne ""){$UploadRoute += "&" + $OtherArguments}
    if ($OverrideStickiness){$UploadRoute += "&override_sis_stickiness=true&add_sis_stickiness=true"}
    Write-Verbose $UploadRoute
    # send the results to canvas
    $UploadResult = Invoke-restmethod -Method POST -Authentication Bearer -Token $TokenString -Uri $UploadRoute -InFile $UploadFilePath -ContentType "text/csv"
    
    # clear out the token var
    $TokenString = $null;
    Remove-Variable -Name "TokenString"
    
    # return the upload result to the calling script
    return $UploadResult
}

function Invoke-CanvasFileDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,    
        
        [Parameter(Mandatory = $true)]
        [Alias("OutputFilePath","Outputfile","OutFilePath")]
        [string]$OutFile,
        
        [Parameter(Mandatory = $true)]
        [string]$TokenFilePath
    )
    begin {
        $WebRequestParameters = @{
            Authentication = 'Bearer'
            Token = (Get-CanvasTokenStringSecured $TokenFilePath)
            Uri = $Uri
            OutFile = $OutFile
        }
    }   
    process {
        Invoke-WebRequest @WebRequestParameters
    }
}

function Send-CanvasOutcomeFile {
    <#
    .Synopsis
    upload outcomes csv files to Canvas.
    
    .Description
    upload outcomes csv files to Canvas.

    for a full reference of formatting the CSV files see https://developerdocs.instructure.com/services/canvas/outcomes/file.outcomes_csv
    
    .Parameter UploadFilePath
    full file path of the file to be uploaded
    
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UploadFilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$TokenFilePath
        
    )
    $TokenString = Get-CanvasTokenStringSecured -KeeperFile $TokenFilePath
    # format the upload url
    [string]$UploadRoute = "https://{0}/api/v1/accounts/1/outcome_imports" -f  $global:CanvasSite;
    $UploadRoute += "?import_type=instructure_csv"
    
    Write-Verbose $UploadRoute
    # send the file to canvas
    $UploadResult = Invoke-restmethod -Method POST -Authentication Bearer -Token $TokenString -Uri $UploadRoute -InFile $UploadFilePath -ContentType "text/csv"
    
    # clear out the token var
    $TokenString = $null;
    Remove-Variable -Name "TokenString"
    
    # return the upload result to the invoking expression
    return $UploadResult
}

function Get-CanvasSisStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SisUploadRefId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # build the route
    [string]$StatusCheckUrl = "https://{0}/api/v1/accounts/1/sis_imports/{1}" -f $global:CanvasSite,$SisUploadRefId
    # get the result
    $StatusCheckResult = Get-CanvasItem -CanvasApiUrl $StatusCheckUrl -TokenFilePath $TokenFilePath
    #  and return the lookup results
    return $StatusCheckResult
}

function New-CanvasTokenFile {
    # prompt for file location - Dialog may be more friendly
    $NewPasswordFilePath = Read-Host -Prompt "Enter or paste path for the new token file"
    Write-Host "Saving token via secure string to $NewPasswordFilePath"
     # remove the extra parameters from get-credential on older powershell
    if ( ($PSVersionTable.PsVersion.Major) -ge 3) {
        (get-credential -UserName "Token Saver" -Message "Only the password field is required.").password | convertFrom-SecureString | set-content $NewPasswordFilePath
    }
    else {
        (get-credential).password | convertFrom-SecureString | set-content $NewPasswordFilePath
    }
 
    Write-Host "Credential operation complete."
 }

function Get-CanvasTokenString {
	[CmdletBinding()]
    param (
        [Parameter()]
        [string]$KeeperFile
    )
    # setup return var
    [string]$UserPwPlainText = ""
    # read the content of the file
    $UserPwSecured = Get-Content $KeeperFile | ConvertTo-SecureString
    $UserPwPlainText = ConvertFrom-SecureString -SecureString $UserPwSecured -AsPlainText
    # send the text back
    return $UserPwPlainText
}

function Get-CanvasTokenStringSecured {
	[CmdletBinding()]
    param (
        [Parameter()]
        [string]$KeeperFile
    )
    # read the content of the file
    $UserPwSecured = Get-Content $KeeperFile | ConvertTo-SecureString
    # send the data back as a secure string
    return $UserPwSecured
}

function Get-CanvasUserInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUserId,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $UserUrl = "https://{0}/api/v1/users/{1}" -f $global:CanvasSite,$CanvasUserId
    $UserData = Get-CanvasItem -TokenFilePath $TokenFilePath -CanvasApiUrl $UserUrl
    return $UserData
}

function Test-CanvasUsername {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUsername,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $UserUrl = "https://{0}/api/v1/users/sis_login_id:{1}" -f $global:CanvasSite,$CanvasUsername
        
    $ResultData = Get-CanvasItemWithVars -CanvasApiUrl $UserUrl -TokenFilePath $TokenFilePath

    if ($ResultData.StatusCode -ne 200){
        $Msg = "Error:" + $ResultData.StatusCode + ":" + $ResultData.result.errors.message
        return $Msg
    }
    else {
        return $ResultData.result 
    }
}

function Get-CanvasUserByLogin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUsername,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$PersonId = "sis_login_id:" +  $CanvasUsername
    $UserInfo = Get-CanvasUserInfo -CanvasUserId $PersonId -TokenFilePath $TokenFilePath
    return $UserInfo
}

function Get-CanvasUserByPersonId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUserId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$PersonId = "sis_user_id:" +  $CanvasUserId
    $UserInfo = Get-CanvasUserInfo -CanvasUserId $PersonId -TokenFilePath $TokenFilePath
    return $UserInfo
}

function New-CanvasUser {
    <#
    .synopsis
    Create basic user in Canvas
    .Parameter Fullname
    first and last name of user separated by a space
    .Parameter LogonId
    username used to access Canvas
    .Parameter EmailAddress
    email address for user.  this is a required field.  anyone expecting to use a M365 resource must be set to institution email
    .Parameter SisId
    Banner SourcedId for user.  skip this parameter for external or admin users
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FullName,
        
        [Parameter(Mandatory=$true)]
        [string]$LogonId,

        [Parameter(Mandatory=$true)]
        [string]$EmailAddress,

        [Parameter(Mandatory=$false)]
        [string]$SisId="",
        
        [Parameter(Mandatory=$false)]
        [bool]$UseSaml=$true,

        [Parameter(Mandatory=$false)]
        [bool]$Notify=$false,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # craft user object parts
    $userParts = @{    
        name = $FullName
    }
    # add logon info
    $pseudonymParts = @{
        unique_id = $LogonId
    }
    if ($UseSaml){$pseudonymParts.Add("authentication_provider_id","saml")}
    # add the Banner SourcedId if applicable
    if ($SisId -ne ""){$pseudonymParts.Add("sis_user_id",$SisId)}
    # add email address
    $comParts = @{
        address = $EmailAddress
    }
    # notify use if requested
    if ($Notify){
        # these two are recommended to be used together, see https://canvas.instructure.com/doc/api/users.html#method.users.create
        $pseudonymParts.Add("send_confirmation",$true)
        $comParts.Add("skip_confirmation",$true)
    }
    # combine user objects into one
    $UserObject = @{
        user = $userParts
        pseudonym = $pseudonymParts
        communication_channel = $comParts
    }
    # format the data as JSON
    $UserObjectBody = ConvertTo-Json -InputObject $UserObject
    # construct the route
    $UserCreationUrl = "https://{0}/api/v1/accounts/self/users" -f $global:CanvasSite
    # construct arguments and send request
    $UserCreationArgs = @{
        CanvasApiUrl = $UserCreationUrl
        RequestBody = $UserObjectBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    $UserCreationResult = Send-CanvasUpdate @UserCreationArgs
    return $UserCreationResult
}

function Update-CanvasUserEmail {
    <#
    .synopsis
    Create basic user in Canvas
    .Parameter UserId
    user identifier used in Canvas (for username use sis_login_id:)
    .Parameter EmailAddress
    email address for user.  this is a required field.  anyone expecting to use a M365 resource must be set to institution email
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserId,

        [Parameter(Mandatory=$true)]
        [string]$EmailAddress,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # craft user object parts
    $userParts = @{user = @{ email = $EmailAddress}} | ConvertTo-Json
    $UserUrl = "https://{0}/api/v1/users/{1}" -f $global:CanvasSite,$UserId
    Send-CanvasUpdate -CanvasApiUrl $UserUrl -RequestBody $userParts -ApiVerb "PUT" -TokenFilePath $TokenFilePath
}

function Update-CanvasCourseSisId {
    <#
    .SYNOPSIS
    update a course's SIS ID
    #>
    [CmdletBinding()]
    param (
        # Existing course ID (use sis_course_id: prefix for existing SIS Course ID)
        [Parameter(Mandatory=$true)]
        [string]$CourseId,

        # New course SIS ID
        [Parameter(Mandatory=$true)]
        [string]$NewCourseId,

        # path of the file containing the token text stored as a secure string
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $CourseUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $UpdatePart = @{course = @{sis_course_id = $NewCourseId}}|ConvertTo-Json
    $UpdateArgs = @{
        CanvasApiUrl = $CourseUrl
        RequestBody = $UpdatePart
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    Send-CanvasUpdate @UpdateArgs
}

function Get-CanvasCourse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $CourseUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $CourseData = Get-CanvasItem -CanvasApiUrl $CourseUrl -TokenFilePath $TokenFilePath
    return $CourseData
}

function Get-CanvasCourseByCRN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CourseId")]
        [string]$CanvasCrn,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$CourseId = "sis_course_id:" +  $CanvasCrn
    $CourseInfo = Get-CanvasCourse -CanvasCourse $CourseId -TokenFilePath $TokenFilePath
    return $CourseInfo
}

function Get-CanvasCourseSections {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $CourseUrl = "https://{0}/api/v1/courses/{1}/sections" -f $global:CanvasSite,$CourseId
    # $CourseData = Get-CanvasItemList -CanvasApiUrl $CourseUrl -PerPage 100 -TokenFilePath $TokenFilePath
    $CourseData = Get-CanvasItemListFlattened -ApiUrl $CourseUrl -ResultsPerCall 100 -TokenFilePath $TokenFilePath
    return $CourseData    
}

function New-CanvasCourse {
    <#
    .SYNOPSIS
    create a course in Canvas

    .PARAMETER TermId
    SIS Id for the term

    .PARAMETER CourseAccount
    SIS Id for the account, defaults to self
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseNameLong,

        [Parameter(Mandatory=$true)]
        [string]$CourseNameShort,

        [Parameter(Mandatory=$true)]
        [string]$CourseRef,

        [Parameter(Mandatory=$true)]
        [string]$TermId,

        [Parameter(Mandatory=$false)]
        [bool]$SelfEnroll = $false,
        
        [Parameter(Mandatory=$false)]
        [string]$CourseFormat = "",

        [Parameter(Mandatory=$false)]
        [bool]$PublishImmediately = $false,

        [Parameter(Mandatory=$false)]
        [string]$CourseAccount = "self",

        [Parameter(Mandatory=$false)]
        [string]$StartDate = "",

        [Parameter(Mandatory=$false)]
        [string]$EndDate = "",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath        
    )
    # sub account config for URL
    if ($CourseAccount -ne "self"){$CourseAccount = "sis_account_id:" + $CourseAccount}
    # build URL
    $CourseUrl = "https://{0}/api/v1/accounts/{1}/courses" -f $global:CanvasSite,$CourseAccount
    # use default term if empty specification
    if ($TermId -eq ""){$TermId = "default"}
    $Course = @{
        name = $CourseNameLong
        course_code = $CourseNameShort
        term_id = "sis_term_id:{0}" -f $TermId
        sis_course_id = $CourseRef
    }
    if ($PublishImmediately){$Course.Add("offer","true")}
    if ($SelfEnroll){$Course.Add("self_enrollment","true")}
    if ($CourseFormat -ne ""){$Course.Add("course_format" ,$CourseFormat)}
    if ($StartDate -ne ""){
        $Course.Add("start_at",$StartDate)
        $Course.Add("restrict_enrollments_to_course_dates","true")
    }
    if ($EndDate -ne ""){$Course.Add("end_at",$EndDate)}
    $CourseBody = @{"course"= $Course}
    $CourseBodyParts = ConvertTo-Json $CourseBody
    $NewCourse = Send-CanvasUpdate -CanvasApiUrl $CourseUrl -RequestBody $CourseBodyParts -TokenFilePath $TokenFilePath
    return $NewCourse
}

function New-CanvasMembership {
    <#
    .Synopsis 
    Add course enrollment to Canvas.  use sis_login_id: prefix for person's username
    .Parameter CanvasCourse
    identifier for Canvas course.  user sis_course_id: prefix to use the SIS id for the course.  
    otherwise, you will need the integeger from the course url.
    .Parameter CanvasUser
    user identifier.  use one of the SIS prefixes or you will need the integer id from the user's properties url
    AD username prefix      = sis_login_id:
    Banner sourcedId prefix = sis_user_id:
    .Parameter CourseRole
    course membership role.  use student or instructor
    .Parameter Notify
    switch to send notification or notify new enrollee of new enrollment
    use PowerShell boolean value when splatting
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    .Parameter Section
    section identifier (optional).  non database id prefix is sis_section_id:
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,

        [Parameter(Mandatory=$true)]
        [string]$CourseRole,

        [Parameter()]
        [switch]$Notify,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$Section="",

        [Parameter(Mandatory=$false)]
        [string]$NewStatus="active"
    )
    # build the route
    $EnrollmentUrl = "https://{0}/api/v1/courses/{1}/enrollments" -f $global:CanvasSite,$CourseId
    
    # get list of acceptable course roles
    if ($global:CourseRoleIds.count -eq 0){
        $RoleList = Get-CanvasRoles -TokenFilePath $TokenFilePath | Where-Object{$_.base_role_type -like "*Enrollment"}
        $RoleList | ForEach-Object{$global:CourseRoleIds += $_.id.tostring()}
    }

    # build the enrollment body
    $Enrollment = @{
        "user_id" = $CanvasUser
        "enrollment_state" = "active"
    }
    # control for role specifiers
    switch ($CourseRole.ToLower()) {
        { @("student","stu","participant") -contains $_} { 
            $CourseRole = "StudentEnrollment"
            $Enrollment.Add("type",$CourseRole)
        }
        { @("builder","designer") -contains $_} { 
            $CourseRole = "DesignerEnrollment"
            $Enrollment.Add("type",$CourseRole)
        }
        { @("ta","assistant") -contains $_} { 
            $CourseRole = "TaEnrollment"
            $Enrollment.Add("type",$CourseRole)
        }
        { @("teacher","instructor","professor","teacherenrollment") -contains $_} { 
            $CourseRole = "TeacherEnrollment"
            $Enrollment.Add("type",$CourseRole)
        }
        { @("ea","eduassist","eduassistant","educationalassistant") -contains $_} {
            $Enrollment.Add("role_id","28")
        }
        { @("communicator","tutor") -contains $_} {
            $Enrollment.Add("role_id","22")
        }
        { @("accreditor","dean","reviewer") -contains $_} {
            $Enrollment.Add("role_id","25")
        }
        { $global:CourseRoleIds -contains $_} {
            $Enrollment.Add("role_id",$CourseRole)
        }
        Default {Write-Host "unrecognized role definition: $($CourseRole)";break;}
    }
    # add notify if set
    if ($Notify){$Enrollment.Add("notify","true")}
    if ($Section -ne ""){$Enrollment.Add("course_section_id",$Section)}
    $EnrollmentBody = @{"enrollment"= $Enrollment}|ConvertTo-Json
    $NewEnrollment = Send-CanvasUpdate -CanvasApiUrl $EnrollmentUrl -RequestBody $EnrollmentBody -TokenFilePath $TokenFilePath    
    return $NewEnrollment
}
Set-Alias -Name New-CanvasEnrollment -Value New-CanvasMembership

function Get-CanvasCourseMemberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,
       
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [int32]$MaxResults = 150,

        [Parameter(Mandatory=$false)]
        [string]$Role="",

        [Parameter(Mandatory=$false)]
        [string]$PersonId=""
    )
    # build the URL
    $CourseUsersUrl = "https://{0}/api/v1/courses/{1}/enrollments" -f $global:CanvasSite,$CourseId
    
    if ($Role -ne ""){
        $CourseRole = ""
        switch ($Role.ToLower()){
            { @("teach","teacher","teacherenrollment","instructor","instructorenrollment") -contains $_} {
                $CourseRole = "TeacherEnrollment"
            }
            { @("ta","assistant") -contains $_} { 
                $CourseRole = "TaEnrollment"
            }
            { @("student","studentenrollment","stu") -contains $_} {
                $CourseRole = "StudentEnrollment"
            }
            { @("ea","eduassist","eduassistant","educationalassistant") -contains $_} {
                $CourseRole = "Educational%20Assistant"
            }
            { @("builder","designer") -contains $_} { 
                $CourseRole = "DesignerEnrollment"
            }
            { @("communicator","tutor") -contains $_} {
                $CourseRole = "Communicator"
            }
            { @("proctor","invigilator") -contains $_} {
                $CourseRole = Get-UrlEncodedString "Proctor (Testing Center)"
            }
            { @("accreditor","dean","reviewer") -contains $_} {
                $CourseRole = "Accreditor"
            }
            default {
                $CourseRole = Get-UrlEncodedString $Role
            }
        }
        $UrlAddition = "role=$($CourseRole)"
        $CourseUsersUrl = Add-UrlQueryParameter -ExistingUrl $CourseUsersUrl -QueryAddition $UrlAddition
    }
    if ($PersonId -ne ""){
        $UrlAddition = "user_id=$($PersonId)"
        $CourseUsersUrl = Add-UrlQueryParameter -ExistingUrl $CourseUsersUrl -QueryAddition $UrlAddition
    }

    Get-CanvasItemListFlattened -ApiUrl $CourseUsersUrl -ResultsPerCall 75 -TokenFilePath $tknPath
}
Set-Alias -Name Get-CanvasCourseEnrollments -Value Get-CanvasCourseMemberships

function Get-CanvasUserMemberships {
    <#
    .SYNOPSIS
    get canvas enrollments for user

    .DESCRIPTION
    get canvas enrollments for a user. By default only returns active
    
    API Allowed Values for state:
    active, invited, creation_pending, deleted, 
    rejected, completed, inactive, 
    current_and_invited, current_and_future, current_future_and_restricted, current_and_concluded
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,
       
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,
        
        [Parameter(Mandatory=$false)]
        [bool]$InactiveList=$false,

        [Parameter(Mandatory=$false)]
        [string]$CanvasTermSisId=""
    )
    # build the URL
    $CourseUsersUrl = "https://{0}/api/v1/users/{1}/enrollments" -f $global:CanvasSite,$CanvasUser
    if ($InactiveList){
        $CourseUsersUrl = Add-UrlQueryParameter -ExistingUrl $CourseUsersUrl -QueryAddition "state=inactive"
    }
    if ($CanvasTermSisId -ne "") {
        $CourseUsersUrl = Add-UrlQueryParameter -ExistingUrl $CourseUsersUrl -QueryAddition "enrollment_term_id=sis_term_id:$($CanvasTermSisId)"
    }
    # construct the parameters
    $MembershipListParams = @{
        CanvasApiUrl = $CourseUsersUrl
        TokenFilePath = $TokenFilePath
        PerPage = 100
    }
    # call the requestor
    Get-CanvasItemListFlattened @MembershipListParams
}
Set-Alias -Name Get-CanvasUserEnrollments -Value Get-CanvasUserMemberships

function Set-CanvasCourseMembershipStatus {
    <#
    .Synopsis 
    updates existing enrollments user course identifier and user sis identifier
    .Parameter CanvasCourse
    course identifier, use standard Canvas API searches such as sis_course_id:XXX 
    .Parameter CanvasUser
    username for the enrollment to update, must use prefix sis_user_id:
    .Parameter Status
    new status for enrollment, possible values: concluded,deleted,active,inactive
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string
    #>    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CourseId")]
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,

        [Parameter(Mandatory=$true)]
        [string]$Status,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath        
    )
    [bool]$continue = $false
    $ApiVerb = "PUT"
    $EnrollmentUpdateURl = ""
    $EnrTask = @{}
    $EnrId = ""
    # Retrieve User Information Details
    $UserInfo = Get-CanvasUserInfo -CanvasUserId $CanvasUser -TokenFilePath $TokenFilePath
    
    # check that the enrollment exists, get id if it does
    $CourseEnrs = Get-CanvasCourseMemberships -CanvasCourse $CanvasCourse -TokenFilePath $TokenFilePath -PersonId $UserInfo.id
    
    $UserEnr = $CourseEnrs | Where-Object{$_.user_id -eq $UserInfo.id}
    Write-Host $UserEnr.count.ToString()
    
    # make sure there is only one result, grab the ID
    if ($UserEnr.count -eq 1){
        $EnrId = $UserEnr[0].id
        # construct the parameters based on operation, course, id
        switch ($Status.ToLower()){
            { @("conclude","concluded") -contains $_} {
                $continue = $true
                $ApiVerb = "DELETE"
                $EnrollmentUpdateURl = "https://{0}/api/v1/courses/{1}/enrollments/{2}" -f $global:CanvasSite,$CanvasCourse,$EnrId
                $EnrTask.Add("task","conclude")
            }
            { @("delete","deleted","remove","removed") -contains $_} {
                $continue = $true
                $ApiVerb = "DELETE"
                $EnrollmentUpdateURl = "https://{0}/api/v1/courses/{1}/enrollments/{2}" -f $global:CanvasSite,$CanvasCourse,$EnrId
                $EnrTask.Add("task","delete")
            }
            { @("inactive","inactivate","inactivated") -contains $_} {
                $continue = $true
                $ApiVerb = "DELETE"
                $EnrollmentUpdateURl = "https://{0}/api/v1/courses/{1}/enrollments/{2}" -f $global:CanvasSite,$CanvasCourse,$EnrId
                $EnrTask.Add("task","inactivate")
            }
            { @("active","activate","activated","reactivate","reactivated") -contains $_} {
                $continue = $true
                $ApiVerb = "PUT"
                $EnrollmentUpdateURl = "https://{0}/api/v1/courses/{1}}/enrollments/{2}/reactivate" -f $global:CanvasSite,$CanvasCourse,$EnrId
            }
            default {Write-Host "unrecognized status: '$Status'"}
        }
        if ($continue -eq $true){
            # build it
            $UpdateArgs = @{
                "CanvasApiUrl"= $EnrollmentUpdateURl
                "ApiVerb" = $ApiVerb
                "RequestBody" = ConvertTo-Json $EnrTask
                "TokenFilePath" = $TokenFilePath
            }
            # do it
            Send-CanvasUpdate @UpdateArgs
        }
        else {
            Write-Host "Enrollment update cancelled."
        }
    }
    else {
        Write-Host "Could not find the single enrollment to update"
    }
}
Set-Alias -Name Set-CanvasEnrollmentStatus -Value Set-CanvasCourseMembershipStatus

function New-CanvasCourseCopy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$CourseSource,

        [Parameter(Mandatory=$true)]
        [String]$CourseDestination,

        [Parameter(Mandatory=$false)]
        [bool]$SkipSettings=$false,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [bool]$ShiftDates=$false,

        [Parameter(Mandatory=$false)]
        [string]$OldStart="",

        [Parameter(Mandatory=$false)]
        [string]$OldEnd="",

        [Parameter(Mandatory=$false)]
        [string]$NewStart="",

        [Parameter(Mandatory=$false)]
        [string]$NewEnd=""
    )
    $MigrationUrl = "https://{0}/api/v1/courses/{1}/content_migrations" -f $global:CanvasSite,$CourseDestination
    $MigrationSettings = @{
        source_course_id = $CourseSource
    }
    if ($SkipSettings){
        $MigrationSettings.Add("importer_skips","all_course_settings")
    }
    $MigrationObject = @{
        migration_type = "course_copy_importer"
        settings = $MigrationSettings
    }
    if ($ShiftDates -and ($OldStart -ne "") -and ($NewStart -ne "") -and ($OldEnd -ne "") -and ($NewEnd -ne "")){
        $DateShiftOptions = @{
            shift_dates     = $ShiftDates
            old_start_date  = $OldStart
            old_end_date    = $OldEnd
            new_start_date  = $NewStart
            new_end_date    = $NewEnd
        }
        $MigrationObject.Add("date_shift_options",$DateShiftOptions)
    }
    $MigrationBody = ConvertTo-Json $MigrationObject
    $MigrationTask = Send-CanvasUpdate -RequestBody $MigrationBody -CanvasApiUrl $MigrationUrl -TokenFilePath $TokenFilePath
    return $MigrationTask
}
Set-Alias -Name Start-CanvasCourseCopy -Value New-CanvasCourseCopy

function New-CanvasCommonsImport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$ResourceId,

        [Parameter(Mandatory=$true)]
        [String]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$CourseName,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # Get Commons JWT
    $JwtUrl = "https://{0}/api/lti/accounts/self/jwt_token?tool_launch_url=https://{1}/api/lti" -f $CanvasSite, $global:LorSite
    $MyJwt = Get-CanvasItem -CanvasApiUrl $JwtUrl -TokenFilePath $TokenFilePath
    $JwtBody = @{"jwt_token" = $MyJwt.jwt_token}|ConvertTo-Json
    $SessionUrl = "https://{0}/api/sessions" -f $global:LorSite
    $SessionInfo = Invoke-RestMethod -Method POST -Uri $SessionUrl -ContentType "application/json" -Body $JwtBody
    $CommonsHeader = @{"X-Session-ID" = $SessionInfo.sessionId}
    $UploadUrl = "https://{0}/api/resources/{1}/import" -f $global:LorSite, $ResourceId
    $CourseBody = @{
        id = $CourseId
        name = $CourseName
    }
    $UploadBody = @{
        courses = @($CourseBody)
    }
    $UploadBody = $UploadBody | ConvertTo-Json
    Invoke-RestMethod -Method POST -Uri $UploadUrl -Body $UploadBody -Headers $CommonsHeader -ContentType "application/json"
}
Set-Alias -Name Start-CanvasCommonsImport -Value New-CanvasCommonsImport

function New-CanvasCourseExport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$CourseId,

        [Parameter(Mandatory=$false)]
        [string]$ExportType="Course",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ExportSettings = @{
        skip_notifications = $true
    }
    switch ($ExportType.ToLower()) {
        "course" { $ExportSettings.Add("export_type","common_cartridge") }
        "files" { $ExportSettings.Add("export_type","zip") }
        { @("quiz","quizzes","test","tests") -contains $_} { $ExportSettings.Add("export_type","qti") }
        Default {$ExportSettings.Add("export_type","common_cartridge")}
    }
    $ExportStartUrl = "https://{0}/api/v1/courses/{1}/content_exports" -f $CanvasSite,$CourseId
    $ExportSettings = $ExportSettings | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $ExportStartUrl -RequestBody $ExportSettings -ApiVerb "POST" -TokenFilePath $TokenFilePath
}

function Get-CanvasCourseExports {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ExportListUrl = "https://{0}/api/v1/courses/{1}/content_exports" -f $global:CanvasSite,$CourseId
    # $result = Get-CanvasItemList -CanvasApiUrl $ExportListUrl -TokenFilePath $TokenFilePath
    $result = Get-CanvasItemListFlattened -ApiUrl $ExportListUrl -TokenFilePath $TokenFilePath
    return $result
}

function Set-CanvasCoursePublished {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$CourseUpdateUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $updatePart = @{"event"="offer"}
    $updateBody = @{"course"=$updatePart} | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $CourseUpdateUrl -ApiVerb "PUT" -RequestBody $updateBody -TokenFilePath $TokenFilePath
}

function Set-CanvasCourseStatus {
    <#
    .Synopsis
    update an existing course's visibility status
    
    .Parameter CourseId
    the course identifier.  use sis_course_id: prefix when specifying CRN
    
    .Parameter CourseStatus
    new status to assign to the course officailly allowed values:
    claim,offer,conclude,delete,undelete
    
    'claim' makes a course no longer visible to students. This action is also called “unpublish” on the web site. 
      A course cannot be unpublished if students have received graded submissions.
    
    'offer' makes a course visible to students. This action is also called “publish” on the web site.

    'conclude' prevents future enrollments and makes a course read-only for all participants. The course still appears 
    in prior-enrollment lists.

    'delete' completely removes the course from the web site (including course menus and prior-enrollment lists). 
    All enrollments are deleted. Course content may be physically deleted at a future date.

    'undelete' attempts to recover a course that has been deleted. This action requires account administrative rights. 
    (Recovery is not guaranteed; please conclude rather than delete a course if there is any possibility the course will 
    be used again.) The recovered course will be unpublished. Deleted enrollments will not be recovered.
    
    .Parameter TokenFilePath
    path of the file containing the token text stored as a secure string    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId,
        
        [Parameter(Mandatory=$true)]
        [string]$CourseStatus,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # Course Status Update route
    [string]$CourseUpdateUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    # format the status
    switch ($CourseStatus){
        {@("publish","published","available","visible","offer") -contains $_} {
            $CourseStatus = "offer"
        }
        {@("conclude","concluded","done","finished") -contains $_} {
            $CourseStatus = "conclude"
        }
        {@("claim","unavailable","unpublished") -contains $_} {
            $CourseStatus = "claim"
        }
        "delete" {
            $CourseStatus = "delete"
        }
        "undelete" {
            $CourseStatus = "undelete"
        }
        default {
            $CourseStatus = "claim"
        }
    }
    # format the content body for upload
    $updateBody = @{course = @{event = $CourseStatus}} | ConvertTo-Json
    # send the update
    Send-CanvasUpdate -CanvasApiUrl $CourseUpdateUrl -ApiVerb "PUT" -RequestBody $updateBody -TokenFilePath $TokenFilePath
}

function Set-CanvasCourseSelfenroll {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$CourseUpdateUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $updatePart = @{"self_enrollment"="true"}
    $updateBody = @{"course"=$updatePart} | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $CourseUpdateUrl -ApiVerb "PUT" -RequestBody $updateBody -TokenFilePath $TokenFilePath
}

function Set-CanvasCourseBlueprintStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [bool]$BlueprintStatus,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$CourseUpdateUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $updatePart = @{"blueprint" = $BlueprintStatus}
    $updateBody = @{"course" = $updatePart} | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $CourseUpdateUrl -ApiVerb "PUT" -RequestBody $updateBody -TokenFilePath $TokenFilePath
}

function Get-CanvasGraphQLResults {
    <#
    .Synopsis
        sends GraphQL query to Canvas and get JSON results back in the form of a custom object

    .Description
        recieves GraphQL query definition and variables, sends them to Canvas, returns the results of the query
        much of the request body building code is from Anthony Guimelli's project at https://github.com/anthonyg-1/PSGraphQL

    .Parameter TokenFilePath
        path to the secure string file containing the encrypted Canvas user token
    
    .Parameter Query
        text of the GraphQL query.  When importing from a file, make sure to use the -Raw switch with Get-Content
    #>    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$Query,

        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]$Variables
    )
    # construct end point url
    $GraphUrl = "https://{0}/api/graphql" -f $global:CanvasSite
    
    # build request header from token value
    $TokenString = Get-CanvasTokenString $TokenFilePath
    $Headers = @{"Authorization"="Bearer $TokenString"}
    
    # build request body from query
    $jsonRequestObject = [ordered]@{ }
    
    # Add variables hashtable to request json
        if ($PSBoundParameters.ContainsKey("Variables")) {
        $jsonRequestObject.Add("variables", $Variables)
    }

    # Trim all spaces and flatten query parameter value and add to request json
    $cleanedQueryInput = Compress-String -InputString $Query
    
    # perform some input validation on the query
    if ($cleanedQueryInput.ToLower() -notlike "query*" ) {
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList "Not a valid GraphQL query. Verify syntax and try again."
        Write-Error -Exception $ArgumentException -ErrorAction Stop
    }
        
    # Add query to the request json
    $jsonRequestObject.Add("query", $cleanedQueryInput)

    # Serialize request json
    [string]$jsonRequestBody = ""
    try {
        $jsonRequestBody = $jsonRequestObject | ConvertTo-Json -Depth 4 -Compress -ErrorAction Stop
    }
    catch {
        Write-Error -Exception $_.Exception -ErrorAction Stop
    }    

    # assemble request parameters
    $ReqParams = @{Uri = $GraphUrl
        Method = "POST"
        Headers = $Headers
        Body = $jsonRequestBody
        ContentType = "application/json"
        ErrorAction = "Stop"
    }

    $result = Invoke-RestMethod @ReqParams
    return $result   
}

function Invoke-CanvasCourseContentReset {
    [CmdletBinding()]
    param (
        [string]$CourseId,
        [string]$TokenFilePath
    )
    [string]$CourseResetUrl = "https://{0}/api/v1/courses/{1}/reset_content" -f $global:CanvasSite,$CourseId   
    $result = Send-CanvasUpdate -CanvasApiUrl $CourseResetUrl -ApiVerb "POST" -TokenFilePath $TokenFilePath
    return $result
}

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

function Get-CanvasRoleDetails {
    <#
    .Synopsis
    Returns details, including permissions for a Role in Canvas. Requires you to know the id number of the role you are enumerating. 
    Outputs the permissions to a CSV file.

    .Parameter RoleId
    the numeric id of the role

    .Parameter OutFile
    path to the output csv permissions file

    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RoleId,

        [Parameter(Mandatory=$true)]
        [string]$OutFile,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath       
    )
    begin{
        # write the csv file with header
        Set-Content -Path $OutFile -Value "Permission,Enabled,ReadOnly,Locked,Explicit,Self,Descendants,Group"
        
        $RoleUrl = "https://{0}/api/v1/accounts/1/roles/{1}" -f $global:CanvasSite,$RoleId
        
        # get all the role data
        $RoleData = Get-CanvasItem -CanvasApiUrl $RoleUrl -TokenFilePath $TokenFilePath
        
        # identify role permissions
        $RoleDataPermissionProperties = $RoleData.permissions | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        
        # enumerate settings for every role permission
        foreach($PropertyName in $RoleDataPermissionProperties){
            $Permission = $RoleData.permissions.$PropertyName
            $enbl = $Permission.enabled
            $lock = $Permission.locked
            $ronl = $Permission.readonly
            $expl = $Permission.explicit
            $self = $Permission.applies_to_self
            $dscn = $Permission.applies_to_descendants
            $grp = $Permission.group
            
            # write the settings to the csv file
            Add-Content -path "$OutFile" -Value "$PropertyName,$enbl,$ronl,$lock,$expl,$self,$dscn,$grp"
        }
        return $RoleData
    }
}

function Get-CanvasCoursePages {
    <#
    .Synopsis
    returns collection of pages in a course
    .Parameter CanvasCourse
    identifier for course, use sis_course_id: prefix to specify by CRN
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    .Parameter SortBy
    options are title, created_at, updated_at; defaults to title
    .Parameter SortOrder
    options are asc, desc; defaults to asc
    .Parameter SearchTerm
    search term; defaults to empty
    .Parameter PublishedOnly
    if true, include only published paqes. If false, exclude published pages.
    #>    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$SortBy="title",

        [Parameter(Mandatory=$false)]
        [string]$SortOrder="asc",

        [Parameter(Mandatory=$false)]
        [string]$SearchTerm="",

        [Parameter(Mandatory=$false)]
        [string]$PublishedOnly="na"
    )
    # build sort and search
    $ResultPageSize = "&per_page=100"
    # clean options
    $SortBy = $SortBy.ToLower()
    $SortOrder = $SortOrder.ToLower()
    $Published = $PublishedOnly.ToLower()
    $SearchOptions = ""
    # add sort by
    if ($SortBy.ToLower() -in ('title','created_at','updated_at')){
        $SearchOptions = "?sort=$SortBy"
    }
    else {$SearchOptions = "?sort=title"}
    # add sort order
    if (($SortBy -in ('title','created_at','updated_at')) -and ($SortOrder -in ('asc','desc'))){
        $SearchOptions += "&order=$SortOrder"
    }
    # add search term
    if ($SearchTerm -ne ""){
        $SearchTerm = Get-UrlEncodedString $SearchTerm
        $SearchOptions += "&search_term=$SearchTerm"
    }
    if ( ($Published -eq "true") -or ($Published -eq $false) ){
        $SearchOptions += "&published=$Published"
    }
    # build the URL
    $CoursePagessUrl = "https://{0}/api/v1/courses/{1}/pages{2}{3}" -f $global:CanvasSite,$CourseId,$SearchOptions,$ResultPageSize
    $pagelist = Get-CanvasItemListFlattened -ApiUrl $CoursePagessUrl -TokenFilePath $TokenFilePath -ResultsPerCall 99
    return $pagelist
}

function Get-CanvasCourseModules {
    <#
    .Synopsis
    returns collection of modules in a course
    .Parameter CanvasCourse
    identifier for course, use sis_course_id: prefix to specify by CRN
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CourseId")]
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$SearchTerm=""
    )

    # build the URL
    $CourseModulesUrl = "https://{0}/api/v1/courses/{1}/modules" -f $global:CanvasSite,$CanvasCourse
    
    # build search
    if ($SearchTerm -ne ""){
        $SearchQry = Get-UrlEncodedString $SearchTerm
        $SearchQry = "search_term=$($SearchQry)"
        $CourseModulesUrl = Add-UrlQueryParameter $CourseModulesUrl $SearchQry
    }
    
    # construct the parameters
    $ModuleListParams = @{
        "CanvasApiUrl" = $CourseModulesUrl
        "TokenFilePath" = $TokenFilePath
    }
    
    # retrieve
    Get-CanvasItemListFlattened @ModuleListParams
}

function Get-CanvasCourseFiles {
    <#
    .Synopsis
    retrieve list of files for a course
    .Parameter CanvasCourse
    identifier for course, use sis_course_id: prefix to specify by CRN
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$SearchTerm=""
    )
    #GET /api/v1/courses/:course_id/files
    # build sort and search
    $SearchOptions = ""
    if ($SearchTerm -ne ""){
        $SearchTerm = Get-UrlEncodedString $SearchTerm
        $SearchOptions += "?search_term=$SearchTerm"
    }    
    # build the URL
    $CourseFilesUrl = "https://{0}/api/v1/courses/{1}/files" -f $global:CanvasSite,$CourseId
    # construct the parameters
    $FileListParams = @{
        "CanvasApiUrl" = $CourseFilesUrl
        "TokenFilePath" = $TokenFilePath
    }
    # call the requestor
    Get-CanvasItemListFlattened @FileListParams      
}

function Get-CanvasCourseTabs {
    <#
    .Synopsis
    retrieve list of files for a course
    .Parameter CanvasCourse
    identifier for course, use sis_course_id: prefix to specify by CRN
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath

    )
    #GET /api/v1/courses/:course_id/tabs
    # build the URL
    $CourseTabsUrl = "https://{0}/api/v1/courses/{1}/tabs" -f $global:CanvasSite,$CourseId
    # construct the parameters
    $ListParams = @{
        CanvasApiUrl = $CourseTabsUrl
        TokenFilePath = $TokenFilePath
        PerPage = 100
    }
    # call the requestor
    $results = Get-CanvasItemListFlattened @ListParams
    return $results
}

function Get-CanvasSubAccounts {
    <#
    .Synopsis
    list sub accounts on Canvas instance
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$AccountId="self"
    )
    $AcctUrl = "https://{0}/api/v1/accounts/{1}/sub_accounts" -f $global:CanvasSite,$AccountId
    $AcctListParams = @{
        CanvasApiUrl = $AcctUrl
        TokenFilePath = $TokenFilePath
        PerPage = "100"
    }
    Get-CanvasItemListFlattened @AcctListParams
}

function Get-CanvasUserLogins {
    <#
    .Synopsis
    get logins details for a specific login user
    .Parameter CanvasUser
    username for lookup
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath            
    )
    $apiUrl = "https://{0}/api/v1/users/sis_login_id:{1}/logins" -f $global:CanvasSite,$CanvasUser
    Get-CanvasItemListFlattened -CanvasApiUrl $apiUrl -TokenFilePath $TokenFilePath
}

function Set-CanvasLoginStatus {
    <#
    .Synopsis
    configure the user's login state.  takes the standard login username only
    .Parameter CanvasUser
    username for lookup, example:jdoe123
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    .Parameter NewStatus
    status to set for the login.  The only two acceptable values are active and suspended.
    defaults to suspended.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$NewStatus = "suspended"
    )
    # code the status, options are active,suspended
    $NewStatus = $NewStatus.ToLower()
    if ( ($NewStatus -ne "suspended") -and ($NewStatus -ne "active") ){$NewStatus = "suspended"}
    
    # Get logins for the user
    $UserLogins = Get-CanvasUserLogins -CanvasUser $CanvasUser -TokenFilePath $TokenFilePath
    
    # display message and stop if multiple logins for the user
    if ($UserLogins.Count -ne 1){
        $Message = "{0} logins found for {1}.  use a custom call to https://{2}/api/v1/accounts/1/logins/<id> for the specific ID." -f $UserLogins.Count.ToString(),$CanvasUser,$global:CanvasSite
        Write-Host $Message
        # output list to console
        $UserLogins
        break;
    }
    else {
        $LoginId = $UserLogins[0].id
        #  PUT /api/v1/accounts/:account_id/logins/:id | login[workflow_state]	active, suspended
        $UpdateUrl = "https://{0}/api/v1/accounts/{1}/logins/{2}" -f $global:CanvasSite,"1",$LoginId.ToString()
        $UpdatePart = @{workflow_state = $NewStatus}
        $UpdateBody = @{login = $UpdatePart}
        $UpdateJson = $UpdateBody | ConvertTo-Json
        $UpdateParams = @{
            RequestBody = $UpdateJson
            CanvasApiUrl = $UpdateUrl
            ApiVerb = "PUT"
            TokenFilePath = $TokenFilePath
        }    
        Send-CanvasUpdate  @UpdateParams
    }
}

function Remove-CanvasAdmin {
    <#
    .Synopsis
    Remove a user's admin access.
    .Parameter CanvasUser
    login ID for lookup, example sis_login_id:jdoe123
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    .Parameter AccountId
    account from which to remove the admin rights
    .Parameter RoleId
    the role to which the user is currently assigned
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,

        [Parameter(Mandatory=$true)]
        [string]$AccountId,
        
        [Parameter(Mandatory=$true)]
        [string]$RoleId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # DELETE /api/v1/accounts/:account_id/admins/:user_id
    $AdminUrl = "https://{0}/api/v1/accounts/{1}/admins/{2}" -f $global:CanvasSite,$AccountId,$CanvasUser
    $UpdateJson = @{role = $CanvasRole;role_id = $RoleId} | ConvertTo-Json
    $UpdateParams = @{
        RequestBody = $UpdateJson
        CanvasApiUrl = $AdminUrl
        ApiVerb = "Delete"
        TokenFilePath = $TokenFilePath
    }    
    Send-CanvasUpdate  @UpdateParams    
}

function New-CanvasAdmin {
    <#
    .Synopsis
    Remove a user's admin access.
    .Parameter CanvasUser
    login ID for lookup, example sis_login_id:jdoe123
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    .Parameter AccountId
    account from which to remove the admin rights
    .Parameter RoleId
    the role to which the user is currently assigned
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,

        [Parameter(Mandatory=$true)]
        [string]$AccountId,
        
        [Parameter(Mandatory=$true)]
        [string]$RoleId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # POST /api/v1/accounts/:account_id/admins/:user_id
    $AdminUrl = "https://{0}/api/v1/accounts/{1}/admins" -f $global:CanvasSite,$AccountId
    $UserInfo = Get-CanvasUserInfo -CanvasUserId $CanvasUser -TokenFilePath $tknPath
    #$RoleInfo = Get-CanvasRoles
    $AdminSetup = @{
        user_id = $UserInfo.id
        role_id = $RoleId
        send_confirmation = $false
    }
    $UpdateJson = $AdminSetup | ConvertTo-Json
    $UpdateParams = @{
        RequestBody = $UpdateJson
        CanvasApiUrl = $AdminUrl
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }    
    Send-CanvasUpdate  @UpdateParams    
}

function Get-CanvasRole {
    [CmdletBinding()]
    param (
    
        [Parameter(Mandatory=$true)]
        [string]$AccountId,

        [Parameter(Mandatory=$true)]
        [string]$RoleId,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath        
    )
    # GET /api/v1/accounts/:account_id/roles/:id
    $RoleUrl = "https://{0}/api/v1/accounts/{1}/{2}" -f $global:CanvasSite, $AccountId, $RoleId
    $RoleInfo = Get-CanvasItem -CanvasApiUrl $RoleUrl -TokenFilePath $TokenFilePath
    return $RoleInfo
}
function Get-CanvasTerms {
    <#
    .Synopsis
    retrieve list of terms from Canvas
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    .Parameter Account
    optional account specifier, defaults to self   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$Account="self"
    )
    # GET /api/v1/accounts/:account_id/terms
    $TermsUrl = "https://{0}/api/v1/accounts/{1}/terms?include=course_count" -f $global:CanvasSite,$Account
    $TermList = Get-CanvasItemListFlattened -CanvasApiUrl $TermsUrl -TokenFilePath $TokenFilePath -PerPage 100
    return $TermList.enrollment_terms
}
Set-Alias -Name Get-CanvasCourseTerms -Value Get-CanvasTerms
Set-Alias -Name Get-CanvasEnrollmentTerms -Value Get-CanvasTerms

function Get-CanvasAccountDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$AccountId,
    
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    #GET /api/v1/accounts/:id
    $AccountUrl = "https://{0}/api/v1/accounts/{1}" -f $global:CanvasSite, $AccountId
    $AcctResult = Get-CanvasItem -CanvasApiUrl $AccountUrl -TokenFilePath $TokenFilePath
    return $AcctResult
}

function Get-CanvasTerm {
    <#
    .Synopsis
    retrieve single term from Canvas
    .PARAMETER TermCode
    full YYYYTC term code, example: 202030
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    .Parameter Account
    optional account specifier, defaults to self   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TermCode
    
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
        
        ,[Parameter(Mandatory=$false)]
        [string]$Account="self"
    )
    $TermsUrl = "https://{0}/api/v1/accounts/{1}/terms/sis_term_id:{2}" -f $global:CanvasSite,$Account,$TermCode
    $TermResponse = Get-CanvasItem -CanvasApiUrl $TermsUrl -TokenFilePath $TokenFilePath
    return $TermResponse
}

function New-CanvasNotification {
    <#
    .Synopsis 
    post a global notification into Canvas
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        
        [Parameter(Mandatory=$true)]
        [string]$Body,
        
        [Parameter(Mandatory=$false)]
        [string]$Account="self",
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$MessageIcon="information",

        [Parameter(Mandatory=$false)]
        [string]$StartMessage = (Get-Date).toString(),

        [Parameter(Mandatory=$false)]
        [string]$EndMessage = (Get-Date).AddDays(1).toString()
    )
    # POST /api/v1/accounts/:account_id/account_notifications
    $AncUrl = "https://{0}/api/v1/accounts/{1}/account_notifications" -f $global:CanvasSite,$Account
    $StartMessage = (Get-Date (Get-Date $StartMessage).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z').toString()
    $EndMessage = (Get-Date (Get-Date $EndMessage).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z').toString()
    $Msg = @{
        subject = $Subject
        message = $Body
        start_at = $StartMessage
        end_at = $EndMessage
        icon = $MessageIcon
    }
    $MsgJson = @{account_notification = $Msg} | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $AncUrl -RequestBody $MsgJson -ApiVerb "POST" -TokenFilePath $TokenFilePath
}

function Get-CanvasLogonReportForTerm {
    <#
    .Synopsis
    run a user access report for a term. then download it.
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TermId,
        
        [Parameter(Mandatory=$false)]
        [string]$Account="self",

        [Parameter(Mandatory=$false)]
        [string]$ReportName="zero_activity_csv",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # start a report    POST /api/v1/accounts/:account_id/reports/:report
    $ReportStartUrl = "https://{0}/api/v1/accounts/{1}/reports/{2}" -f $global:CanvasSite,$Account,$ReportName
    $ReportParams = @{parameters = @{enrollment_term_id = $TermId}}|ConvertTo-Json
    Send-CanvasUpdate -ApiVerb "POST" -RequestBody $ReportParams -CanvasApiUrl $ReportStartUrl -TokenFilePath $TokenFilePath
}

function Get-CanvasReportStatus {
    <#
    .Synopsis
    check the status of a report by report ID
    .Parameter ReportName
        report                             title
        ------                             -----
        eportfolio_report_csv              Eportfolio Report
        grade_export_csv                   Grade Export
        mgp_grade_export_csv               MGP Grade Export
        last_user_access_csv               Last User Access             @{enrollment_term_id=; course_id=; include_deleted=}
        last_enrollment_activity_csv       Last Enrollment Activity
        outcome_export_csv                 Outcome Export
        outcome_results_csv                Outcome Results
        provisioning_csv                   Provisioning
        recently_deleted_courses_csv       Recently Deleted Courses
        sis_export_csv                     SIS Export
        student_assignment_outcome_map_csv Student Competency
        students_with_no_submissions_csv   Students with no submissions
        unpublished_courses_csv            Unpublished Courses
        public_courses_csv                 Public Courses
        course_storage_csv                 Course Storage
        unused_courses_csv                 Unused Courses
        zero_activity_csv                  Zero Activity                @{enrollment_term_id=; start_at=; course_id=}
        user_access_tokens_csv             User Access Tokens
        lti_report_csv                     LTI Report
        user_course_access_log_csv         User Course Access Log    
    .Parameter ReportId
    id of the report instance
    .Parameter Account
    account identifer against which the report is being run
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ReportName,
        
        [Parameter(Mandatory=$true)]
        [string]$ReportId,

        [Parameter(Mandatory=$false)]
        [string]$Account="self",
        
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # status of report  GET /api/v1/accounts/:account_id/reports/:report/:id
    $ReportStatusUrl = "https://{0}/api/v1/accounts/{1}/reports/{2}/{3}" -f $global:CanvasSite,$Account,$ReportName,$ReportId
    Get-CanvasItem -CanvasApiUrl $ReportStatusUrl -TokenFilePath $TokenFilePath
}

function Start-CanvasUserReportForTerm {
    <#
    .Synopsis
    run a user access report for a term. then download it.
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TermId,
        
        [Parameter(Mandatory=$false)]
        [string]$Account="self",
        
        [Parameter(Mandatory=$false)]
        [string]$ReportName="sis_export_csv",

        [Parameter(Mandatory=$false)]
        [bool]$IncludeUsers=$true,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeCourses=$true,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeSections=$true,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeEnrollments=$true,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    
    $ReportUrl = "https://{0}/api/v1/accounts/{1}/reports/{2}" -f $global:CanvasSite,$Account,$ReportName
    $ParamatersData = @{parameters = @{
        enrollment_term_id = $TermId;
        users = $IncludeUsers;
        courses = $IncludeCourses;
        sections = $IncludeSections;
        enrollments = $IncludeEnrollments}
    }
    $ParamatersBody = $ParamatersData | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $ReportUrl -RequestBody $ParamatersBody -ApiVerb "POST" -TokenFilePath $TokenFilePath
}
Set-Alias -Name Start-CanvasSisReport -Value Start-CanvasUserReportForTerm

function Get-CurrentTermCode {
    <#
    .Synopsis
    returns likely current term code
    #>
    $nowstamp = Get-Date
    $m = $nowstamp.Month
    $y = $nowstamp.Year
    switch ($m){
        {@(1,2,3,4) -contains $_}{
            $tc = "10"
        }
        5{
            if ($nowstamp.Day -gt 10){
                $tc = "20"
            }
            else {
                $tc = "10"
            }
        }
        {@(6,7) -contains $_}{
            $tc = "20"
        }
        {@(8,9,10,11) -contains $_}{
            $tc = "30"
        }
        12{
            if ($nowstamp.Day -gt 20){
                $y++
                $tc = "10"
            }
            else {
                $tc = "30"
            }
        }
    }
    $tc = "{0}{1}" -f $y.ToString(),$tc.ToString()
    return $tc
}

function Invoke-CanvasSisMonitor {
    <#
    .SYNOPSIS
    Canvas SIS Monitor - Recursive
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SisJobId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath

        ,[Parameter(Mandatory=$false)]
        [int32]$MaxIterations = 15

        ,[Parameter(Mandatory=$false)]
        [int32]$PreviousIterations = 0

        ,[Parameter(Mandatory=$false)]
        [int32]$SleepSeconds = 30
    )
    $FinalMsg = ""
    try {
        $PreviousIterations++
        if ($PreviousIterations -le $MaxIterations){
            Write-Host ("Monitor check of job {0} number {1}" -f $SisJobId,$PreviousIterations.ToString())
            $CurrentStatus = Get-CanvasSisStatus -SisUploadRefId $SisJobId -TokenFilePath $TokenFilePath
            switch ($CurrentStatus.workflow_state) {                
                { @("imported","imported_with_messages","aborted","failed","failed_with_messages") -contains $_} {  
                    Write-Host ("Current finished status is {0}" -f $CurrentStatus.workflow_state)
                    $FinalMsg = "SIS import task {0} finished with state:{1}" -f $SisJobId,$CurrentStatus.workflow_state
                }                
                { @("created","importing") -contains $_} {  
                    Write-Host ("Current status is {0}, progress:{1}" -f $CurrentStatus.workflow_state,$CurrentStatus.progress)
                    Start-Sleep -Seconds $SleepSeconds
                    Invoke-CanvasSisMonitor -SisJobId $SisJobId -TokenFilePath $TokenFilePath -MaxIterations $MaxIterations -PreviousIterations $PreviousIterations -SleepSeconds $SleepSeconds
                }
                Default {
                    $FinalMsg =  "Unhandled workflow state for job {0}" -f $SisJobId.ToString()
                }
            }
        }
        else {
            $FinalMsg = "Max job monitor checks reached"
        }
    }
    catch {
        $FinalMsg = "Error monitoring workflow state for job {0}" -f $SisJobId
        Write-Host $_
        Write-Host $_.ScriptStackTrace
    }
    return $FinalMsg
}

function Invoke-CanvasReportMonitor {
    <#
    .SYNOPSIS
    Canvas report monitor - recursive
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ReportJobId
        
        ,[Parameter(Mandatory=$true)]
        [string]$ReportName

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath

        ,[Parameter(Mandatory=$false)]
        [int32]$MaxIterations = 15

        ,[Parameter(Mandatory=$false)]
        [int32]$PreviousIterations = 0

        ,[Parameter(Mandatory=$false)]
        [int32]$SleepSeconds = 30

        ,[Parameter(Mandatory=$false)]
        [string]$Account = "self"
    )
    $FinalMsg = ""
    $FinalStatus = ""
    try {
        $PreviousIterations++
        if ($PreviousIterations -le $MaxIterations){
            Write-Host ("Monitor check of report job {0} number {1}" -f $ReportJobId,$PreviousIterations.ToString())
            $CurrentStatus = Get-CanvasReportStatus -ReportName $ReportName -ReportId $ReportJobId -TokenFilePath $TokenFilePath -Account $Account
            switch ($CurrentStatus.status) {                
                { @("complete") -contains $_} {  
                    Write-Host ("Report status is {0}" -f $CurrentStatus.status)
                    $FinalStatus = $CurrentStatus.status
                    $FinalMsg = $CurrentStatus
                }
                { @("error") -contains $_} { 
                    $FinalStatus = $CurrentStatus.status
                    $FinalMsg = "Report job {0} failed with message:{1}" -f $ReportJobId,$CurrentStatus.parameters.extra_text
                    Write-Host $FinalMsg
                }    
                { @("created") -contains $_} {  
                    Write-Host ("Current status is {0}" -f $CurrentStatus.status)
                    Start-Sleep -Seconds $SleepSeconds
                    $ReMonitor = @{
                        ReportJobId = $ReportJobId
                        ReportName = $ReportName
                        TokenFilePath = $TokenFilePath
                        MaxIterations = $MaxIterations
                        PreviousIterations = $PreviousIterations
                        SleepSeconds = $SleepSeconds
                        Account = $Account
                    }
                    Invoke-CanvasReportMonitor @ReMonitor
                }
                Default {
                    Write-Host ("Current status is {0}" -f $CurrentStatus.status)
                    Start-Sleep -Seconds $SleepSeconds
                    $ReMonitor = @{
                        ReportJobId = $ReportJobId
                        ReportName = $ReportName
                        TokenFilePath = $TokenFilePath
                        MaxIterations = $MaxIterations
                        PreviousIterations = $PreviousIterations
                        SleepSeconds = $SleepSeconds
                        Account = $Account
                    }
                    Invoke-CanvasReportMonitor @ReMonitor
                    <#
                    $FinalStatus = "error"
                    $FinalMsg =  "Unhandled workflow state, {1}, for job {0}" -f $ReportJobId,$CurrentStatus.status
                    #>
                }
            }
        }
        else {
            $FinalMsg = "Max job monitor checks reached"
        }
    }
    catch {
        $FinalStatus = "error"
        $FinalMsg = "Error monitoring state for report job {0}" -f $SisJobId
        Write-Host $_
        Write-Host $_.ScriptStackTrace
    }
    return @{status=$FinalStatus;message=$FinalMsg}
}

function Start-CanvasSisJobMonitor {
    <#
    .SYNOPSIS 
    begin monitoring of Canvas SIS processing task
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SisJobId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath

        ,[Parameter(Mandatory=$false)]
        [int32]$MaxIterations = 10

        ,[Parameter(Mandatory=$false)]
        [int32]$SleepSeconds = 60
    )
    $SisJobMonResult = Invoke-CanvasSisMonitor -SisJobId $SisJobId -TokenFilePath $TokenFilePath -MaxIterations $MaxIterations -SleepSeconds $SleepSeconds
    return $SisJobMonResult
}

<#
function Set-CanvasCourseTeamsClassEnabled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    #api/v1/courses/:course_id/external_tools
    $CourseToolUrl = "https://{0}/api/v1/courses/{1}/external_tools" -f $global:CanvasSite,$CourseId
    $UpdateBody = @{client_id = "170000000000570"}|ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $CourseToolUrl -RequestBody $UpdateBody -ApiVerb "POST" -TokenFilePath $TokenFilePath
}

function Set-CanvasCourseTeamsMeetingsEnabled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    #api/v1/courses/:course_id/external_tools
    $CourseToolUrl = "https://{0}/api/v1/courses/{1}/external_tools" -f $global:CanvasSite,$CourseId
    $UpdateBody = @{client_id = "170000000000703"}|ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $CourseToolUrl -RequestBody $UpdateBody -ApiVerb "POST" -TokenFilePath $TokenFilePath
}
#>
function Set-CanvasCourseTabVisibility {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        ,[Parameter(Mandatory=$true)]
        [string]$TabId

        ,[Parameter(Mandatory=$true)]
        [bool]$Hidden
        
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # PUT /api/v1/courses/:course_id/tabs/:tab_id
    $UpdateBody = @{hidden = $Hidden.ToString()}|convertto-json
    $UpdateUrl = "https://{0}/api/v1/courses/{1}/tabs/{2}" -f $global:CanvasSite,$CourseId,$TabId
    Send-CanvasUpdate -CanvasApiUrl $UpdateUrl -RequestBody $UpdateBody -ApiVerb "PUT" -TokenFilePath $TokenFilePath

}

<#
function Set-AllyConfigVisibilityAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [bool]$Visible
        
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    #/api/v1/accounts/:account_id/external_tools/:external_tool_id
    $VisiblityUrl = "https://{0}/api/v1/accounts/1/external_tools/54" -f $global:CanvasSite
    $VisibilityUpdate = @{account_navigation = @{enabled = $Visible.ToString()}}|ConvertTo-Json
    $UpdateParams = @{
        CanvasApiUrl = $VisiblityUrl
        RequestBody = $VisibilityUpdate
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    $UpdateResult = Send-CanvasUpdate @UpdateParams
    return $UpdateResult
}
#>

function Set-CanvasToolVisibilityDefault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ToolId
        
        ,[Parameter(Mandatory=$true)]
        [string]$ToolName

        ,[Parameter(Mandatory=$true)]
        [bool]$Visible

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    [string]$Visibility = "disabled"
    if ($Visible){$Visibility = "enabled"}
    $UpdateUrl = "https://{0}/api/v1/accounts/1/external_tools/{1}" -f $global:CanvasSite,$ToolId
    $UpdateUrl += "?course_navigation[default]={0}&name={1}" -f $Visibility,$ToolName
    $UpdateParams = @{
        CanvasApiUrl = $UpdateUrl
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    $UpdateResult = Send-CanvasUpdate @UpdateParams
    return $UpdateResult
}

function New-CanvasCourseSection {
    <#
    .SYNOPSIS
    create a new section in an existing Canvas course

    .PARAMETER CourseId
    course identfier, use sis_course_id: for CRN

    .PARAMETER NewSectionSisId
    SIS ID to use for the new section

    .PARAMETER NewSectionName
    name for the new course section

    .PARAMETER StartDate
    local date (and optionally time) to use for the section access to begin for students
    the function will convert the local time to the correct format in zulu

    .PARAMETER EndDate
    local date (and optionally time) to use for the section access to end for students
    the function will convert the local time to the correct format in zulu

    .PARAMETER Restricted
    boolean to limit student enrollment participation to section dates. defaults to true
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$NewSectionSisId
        
        ,[Parameter(Mandatory=$true)]
        [string]$NewSectionName

        ,[Parameter(Mandatory=$false)]
        [string]$StartDate=""

        ,[Parameter(Mandatory=$false)]
        [string]$EndDate=""

        ,[Parameter(Mandatory=$false)]
        [bool]$Restricted=$true

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    #POST /api/v1/courses/:course_id/sections
    # format the api url
    $NewSectionUrl = "https://{0}/api/v1/courses/{1}/sections" -f $global:CanvasSite,$CourseId
    # structure the section data
    $NewSectionData = @{
        course_section = @{
            name = $NewSectionName
            sis_section_id = $NewSectionSisId
        }
    }
    # add start date if specified
    if ($StartDate -ne ""){
        $StartDate = Get-IsoDate $StartDate
        $NewSectionData.course_section.add("start_at",$StartDate)
    }
    # add the end date if specified
    if ($EndDate -ne ""){
        $EndDate = Get-IsoDate $EndDate
        $NewSectionData.course_section.add("end_at",$EndDate)
    }
    if ($Restricted){
        $NewSectionData.course_section.add("restrict_enrollments_to_section_dates","true")
    }
    # format the data for upload
    $NewSectionBody = $NewSectionData|ConvertTo-Json
    # configure upload parameters
    $NewSectionParams = @{
        CanvasApiUrl = $NewSectionUrl
        RequestBody = $NewSectionBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewSectionResult = Send-CanvasUpdate @NewSectionParams
    return $NewSectionResult
}

function Set-CanvasCourseFormat {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$false)]
        [string]$NewFormat = ""

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # PUT /api/v1/courses/:id
    $UpdateBody = @{course = @{course_format = $NewFormat}}|convertto-json
    $UpdateUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    $UpdateResult = Send-CanvasUpdate -CanvasApiUrl $UpdateUrl -RequestBody $UpdateBody -ApiVerb "PUT" -TokenFilePath $TokenFilePath
    return $UpdateResult
}
Set-Alias -Name Set-CanvasCourseModality -Value Set-CanvasCourseFormat

function Set-CanvasCourseTerm {
    <#
    .Synopsis
    Update the term to which a course is associated
    .Parameter CourseId
    identifier for the course. can be any id for the course, including sis_course_id:
    .Parameter TermId
    the numerical ID of the term.  must use the numerical ID of the term (as properties of the term, NOT the sis_term_id)
    to enumerate existing terms, run Get-CanvasTerms
    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token  
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$TermId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    # structure the new data
    $NewData = @{
        course = @{
            term_id = $TermId
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $CourseUpdateResult = Send-CanvasUpdate @NewDataParams
    return $CourseUpdateResult
}

function Remove-CanvasCoursePage {
    [CmdletBinding()]
    param (
        # canvas course identifier, for crn use prefix sis_course_id:
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        # page id or url of page to delete
        ,[Parameter(Mandatory=$true)]
        [string]$PageId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/pages/{2}" -f $global:CanvasSite,$CourseId,$PageId
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $result = Send-CanvasUpdate @NewDataParams
    $msg = "page deleted $($result.title)"
    if (Test-LogExistence){
        Add-LogEntry $msg
    }
    else {
        if ($VerbosePreference -in @("Continue","SilentlyContinue")){
            Write-Host $msg
        }
    }    
}

function Remove-CanvasCoursePages {
    [CmdletBinding()]
    param (
        # canvas course identifier, for crn use prefix sis_course_id:
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    
    $Pages = Get-CanvasCoursePages -CanvasCourse $CourseId -TokenFilePath $TokenFilePath
    foreach ($Page in $Pages){
        # configure page parameters
        $DelDataParams = @{
            CourseId = $CourseId
            PageId = $Page.page_id
            TokenFilePath = $TokenFilePath
        }
        # send the update
        Remove-CanvasCoursePage @DelDataParams
    }
}

function Remove-CanvasCourseModules {
    [CmdletBinding()]
    param (
        # canvas course identifier, for crn use prefix sis_course_id:
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $Modules = Get-CanvasCourseModules -CanvasCourse $CourseId -TokenFilePath $TokenFilePath
    foreach ($Module in $Modules){
        # configure upload parameters
        $NewDataParams = @{
            CourseId = $CourseId
            ModuleId = $Module.id
            TokenFilePath = $TokenFilePath
        }
        # send the update
        Remove-CanvasCourseModule @NewDataParams
    }
}

function Remove-CanvasCourseModule {
    [CmdletBinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$CourseId

        ,[Parameter(Mandatory)]
        [string]$ModuleId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/modules/{2}" -f $global:CanvasSite, $CourseId, $ModuleId
    # configure upload parameters
    $DelDataParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $result = Send-CanvasUpdate @DelDataParams

    $msg = "module deleted $($result.name)"
    if (Test-LogExistence){
        Add-LogEntry $msg
    }
    else {
        if ($VerbosePreference -in @("Continue","SilentlyContinue")){
            Write-Host $msg
        }
    }
}
function Get-CanvasCourseAssignmentGroups {
    [CmdletBinding()]
    param (
        # canvas course identifier, for crn use prefix sis_course_id:
        [Parameter(Mandatory=$true)]
        [string]$CourseId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/assignment_groups?include=assignments&per_page=100" -f $global:CanvasSite,$CourseId
    $AsgnGroupListParams = @{
        "CanvasApiUrl" = $ApiUrl
        "TokenFilePath" = $TokenFilePath
    }
    # call the requestor
    Get-CanvasItemList @AsgnGroupListParams
}

function Remove-CanvasCourseAssignmentGroup {
    [CmdletBinding()]
    param (
        # canvas course identifier, for crn use prefix sis_course_id:
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        # assignment group ID
        ,[Parameter(Mandatory=$true)]
        [string]$AssignmentGroupId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/assignment_groups/{2}" -f $global:CanvasSite,$CourseId,$AssignmentGroupId
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $result = Send-CanvasUpdate @NewDataParams
    Write-Host "deleted assignment group '$($result.name)'"
}

function Set-CanvasCourseQuota {
    [CmdletBinding()]
    param (
        # canvas course identifier
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        # new quota in megabytes
        ,[Parameter(Mandatory=$true)]
        [uint]$Quota
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    # structure the new data
    $NewData = @{
        course = @{
            storage_quota_mb = $Quota.ToString()
        }
    }
    
    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasMigrationStatus {
    [CmdletBinding()]
    param (
        # Canvas course identifier
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        # migration id
        ,[Parameter(Mandatory=$true)]
        [string]$MigrationId
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/content_migrations/{2}" -f $global:CanvasSite,$CourseId,$MigrationId

    # configure call parameters
    $MigParams = @{
        CanvasApiUrl = $ApiUrl
        TokenFilePath = $TokenFilePath
    }
    
    # send the request
    $ItemResult = Get-CanvasItem @MigParams
    return $ItemResult
}

function Get-CanvasProgress {
    [CmdletBinding()]
    param (
        # Progress ID from end of URL
        [Parameter(Mandatory=$true)]
        [string]$ProgressId
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/progress/{1}" -f $global:CanvasSite,$ProgressId

    # configure call parameters
    $MigParams = @{
        CanvasApiUrl = $ApiUrl
        TokenFilePath = $TokenFilePath
    }
    
    # send the request
    $ItemResult = Get-CanvasItem @MigParams
    return $ItemResult
}

function Reset-CanvasLinkVerifier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FileId

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/files/{1}/reset_verifier" -f $global:CanvasSite,$FileId
    
    $NewDataBody = ""

    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "Delete"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasRoles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath

        ,[Parameter(Mandatory=$false)]
        [string]$AccountId="1"
    )
    $RoleUrl = "https://{0}/api/v1/accounts/{1}/roles" -f $global:CanvasSite,$AccountId
    $RoleList = Get-CanvasItemList -CanvasApiUrl $RoleUrl -TokenFilePath $TokenFilePath -PerPage 50
    return $RoleList
}

function Get-CanvasCourseRoles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $RoleList = Get-CanvasRoles -TokenFilePath $TokenFilePath | Where-Object{$_.base_role_type -like "*Enrollment"}
    return $RoleList
}

function Get-CanvasOutcomeImportStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ImportId
        
        ,[Parameter(Mandatory=$false)]
        [string]$account="self"
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # " /api/v1/accounts/self/outcome_imports/:id"
    $OcImportUrl = "https://{0}/api/v1/accounts/{1}/outcome_imports/{2}" -f $CanvasSite, $account, $ImportId
    $Status = Get-CanvasItemWithVars -CanvasApiUrl $OcImportUrl -TokenFilePath $TokenFilePath
    if ($Status.statuscode -eq 200) {
        return $Status.result
    }
    else {
        return "Error retrieving report: $($Status.StatusCode), $($Status.result.message)"
    }
}

function Get-CanvasContentMigrationsForCourse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
                
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # /api/v1/courses/:course_id/content_migrations
    $MigListUrl = "https://{0}/api/v1/courses/{1}/content_migrations" -f $CanvasSite, $CourseId
    $MigListParams = @{
        CanvasApiUrl = $MigListUrl 
        TokenFilePath = $TokenFilePath 
        PerPage = 50
    }
    $MigList = Get-CanvasItemList @MigListParams
    return $MigList
}

function Get-CanvasCourseAnnouncements {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/discussion_topics?only_announcements=true" -f $global:CanvasSite, $CourseId
       
    # $ListResult = Get-CanvasItemListWithVars @DataParams
    $ListResult = Get-CanvasItemListFlattened -ApiUrl $ApiUrl -ResultsPerCall 99 -TokenFilePath $tknPath
    $ResultData = @{
        result = $ListResult
    }
    return $ResultData
}

function Update-CanvasPageContents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("CanvasCourse")]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$PageUrlOrId
        
        ,[Parameter(Mandatory=$false)]
        [string]$ContentBody=""
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    #PUT /api/v1/courses/:course_id/pages/:url_or_id
    $ApiUrl = "https://{0}/api/v1/courses/{1}/pages/{2}" -f $global:CanvasSite, $CourseId, $PageUrlOrId
    # structure the new data
    $NewData = @{
        wiki_page = @{
            body = $ContentBody
        }
    }
    
    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasCustomGradeColumn {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$ColumnId
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/custom_gradebook_columns/{2}" -f $global:CanvasSite, $CourseId, $ColumnId

    # send the request
    $ItemResult = Get-CanvasItemWithVars -CanvasApiUrl $ApiUrl -TokenFilePath $TokenFilePath
    return $ItemResult
}

function Get-CanvasCustomGradeColumns {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/custom_gradebook_columns" -f $global:CanvasSite, $CourseId

    # send the request
    # $ItemResult = Get-CanvasItemListWithVars -CanvasApiUrl $ApiUrl -TokenFilePath $TokenFilePath
    $GradeColumns = Get-CanvasItemListFlattened -ApiUrl $ApiUrl -TokenFilePath $tknPath
    $GradeColumnsData = @{
        result = $GradeColumns
    }
    return $GradeColumnsData
}

function Remove-CanvasCustomGradeColumn {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$ColumnId
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/custom_gradebook_columns/{2}" -f $global:CanvasSite, $CourseId, $ColumnId

    # configure upload parameters
    $DeleteParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }

    # send the update
    $ItemResult = Send-CanvasUpdate @DeleteParams
    return $ItemResult
}

function New-CanvasCustomGradeColumn {
    [CmdletBinding()]
    param (
        # course identifier
        [Parameter(Mandatory)]
        [string]$CourseId
        # title of new notes column
        ,[Parameter(Mandatory)]
        [string]$ColumnTitle
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/custom_gradebook_columns" -f $global:CanvasSite, $CourseId, $ColumnTitle
    # structure the new data
    $NewData = @{
        column = @{
            title = $ColumnTitle
            hidden = $false
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function New-CanvasSubAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ParrentAccountId
        
        ,[Parameter(Mandatory=$true)]
        [string]$Name

        ,[Parameter(Mandatory=$true)]
        [string]$SisId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/accounts/{1}/sub_accounts" -f $global:CanvasSite, $ParrentAccountId
    # structure the new data
    $NewData = @{
        account = @{
            name = $Name
            sis_account_id = $SisId
        }
    }
    
    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Update-CanvasCourseAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$NewAccountId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite, $CourseId
    # structure the new data
    $NewData = @{
        course = @{
            account_id = $NewAccountId
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $ItemResult = Send-CanvasUpdate @NewDataParams
    return $ItemResult
}

function Get-CanvasModuleItems {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId

        ,[Parameter(Mandatory)]
        [string]$ModuleId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/modules/{2}/items" -f $global:CanvasSite, $CourseId, $ModuleId
    # $ModuleItems = Get-CanvasItemList -CanvasApiUrl $ApiUrl -TokenFilePath $TokenFilePath -PerPage 99
    $ModuleItemList = Get-CanvasItemListFlattened -ApiUrl $ApiUrl -TokenFilePath $TokenFilePath
    return $ModuleItemList
}

function Set-CanvasModuleItemNewTabStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$ModuleId

        ,[Parameter(Mandatory)]
        [string]$ItemId

        ,[Parameter(Mandatory)]
        [bool]$OpenInNewTab
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/modules/{2}/items/{3}" -f $global:CanvasSite, $CourseId, $ModuleId, $ItemId
    Write-Verbose "UpdateURL $ApiUrl"
    # structure the new data
    $NewData = @{
        module_item = @{
            new_tab = $OpenInNewTab
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $UpdateItemResult = Send-CanvasUpdate @NewDataParams
    return $UpdateItemResult
}

function Set-CanvasCourseDateRestrictions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$false)]
        [bool]$Restricted = $true
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/settings" -f $global:CanvasSite, $CourseId
    # structure the new data
    $NewData = @{
        restrict_student_past_view = $Restricted
        restrict_student_future_view = $Restricted
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $UpdateItemResult = Send-CanvasUpdate @NewDataParams
    return $UpdateItemResult
}

function Get-CanvasCourseSettings{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $ApiUrl = "https://{0}/api/v1/courses/{1}/settings" -f $CanvasSite, $CourseId
    $CourseSettings = Get-CanvasItem -CanvasApiUrl $ApiUrl -TokenFilePath $TokenFilePath
    return $CourseSettings
}

function Get-PgSqlResults {
    <#
    .SYNOPSIS
    get postgres sql query results

    .PARAMETER ConnectionString
    database connection string, use DSN name if one is configured

    .PARAMETER DatabaseUser
    Database connection username

    .PARAMETER DatabasePass
    Database connection password

    .PARAMETER Query
    SQL query to execute

    .PARAMETER OutputType
    query result output type: screen, csv, object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConnectionString

        ,[Parameter(Mandatory=$false)]
        [string]$DatabaseUser

        ,[Parameter(Mandatory=$false)]
        [string]$DatabasePass

        ,[Parameter(Mandatory)]
        [string]$Query

        ,[Parameter(Mandatory)]
        [ValidateSet("object","csv","screen")]
        [string]$OutputType
    )
    # Create output path for query results file
    [string]$OutputDirectory = $env:SystemDrive + "\TEMP"
    if (!(Test-Path -Path $OutputDirectory)){mkdir $OutputDirectory|out-null}
    [string]$OutFile = $OutputDirectory + "\Canvas-PgData.csv"
    $DbUser = $DatabaseUser.Trim()
    $DbPass = Get-CanvasTokenString -KeeperFile $DatabasePass
    try {
        # define the database connection object
        $Conn = New-Object -comobject ADODB.Connection
    
        # Open the database connection using the DSN
        if ($null -ne $DatabaseUser -and $null -ne $DatabasePass){
            $Conn.Open($ConnectionString,$DbUser,$DbPass)
        }
        else {
            $Conn.Open($ConnectionString)
        }
    
        # execute the query and handle the result
        $RecordSet = $Conn.Execute("$Query")
        if ($RecordSet.EOF -ne $true){
            $RowCount = 0
            while ($RecordSet.EOF -ne $True)
            {
                # get the column names
                if ($RowCount -eq 0){
                    [string]$HeaderString = ""
                    foreach ($fielddata in $RecordSet.Fields) {
                        $HeaderString += "," + $fielddata.Name
                    }
                    $HeaderString = $HeaderString.Trim(',')
                    switch ($OutputType) {
                        "screen" { Write-Host $HeaderString }
                        { @("csv","object") -contains $_} { Set-Content -Path $OutFile -Value $HeaderString }
                        Default { }
                    }
                }
    
                # build output row based on recordset row data
                [string]$RowString = ""
                $ColCount = 0
                foreach ($Field in $RecordSet.Fields)
                {
                    # add row data
                    if($ColCount -gt 0) {
                        $RowString = $RowString + ",`"" + $Field.value + "`""
                    }
                    else {
                        $RowString = "`"" + $Field.value + "`""
                    }
                    $ColCount++
                }
                switch ($OutputType) {
                    "screen" { Write-Host $RowString }
                    { @("csv","object") -contains $_} { Add-Content -Path $OutFile -Value $RowString }
                    Default { }
                }
                $RowCount++
                $RecordSet.MoveNext()
            }
        }
        else {
            Write-Host "No records retrieved from database"
        }
    }
    catch {
        Write-Host "data error"
    }
    finally {
        # Close the connection
        if ($Conn.State -ne 0){
            $Conn.Close()
        }
    }
    # return based on output selection
    switch ($OutputType){
        "screen" {
            return "finished"
        }
        "csv" {
            return $OutFile
        }
        "object"{
            $ResultData = Import-Csv -Path $OutFile
            return $ResultData
        }
    }
}

function Update-CanvasCourseEndDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$EndDate
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    
    # format date to ISO standard
    $NewEndDate = Get-IsoDate -DateInputString $EndDate
    
    # structure the new data
    $NewData = @{
        course = @{
            end_at = $NewEndDate
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    
    # send the update
    $UpdateResult = Send-CanvasUpdate @NewDataParams
    return $UpdateResult
}

function Update-CanvasCourseStartDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CourseId
        
        ,[Parameter(Mandatory=$true)]
        [string]$StartDate
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CourseId
    
    # format date to ISO standard
    $NewStartDate = Get-IsoDate -DateInputString $StartDate
    
    # structure the new data
    $NewData = @{
        course = @{
            start_at = $NewStartDate
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    
    # send the update
    $UpdateResult = Send-CanvasUpdate @NewDataParams
    return $UpdateResult
}

function Set-CanvasLoginPassword {
    <#
    .SYNOPSIS
    update the password for an account login that uses canvas for authentication

    .PARAMETER AccountId
    Account identifier, use 1 or self for most users

    .PARAMETER LoginId
    Numerical id for the login (not the user); 
    To get the logins for a user, run Get-CanvasUserLogins

    .PARAMETER NewSecret
    Plain text to use for the new password

    .PARAMETER TokenFilePath
    path to the secure string file containing the API user token
    #>
    [CmdletBinding()]
    param (
        # account identifier, use 1 or self for most users    
        [Parameter(Mandatory=$true)]
        [string]$AccountId
        # 
        ,[Parameter(Mandatory=$true)]
        [string]$LoginId
        
        # plain text for the new password
        ,[Parameter(Mandatory=$true)]
        [string]$NewSecret
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    # /api/v1/accounts/:account_id/logins/:id
    $ApiUrl = "https://{0}/api/v1/accounts/{1}/logins/{2}" -f $global:CanvasSite, $AccountId, $LoginId
    # structure the new data
    $NewData = @{
        login = @{
            password = $NewSecret
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdateWithVars @NewDataParams
    $ReturnMessage = "unhandled response status"
    if ($NewItemResult.StatusCode.ToString() -eq "200"){
        $ReturnMessage = "password updated for login id:{0} belonging to user id:{1}" -f $NewItemResult.result.id, $NewItemResult.result.user_id
    } 
    else {
        $ReturnMessage = "unable ({1}) to update password: {0}" -f $NewItemResult.result.errors.message, $NewItemResult.StatusCode
    }
    return $ReturnMessage
}

function Update-CanvasCourseSectionEndDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SectionId
        
        ,[Parameter(Mandatory)]
        [string]$EndDate
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/sections/{1}" -f $global:CanvasSite, $SectionId
    
    # structure the new data
    $NewDate = Get-IsoDate $EndDate
    $NewData = @{
        course_section = @{
            end_at = $NewDate.ToString()
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}
function Update-CanvasCourseSectionStartDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SectionId
        
        ,[Parameter(Mandatory)]
        [string]$EndDate
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/sections/{1}" -f $global:CanvasSite, $SectionId
    
    # structure the new data
    $NewDate = Get-IsoDate $EndDate
    $NewData = @{
        course_section = @{
            start_at = $NewDate.ToString()
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasQuiz {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$QuizId

        ,[Parameter(Mandatory=$false)]
        [switch]$QuizEngineClassic
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    # classic: /api/v1/courses/:course_id/quizzes/:id
    # new qzs: /api/quiz/v1/courses/:course_id/quizzes/:assignment_id
    $ApiUrl = "https://{0}/api/quiz/v1/courses/{1}/quizzes/{2}" -f $global:CanvasSite, $CourseId, $QuizId
    if ($QuizEngineClassic){
        $ApiUrl = "https://{0}/api/v1/courses/{1}/quizzes/{2}" -f $global:CanvasSite, $CourseId, $QuizId
    }
    # send the call
    $QuizInfo = Get-CanvasItemWithVars -CanvasApiUrl $ApiUrl -TokenFilePath $TokenFilePath
    return $QuizInfo.result
}

function Set-CanvasCourseHome {
    <#
    .SYNOPSIS
    Configure the first item to display when accessing the course's default URL

    .PARAMETER CourseId
    Canvas course identifier. To use the CRN, use the standard prefix sis_course_id:Full_CRN

    .PARAMETER HomeOption
    Available home options are "feed","wiki","modules","syllabus","assignments"

    .PARAMETER TokenFilePath
    path to the secure string file containing the API user token

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        # available home options are "feed","wiki","modules","syllabus","assignments"
        ,[Parameter(Mandatory)]
        [string]$HomeOption
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite, $CourseId
    
    # structure the new data
    $HomeOption = $HomeOption.ToLower()
    switch ($HomeOption){
        {@("wiki","page","homepage","startpage") -contains $_} {
            $HomeOption = "wiki"
        }
        "modules" {
            $HomeOption = "modules"
        }
        "syllabus" {
            $HomeOption = "syllabus"
        }
        {@("assignments","homework") -contains $_} {
            $HomeOption = "assignments"
        }
        Default {$HomeOption = "modules"}
    }
    $NewData = @{
        course = @{
            default_view = $HomeOption
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Set-CanvasCourseFrontpage {
    <#
    .SYNOPSIS
    Set the URL for the landing page of the course

    .PARAMETER CourseId
    Canvas course identifier. To use the CRN, use the standard prefix sis_course_id:Full_CRN
    
    .PARAMETER PageUrl
    Relative pages URL for example, 'welcome-to-this-course'. This URL can be found in the page property, url.

    .PARAMETER TokenFilePath
    path of the file containing the token text stored as a secure string
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        # relative pages URL for example, 'welcome-to-this-course'. This URL can be found in the page property, url.
        ,[Parameter(Mandatory)]
        [string]$PageUrl
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/pages/{2}" -f $global:CanvasSite, $CourseId, $PageUrl
    # structure the new data
    $NewData = @{
        wiki_page = @{
            front_page = $true
        }
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasCourseAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$AssignmentId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/assignments/{2}" -f $global:CanvasSite, $CourseId, $AssignmentId

    # configure request parameters
    $DataParams = @{
        CanvasApiUrl = $ApiUrl
        TokenFilePath = $TokenFilePath
    }
    # send the request
    $ItemResult = Get-CanvasItem @DataParams
    return $ItemResult
}

function Get-CanvasCourseAssignments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/assignments" -f $global:CanvasSite, $CourseId
    # structure the new data
    
    # configure request parameters
    $DataParams = @{
        CanvasApiUrl = $ApiUrl
        TokenFilePath = $TokenFilePath
        PerPage = 99
    }
    # send the request
    $ItemListResult = Get-CanvasItemListFlattened @DataParams
    return $ItemListResult
}

function Remove-CanvasCourseAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$AssignmentId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/assignments/{2}" -f $global:CanvasSite, $CourseId, $AssignmentId
    
    # configure delete parameters
    $DataParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $ItemResult = Send-CanvasUpdate @DataParams
    return $ItemResult
}

function Remove-CanvasCourseAssignments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # Retrieve list of assignments to delet
    $AssignmentsToDelete = Get-CanvasCourseAssignments -CourseId $CourseId -TokenFilePath $TokenFilePath
    # remove each assignment in list
    foreach ($Assignment in $AssignmentsToDelete){
        $AssgnId = $Assignment.id.ToString()
        $RemParams = @{
            CourseId = $CourseId
            AssignmentId = $AssgnId
            TokenFilePath = $TokenFilePath
        }
        $DelResult = Remove-CanvasCourseAssignment @RemParams
        Write-Host "Assignment $($AssgnId) in Course $($CourseId) is now $($DelResult.workflow_state)"
    }
    return "Finished removing assignments from $($CourseId)"
}

function Remove-CanvasCourseDiscussionTopic {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId
        
        ,[Parameter(Mandatory)]
        [string]$TopicId
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/courses/{1}/discussion_topics/{2}" -f $global:CanvasSite, $CourseId, $TopicId
    
    # configure Deletion parameters
    $DataParams = @{
        CanvasApiUrl = $ApiUrl
        ApiVerb = "DELETE"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $ItemResult = Send-CanvasUpdate @DataParams
    return $ItemResult
}

function Remove-CanvasCourseAnnouncements {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CourseId

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # Enumerate announcement topics
    $AnnouncementList = Get-CanvasCourseAnnouncements -CourseId $CourseId -TokenFilePath $TokenFilePath
    # Iterate through anc list
    foreach ($AnnouncementTopic in $AnnouncementList.result){
        $AncId = $AnnouncementTopic.id.ToString()
        $DelResult = Remove-CanvasCourseDiscussionTopic -CourseId $CourseId -TopicId $AncId -TokenFilePath $TokenFilePath
        Write-Host "Topic $($AncId) in $($CourseId) now $($DelResult.workflow_state)|$($DelResult.title)"
    }
    
    # format the api url
    $ApiUrl = "https://{0}/api/v1/endpoint/{1}" -f $global:CanvasSite,$ItemId
    # structure the new data
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}

function Get-CanvasDeveloperKeys {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$AccountId="self"

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/accounts/{1}/developer_keys" -f $global:CanvasSite, $AccountId
    $DevKeys = Get-CanvasItemListFlattened -CanvasApiUrl $ApiUrl -TokenFilePath $tknPath -PerPage 100
    return $DevKeys
}

function Get-CanvasLtis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$AccountId="self"

        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/accounts/{1}/external_tools" -f $global:CanvasSite, $AccountId
    $LtiList = Get-CanvasItemListFlattened -CanvasApiUrl $ApiUrl -TokenFilePath $tknPath -PerPage 100
    return $LtiList
}

function Export-CanvasSisUserFile {
    <#
    .SYNOPSIS
    build an SIS Canvas user file based on a object created by qurying AD group membership
    each user is prcessed using LDAP lookups so the properties are: 
    displayname,samaccountname,adspath,givenname,sn,mail,userprincipalname,title,useraccountcontrol
    .PARAMETER UserList
    PSCustom Object resulting from querying get-adgroupmember

    .PARAMETER ExportFilePath
    full file path to output the user csv to

    .PARAMETER StatusMatchActive
    user status to match from individual LDAP lookups (useraccountcontrol)
    common in AD is 512 for enabled
    ref: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#useraccountcontrol-values
    
    .PARAMETER StatusSis
    user status to add to CSV file. acceptable values: active,suspended,deleted
    if active is not selected, not equals will be used to match the StatusMatchActive parameter

    ref: https://canvas.instructure.com/doc/api/file.sis_csv.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        $UserList
        
        ,[Parameter(Mandatory=$true)]
        [string]
        $ExportFilePath

        ,[Parameter(Mandatory=$true)]
        [string]
        $StatusMatchActive

        ,[ValidateSet("active","suspended","deleted", IgnoreCase = $true)]
        [Parameter(Mandatory = $true)]
        [string]$StatusSis

        ,[Parameter(Mandatory)]
        [string]$DirectoryDomain

        ,[Parameter(Mandatory)]
        [string]$UserOu
    )
    Add-LogEntry "$($UserList.Count.ToString()) people found in list"
    $NumEnabled = 0
    foreach ($objGroupUser in $UserList){
        # assemble and validate the data
		$userid = $objGroupUser.samaccountname
        # query for the user info
		$UserLookParams = @{
            CollegeUsername = $userid
            DsDomain = $DirectoryDomain
            DsLdapPath = $UserOu
        }
        $userData = Get-UserInfoFromLDAP @UserLookParams
        # part out the collections
        $sn = $userData['sn'][0]
        $gn = $userData['givenname'][0]
        $mail = $userData['mail'][0]
        $uac = $userData['useraccountcontrol'][0].tostring()
        # filter matches
        if ($StatusSis -ieq "active") {
            if ($uac -eq $StatusMatchActive){
                # create the data for the upload file
                # user_id,login_id,authentication_provider_id,first_name,last_name,email,status
                [string]$DataLine = "{0},{0}" -f $userid
                $DataLine += ",saml,"
                $DataLine += "{0},{1},{2},{3}" -f $gn, $sn, $mail,$StatusSis
                # Add the data to the upload file
                Add-Content -Path $ExportFilePath -Value $DataLine
                $NumEnabled++
            }
        } else {
            if ($uac -ne $StatusMatchActive){
                # create the data for the upload file
                # user_id,login_id,authentication_provider_id,first_name,last_name,email,status
                [string]$DataLine = "{0},{0}" -f $userid
                $DataLine += ",saml,"
                $DataLine += "{0},{1},{2},{3}" -f $gn, $sn, $mail, $StatusSis
                # Add the data to the upload file
                Add-Content -Path $ExportFilePath -Value $DataLine
                $NumEnabled++
            }
        }
    }
    Add-LogEntry "$($NumEnabled.ToString()) $($StatusSis) members configured"
    Add-LogEntry "$($StatusSis) user file generation finished."
}
<#
function Find-CanvasCourse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchTerm
        
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/search/all_courses?search={1}" -f $global:CanvasSite, $SearchTerm
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Get-CanvasItemListFlattened @NewDataParams
    return $NewItemResult
}
#>
<#
function new-genericfunction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ItemId
        
        ,[Parameter(Mandatory=$false)]
        [string]$Optional=""
        # path of the file containing the token text stored as a secure string
        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/endpoint/{1}" -f $global:CanvasSite, $ItemId
    # structure the new data
    $NewData = @{
        toplevel = @{
            item = $ItemId
        }
    }
    # add optional data if specified
    if ($Optional-ne ""){
        $NewData.toplevel.add("option",$Optional)
    }

    # format the data for upload
    $NewDataBody = $NewData|ConvertTo-Json
    
    # configure upload parameters
    $NewDataParams = @{
        CanvasApiUrl = $ApiUrl
        RequestBody = $NewDataBody
        ApiVerb = "POST"
        TokenFilePath = $TokenFilePath
    }
    # send the update
    $NewItemResult = Send-CanvasUpdate @NewDataParams
    return $NewItemResult
}
#>

<#
Available Reports:
title      : User Course Access Log
parameters : @{start_at=; term=; enrollment_type=}
report     : user_course_access_log_csv

title      : Eportfolio Report
parameters : @{no_enrollments=; include_deleted=}
report     : eportfolio_report_csv

title      : Grade Export
parameters : @{enrollment_term_id=; include_deleted=}
report     : grade_export_csv

title      : Multiple Grading Periods Grade Export
parameters : @{enrollment_term_id=}
report     : mgp_grade_export_csv

title      : Last User Access
parameters : @{enrollment_term_id=; course_id=; include_deleted=}
report     : last_user_access_csv

title      : Last Enrollment Activity
parameters : @{enrollment_term_id=; course_id=}
report     : last_enrollment_activity_csv

title      : Outcome Export
parameters :
report     : outcome_export_csv

title      : Outcome Results
parameters : @{enrollment_term_id=; order=; include_deleted=}
report     : outcome_results_csv

title      : Provisioning
parameters : @{enrollment_term_id=; users=; accounts=; terms=; courses=; sections=; enrollments=; groups=;
             group_categories=; group_membership=; xlist=; user_observers=; admins=; created_by_sis=;
             include_deleted=; enrollment_filter=; enrollment_states=}
report     : provisioning_csv

title      : Recently Deleted Courses
parameters : @{enrollment_term_id=}
report     : recently_deleted_courses_csv

title      : SIS Export
parameters : @{enrollment_term_id=; users=; accounts=; terms=; courses=; sections=; enrollments=; groups=;
             group_categories=; group_membership=; xlist=; user_observers=; admins=; created_by_sis=; include_deleted=}
report     : sis_export_csv

title      : Student Competency
parameters : @{enrollment_term_id=; include_deleted=}
report     : student_assignment_outcome_map_csv

title      : Students with no submissions
parameters : @{enrollment_term_id=; course_id=; start_at=; end_at=; include_enrollment_state=; enrollment_state=}
report     : students_with_no_submissions_csv

title      : Unpublished Courses
parameters : @{enrollment_term_id=}
report     : unpublished_courses_csv

title      : Public Courses
parameters : @{enrollment_term_id=}
report     : public_courses_csv

title      : Course Storage
parameters : @{enrollment_term_id=}
report     : course_storage_csv

title      : Unused Courses
parameters : @{enrollment_term_id=}
report     : unused_courses_csv

title      : Zero Activity
parameters : @{enrollment_term_id=; start_at=; course_id=}
report     : zero_activity_csv

title      : User Access Tokens
parameters : @{include_deleted=}
report     : user_access_tokens_csv

title      : LTI Report
parameters : @{include_deleted=}
report     : lti_report_csv

title      : Developer Keys Report
parameters :
report     : developer_key_report_csv
#>
