<#
.SYNOPSIS 
Canvas REST API classes and functions as well as integration upload
All functions tested against PowerShell 7 only
Most if not all functions included assume the token is or will be stored in a secure string file
Set VerbosePreference equal to Continue to read any console output

.DESCRIPTION
Canvas tokens can be retrieved by running Get-CanvasTokenString
Canvas token files can be created by running New-CanvasTokenFile
Generic GET requests can be made by using a fully formed API route in Get-CanvasItem

ID Substitutions:
Copied and pasted from https://canvas.instructure.com/doc/api/file.object_ids.html

Throughout the API, objects are referenced by internal IDs. You can also reference objects by SIS ID, by 
prepending the SIS ID with the name of the SIS field, like sis_course_id:. For instance, to retrieve the 
list of assignments for a course with SIS ID of A1234:
    /api/v1/courses/sis_course_id:A1234/assignments

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
# not sure if PowerShell or Windows issue but not setting TLS 1.2 can cause issues randomly so I always set it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$global:CanvasSite = "school.beta.instructure.com"

#. $PSScriptRoot\Invoke-GraphQLQuery.ps1

<# 
We can scrap all the token getting/renewing for Canvas that was used in Bb and use a user token
OAuth tokens are only used for 3-legged OAuth in Canvas
We will need to setup a policy on expiry for automation tokens
------------------------------------------------
#>

<#function Get-UrlUtf8EncodedString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$StringText
    )
    $enc = [System.Text.Encoding]::UTF8
    $UtfText= $enc.GetChars($enc.GetBytes($StringText))
    $UrlText = [System.Web.HttpUtility]::UrlPathEncode($UtfText)
    return $UrlText
}#>

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

function Get-CanvasSisSshaPasswordText {
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

function Get-IsoDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DateInputString
    )
    $DateString = Get-Date $DateInputString -AsUTC -Format u
    return $DateString.ToString()
}

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
    $TokenString = Get-CanvasTokenString $TokenFilePath
    $RestParams = @{
        Method = $ApiVerb
        Uri = $CanvasApiUrl
        Headers = @{
            Authorization = "Bearer $TokenString"
        }
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
    $TokenString = $null
    Remove-Variable -Name "TokenString"
    return $result
}

function Get-CanvasItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $TokenString = Get-CanvasTokenString $TokenFilePath
    $result = Invoke-RestMethod -Method GET -Headers @{"Authorization"="Bearer $TokenString"} -Uri $CanvasApiUrl -ResponseHeadersVariable ResponseHeaders
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"    
    return $result
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
        if (($CanvasApiUrl -contains "per_page") -eq $false){
            # check if there are already query parameters
            if (($CanvasApiUrl -contains "`?") -eq $false){
                $CanvasApiUrl += "?per_page={0}" -f $PerPage.ToString()
            }
            else {
                $CanvasApiUrl += "&per_page={0}" -f $PerPage.ToString()
            }
        }
    }

    $TokenString = Get-CanvasTokenString $TokenFilePath
    # add follow rel link for the command to automatically follw the next result set link
    $result = Invoke-RestMethod -Method GET -Headers @{"Authorization"="Bearer $TokenString"} -Uri $CanvasApiUrl -FollowRelLink -MaximumFollowRelLink $MaxPages
    # clear token data
    $TokenString = $null
    Remove-Variable -Name "TokenString"    
    return $result
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
    $TokenString = Get-CanvasTokenString $TokenFilePath
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
    if ($OverrideStickiness){$UploadRoute += "&override_sis_stickiness=true&add_sis_stickiness"}
    Write-Verbose $UploadRoute
    # send the results to canvas
    $UploadResult = Invoke-restmethod -Method POST -Headers @{"Authorization"="Bearer $TokenString"} -Uri $UploadRoute -InFile $UploadFilePath -ContentType "text/csv"
    
    # clear out the token var
    $TokenString = $null;
    Remove-Variable -Name "TokenString"
    
    # return the upload result to the calling script
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
        [string]$KeeperFile,

        [Parameter(Mandatory=$false)]
        [bool]$Classic=$false
    )
    # setup return var
    [string]$UserPwPlainText = ""
    # read the content of the file
    $UserPwSecured = Get-Content $KeeperFile | ConvertTo-SecureString

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
    # send the data back
    return $UserPwPlainText
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
function Get-CanvasCourse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $CourseUrl = "https://{0}/api/v1/courses/{1}" -f $global:CanvasSite,$CanvasCourse
    $CourseData = Get-CanvasItem -CanvasApiUrl $CourseUrl -TokenFilePath $TokenFilePath
    return $CourseData
}

function Get-CanvasCourseByCRN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
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
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $CourseUrl = "https://{0}/api/v1/courses/{1}/sections" -f $global:CanvasSite,$CanvasCourse
    $CourseData = Get-CanvasItemList -CanvasApiUrl $CourseUrl -PerPage 100 -TokenFilePath $TokenFilePath
    return $CourseData    
}

function New-CanvasCourse {
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
    identifier for Canvas course.  user sis_course_id: prefix to use the SIS id for the course.  otherwise, you will need the integeger from the course url.
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
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,

        [Parameter(Mandatory=$true)]
        [string]$CourseRole,

        [Parameter()]
        [switch]$Notify,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    <#
    types: StudentEnrollment, TeacherEnrollment, TaEnrollment, ObserverEnrollment, DesignerEnrollment
    #>
    
    # control for role specifiers
    if ($CourseRole.ToLower() -eq "student") {$CourseRole = "StudentEnrollment"}
    if ($CourseRole.ToLower() -eq "builder"-or ($CourseRole.ToLower() -eq "designer")) {$CourseRole = "DesignerEnrollment"}
    if (($CourseRole.ToLower() -eq "ta") -or ($CourseRole.ToLower() -eq "assistant")) {$CourseRole = "TaEnrollment"}
    if (($CourseRole.ToLower() -eq "instructor") -or ($CourseRole.ToLower() -eq "teacher")) {$CourseRole = "TeacherEnrollment"}
    # build the route
    $EnrollmentUrl = "https://{0}/api/v1/courses/{1}/enrollments" -f $global:CanvasSite,$CanvasCourse
    # build the enrollment body
    $Enrollment = @{
        "user_id" = $CanvasUser
        "type" = $CourseRole
        "enrollment_state" = "active"
    }
    # add notify if set
    if ($Notify){$Enrollment.Add("notify","true")}
    $EnrollmentBody = @{"enrollment"= $Enrollment}
    $EnrollmentBodyParts = ConvertTo-Json $EnrollmentBody
    $NewEnrollment = Send-CanvasUpdate -CanvasApiUrl $EnrollmentUrl -RequestBody $EnrollmentBodyParts -TokenFilePath $TokenFilePath    
    return $NewEnrollment
}

function Get-CanvasCourseMemberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasCourse,
       
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [int32]$MaxResults = 150
    )
    # build the URL
    $CourseUsersUrl = "https://{0}/api/v1/courses/{1}/enrollments" -f $global:CanvasSite,$CanvasCourse
    # construct the parameters
    $MembershipListParams = @{
        CanvasApiUrl = $CourseUsersUrl
        TokenFilePath = $TokenFilePath
        PerPage = 75
    }
    if ($MaxResults -ne 150){$MembershipListParams.Add("MaxResults",$MaxResults)}
    # call the requestor
    Get-CanvasItemList @MembershipListParams
}
Set-Alias -Name Get-CanvasCourseEnrollments -Value Get-CanvasCourseMemberships

function Get-CanvasUserMemberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CanvasUser,
       
        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath            
    )
    # build the URL
    $CourseUsersUrl = "https://{0}/api/v1/users/{1}/enrollments" -f $global:CanvasSite,$CanvasUser
    # construct the parameters
    $MembershipListParams = @{
        CanvasApiUrl = $CourseUsersUrl
        TokenFilePath = $TokenFilePath
        PerPage = 100
    }
    # call the requestor
    Get-CanvasItemList @MembershipListParams    
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
    # check that the enrollment exists, get id if it does
    $CourseEnrs = Get-CanvasCourseMemberships -CanvasCourse $CanvasCourse -TokenFilePath $TokenFilePath
    
    $UserEnr = $CourseEnrs | Where-Object{$_.sis_user_id -eq $CanvasUser.Replace('sis_user_id:','')}
    write-host $UserEnr.count.ToString()
    
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
            default {Write-Verbose "unrecognized status: '$Status'"}
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
            Write-Verbose "Enrollment update cancelled."
        }
    }
    else {
        Write-Verbose "Could not find the single enrollment to update"
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

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    $MigrationUrl = "https://{0}/api/v1/courses/{1}/content_migrations" -f $global:CanvasSite,$CourseDestination
    $MigrationSettings = @{
        source_course_id = $CourseSource
    }
    $MigrationObject = @{
        migration_type = "course_copy_importer"
        settings = $MigrationSettings
    }
    $MigrationBody = ConvertTo-Json $MigrationObject
    $MigrationTask = Send-CanvasUpdate -RequestBody $MigrationBody -CanvasApiUrl $MigrationUrl -TokenFilePath $TokenFilePath
    return $MigrationTask
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

function New-InstructorSandbox {
    <#
    .Synopsis
    creates a new Instructor Sandbox course, enrolls instructor, copies template, notifies instructor

    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$InstructorUsername,
        
        [Parameter(Mandatory=$false)]
        [string]$AlternateEmail,
        
        [Parameter(Mandatory=$false)]
        [string]$CourseSuffix="",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$CourseSource = ""
    )
        
    # retrieve user info
    Write-Verbose "Getting User Info."
    $UserData = Get-CanvasUserByLogin $InstructorUsername -TokenFilePath $TokenFilePath
    if ($UserData.count -eq 1){    
        # Build course details    
        if ($CourseSuffix -ne ""){$CourseSuffix = " " + $CourseSuffix.Replace(" ","")}
        $CourseName = "Practice Course {0} {1}" -f $UserData.short_name,$CourseSuffix
        $CourseNameShort = "Practice {0}" -f $InstructorUsername
        $IdSuffix = $CourseSuffix.Replace(" ","_")
        $CourseId = "PRA_" + $InstructorUsername + $IdSuffix
        # course check
        Write-Verbose "Checking for existing practice course"
        $CourseCheck = Get-CanvasCourseByCRN -CanvasCrn $CourseId -TokenFilePath $TokenFilePath
        if ($CourseCheck.count -eq 1){
            Write-Verbose "Course with SIS ID $CourseId already exists."
        } else {
            $CourseParams = @{
                CourseNameLong     = $CourseName.Trim()
                CourseNameShort    = $CourseNameShort
                CourseRef          = $CourseId
                TermId             = "schooltrn"
                PublishImmediately = $false
                CourseAccount      = "prac"
                TokenFilePath      = $TokenFilePath
            }
            Write-Verbose "Creating new practice course"
            $NewCourseResult = New-CanvasCourse @CourseParams
            $NewCourseId = $NewCourseResult.id
            
            # exclude template copy by default; will use sub account settings
            # however, copy from a template into the course if one is specified
            if ($CourseSource -ne ""){
                $CourseCopyParams = @{
                    "CourseSource"     = "$CourseSource"
                    "CourseDestination"= $NewCourseId
                    "TokenFilePath"    = $TokenFilePath
                }
                $CopyStatus = New-CanvasCourseCopy @CourseCopyParams
                $StatusUrl = $CopyStatus.progress_url
                Write-Verbose "monitor copy status at $StatusUrl"
            }
            
            # enroll the instructor
            $EnrollParams = @{
                CanvasCourse  = $NewCourseId
                CanvasUser    = "sis_login_id:{0}" -f $InstructorUsername
                CourseRole    = "TeacherEnrollment"
                Notify        = $false
                TokenFilePath = $TokenFilePath
            }
            Write-Verbose "Adding instructor to course"
            $NewEnrId = New-CanvasMembership @EnrollParams
            Write-Verbose "New Enrollment ID: $NewEnrId"
        }
    }
    else {
        Write-Verbose "instructor with login $InstructorUsername not found"
    }    
}

function New-DeveloperCourseShell {
    <#
    .Synopsis
    creates a new Development course, enrolls instructor, copies template, notifies instructor

    .Parameter InstructorUsername
    login id (username) of instructor for whom to create the development course shell

    .Parameter CourseSuffix
    extra information to ID the course shell, examples: BIO207,BIO207-8

    .Parameter TokenFilePath
    path to the secure string file containing the encrypted Canvas user token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$InstructorUsername,
        
        [Parameter(Mandatory=$false)]
        [string]$CourseSuffix="",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$CourseSource = ""
    )
        
    # retrieve user info
    $UserData = Get-CanvasUserByLogin $InstructorUsername -TokenFilePath $TokenFilePath
    if ($UserData.count -eq 1){
        # Build course details    
        if ($CourseSuffix -ne ""){$CourseSuffix = " " + $CourseSuffix.Replace(" ","")}
        $CourseName = "Development Course {0} {1}" -f $UserData.short_name,$CourseSuffix
        $CourseNameShort = "Development {0}{1}" -f $InstructorUsername,$CourseSuffix
        $IdSuffix = $CourseSuffix.Replace(" ","_")
        $CourseId = "DEV-" + $InstructorUsername + $IdSuffix
        $CourseParams = @{
            CourseNameLong      = $CourseName.Trim()
            CourseNameShort     = $CourseNameShort
            CourseRef           = $CourseId
            TermId              = "default"
            CourseAccount       = "schooldev"
            PublishImmediately  = $false
            TokenFilePath       = $TokenFilePath
        }
        $NewCourseResult = New-CanvasCourse @CourseParams
        if ($NewCourseResult) {
            $NewCourseId = $NewCourseResult.id
            Write-Verbose ("New Course: {0}|{1}" -f $NewCourseId,$NewCourseResult.sis_course_id)
            # enroll the instructor
            $EnrollParams = @{
                CanvasCourse  = $NewCourseId
                CanvasUser    = "sis_login_id:{0}" -f $InstructorUsername
                CourseRole    = "TeacherEnrollment"
                Notify        = $True
                TokenFilePath = $TokenFilePath
            }        
            $NewEnrollment = New-CanvasMembership @EnrollParams
            Write-Verbose ("New Enrollment ID: {0}|{1} in {2}" -f $NewEnrollment.id,$NewEnrollment.role,$NewEnrollment.sis_course_id)
        }
        else {
            Write-Verbose "Course Creation of $CourseId failed"
        }
    }
    else {
        Write-Verbose "instructor with login $InstructorUsername not found"
    }
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
        Set-Content -Path $OutFile -Value "Permission,Enabled,ReadOnly,Locked,Explicit,Self,Descendants"
        
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
            
            # write the settings to the csv file
            Add-Content -path "$OutFile" -Value "$PropertyName,$enbl,$ronl,$lock,$expl,$self,$dscn"
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
        [string]$CanvasCourse,

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
    $CoursePagessUrl = "https://{0}/api/v1/courses/{1}/pages{2}{3}" -f $global:CanvasSite,$CanvasCourse,$SearchOptions,$ResultPageSize
    # construct the parameters
    $PageListParams = @{
        "CanvasApiUrl" = $CoursePagessUrl
        "TokenFilePath" = $TokenFilePath
    }
    # call the requestor
    Get-CanvasItemList @PageListParams       
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
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath,

        [Parameter(Mandatory=$false)]
        [string]$SearchTerm=""
    )
    
    # build sort and search
    $SearchOptions = ""
    if ($SearchTerm -ne ""){
        $SearchTerm = Get-UrlEncodedString $SearchTerm
        $SearchOptions += "?search_term=$SearchTerm"
    }
    
    # build the URL
    $CourseModulesUrl = "https://{0}/api/v1/courses/{1}/modules" -f $global:CanvasSite,$CanvasCourse
    # construct the parameters
    $ModuleListParams = @{
        "CanvasApiUrl" = $CourseModulesUrl
        "TokenFilePath" = $TokenFilePath
    }
    # call the requestor
    Get-CanvasItemList @ModuleListParams   
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
        [string]$CanvasCourse,

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
    $CourseFilesUrl = "https://{0}/api/v1/courses/{1}/files" -f $global:CanvasSite,$CanvasCourse
    # construct the parameters
    $FileListParams = @{
        "CanvasApiUrl" = $CourseFilesUrl
        "TokenFilePath" = $TokenFilePath
    }
    # call the requestor
    Get-CanvasItemList @FileListParams      
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
        [string]$CanvasCourse,

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath

    )
    #GET /api/v1/courses/:course_id/tabs
    # build the URL
    $CourseTabsUrl = "https://{0}/api/v1/courses/{1}/tabs" -f $global:CanvasSite,$CanvasCourse
    # construct the parameters
    $ListParams = @{
        CanvasApiUrl = $CourseTabsUrl
        TokenFilePath = $TokenFilePath
        PerPage = 100
    }
    # call the requestor
    $results = Get-CanvasItemList @ListParams
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
    Get-CanvasItemList @AcctListParams
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
    Get-CanvasItemList -CanvasApiUrl $apiUrl -TokenFilePath $TokenFilePath
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
    $TermsUrl = "https://{0}/api/v1/accounts/{1}/terms" -f $global:CanvasSite,$Account
    $TermList = Get-CanvasItemList -CanvasApiUrl $TermsUrl -TokenFilePath $TokenFilePath -PerPage 100
    return $TermList.enrollment_terms
}
Set-Alias -Name Get-CanvasCourseTerms -Value Get-CanvasTerms
Set-Alias -Name Get-CanvasEnrollmentTerms -Value Get-CanvasTerms

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
    # status of report  GET /api/v1/accounts/:account_id/reports/:report/:id
    # parameter enrollment_term_id
    <#
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
    #>
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
        [string]$IncludeUsers="true",

        [Parameter(Mandatory=$false)]
        [string]$IncludeCourses="true",

        [Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    
    <#
    title      : Provisioning
    parameters : @{enrollment_term_id=; users=; accounts=; terms=; courses=; sections=; enrollments=; groups=;
                group_categories=; group_membership=; xlist=; user_observers=; admins=; created_by_sis=;
                include_deleted=; enrollment_filter=; enrollment_states=}
    report     : provisioning_csv    
    
    title      : SIS Export
    parameters : @{enrollment_term_id=; users=; accounts=; terms=; courses=; sections=; enrollments=; groups=;
                group_categories=; group_membership=; xlist=; user_observers=; admins=; created_by_sis=; include_deleted=}
    report     : sis_export_csv    
    
    # POST /api/v1/accounts/:account_id/reports/:report
    
    title      : Last User Access
    parameters : @{enrollment_term_id=; course_id=; include_deleted=}
    report     : last_user_access_csv
    last_run   : @{id=46; progress=100; parameters=; current_line=2677; status=complete; report=last_user_access_csv;
        created_at=4/1/2022 11:38:02 AM; started_at=4/1/2022 11:38:03 AM; ended_at=4/1/2022 11:38:11 AM;
        file_url=; attachment=}

    title      : Zero Activity
    parameters : @{enrollment_term_id=; start_at=; course_id=}
    report     : zero_activity_csv
    last_run   : @{id=45; progress=100; parameters=; current_line=5617; status=complete; report=zero_activity_csv;
        created_at=4/1/2022 9:18:14 AM; started_at=4/1/2022 9:18:25 AM; ended_at=4/1/2022 9:18:26 AM;
        file_url=; attachment=}
    
    title      : Last User Access
    parameters : @{enrollment_term_id=; course_id=; include_deleted=}
    report     : last_user_access_csv
    last_run   : @{id=46; progress=100; parameters=; current_line=2677; status=complete; report=last_user_access_csv;
        created_at=4/1/2022 11:38:02 AM; started_at=4/1/2022 11:38:03 AM; ended_at=4/1/2022 11:38:11 AM;
        file_url=; attachment=}

    title      : User Access Tokens
    parameters : @{include_deleted=}
    report     : user_access_tokens_csv
    last_run   : @{id=23; progress=100; parameters=; current_line=279; status=complete; report=user_access_tokens_csv;
        created_at=1/5/2022 3:50:54 PM; started_at=1/5/2022 3:50:54 PM; ended_at=1/5/2022 3:50:55 PM;
        file_url=; attachment=}

    title      : User Course Access Log
    parameters : @{start_at=; term=; enrollment_type=}
    report     : user_course_access_log_csv
    last_run   : @{id=10; progress=100; parameters=; current_line=1166; status=complete;
        report=user_course_access_log_csv; created_at=11/3/2021 2:20:35 PM; started_at=11/3/2021 2:20:43 PM;
        ended_at=11/3/2021 2:20:46 PM; file_url=;
        attachment=}
    #>
    
    $ReportUrl = "https://{0}/api/v1/accounts/{1}/reports/{2}" -f $global:CanvasSite,$Account,$ReportName
    $Paramaters = @{parameters = @{enrollment_term_id = $TermId;users = "$IncludeUsers";courses = $IncludeCourses   ;sections = "true";enrollments = "true"}} | ConvertTo-Json
    Send-CanvasUpdate -CanvasApiUrl $ReportUrl -RequestBody $Paramaters -ApiVerb "POST" -TokenFilePath $TokenFilePath
}

function Get-CurrentTermCode {
    <#
    .Synopsis
    returns likely current term code
    #>
    $nowstamp = Get-Date
    $m = $nowstamp.Month
    $y = $nowstamp.Year
    switch ($m){
        {@("1","01") -contains $_} {
            $tc = "10"
        }
        {@("2", "02") -contains $_} {
            $tc = "10"
        }
        {@("3", "03") -contains $_} {
            $tc = "10"
        }
        {@("4", "04") -contains $_} {
            $tc = "10"
        }
        {@("5", "05") -contains $_} {
            if ($nowstamp.Day -gt 10){
                $tc = "20"
            }
            else {
                $tc = "10"
            }
        }
        {@("6","06") -contains $_} {
            $tc = "20"
        }
        {@("7","07") -contains $_} {
            $tc = "20"
        }
        {@("8", "08") -contains $_} {
            $tc = "30"
        }
        {@("9", "09") -contains $_} {
            $tc = "30"
        }
        "10"{
            $tc = "30"
        }
        "11"{
            $tc = "30"
        }
        "12"{
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
            Write-Verbose ("Monitor check of job {0} number {1}" -f $SisJobId,$PreviousIterations.ToString())
            $CurrentStatus = Get-CanvasSisStatus -SisUploadRefId $SisJobId -TokenFilePath $TokenFilePath
            switch ($CurrentStatus.workflow_state) {                
                { @("imported","imported_with_messages","aborted","failed","failed_with_messages") -contains $_} {  
                    Write-Verbose ("Current finished status is {0}" -f $CurrentStatus.workflow_state)
                    $FinalMsg = "SIS import task {0} finished with state:{1}" -f $SisJobId,$CurrentStatus.workflow_state
                }                
                { @("created","importing") -contains $_} {  
                    Write-Verbose ("Current status is {0}, progress:{1}" -f $CurrentStatus.workflow_state,$CurrentStatus.progress)
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
        Write-Verbose $_
        Write-Verbose $_.ScriptStackTrace
    }
    return $FinalMsg
}

function Invoke-CanvasReportMonitor {
    <#
    .SYNOPSIS
    Canvas SIS Monitor - Recursive
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
    )
    $FinalMsg = ""
    $FinalStatus = ""
    try {
        $PreviousIterations++
        if ($PreviousIterations -le $MaxIterations){
            Write-Verbose ("Monitor check of report job {0} number {1}" -f $ReportJobId,$PreviousIterations.ToString())
            $CurrentStatus = Get-CanvasReportStatus -ReportName $ReportName -ReportId $ReportJobId -TokenFilePath $TokenFilePath
            switch ($CurrentStatus.status) {                
                { @("complete") -contains $_} {  
                    Write-Verbose ("Report status is {0}" -f $CurrentStatus.status)
                    $FinalStatus = $CurrentStatus.status
                    $FinalMsg = $CurrentStatus
                }
                { @("error") -contains $_} { 
                    $FinalStatus = $CurrentStatus.status
                    $FinalMsg = "Report job {0} failed with message:{1}" -f $ReportJobId,$CurrentStatus.parameters.extra_text
                    Write-Verbose $FinalMsg
                }    
                { @("created") -contains $_} {  
                    Write-Verbose ("Current status is {0}" -f $CurrentStatus.status)
                    Start-Sleep -Seconds $SleepSeconds
                    $ReMonitor = @{
                        ReportJobId = $ReportJobId
                        ReportName = $ReportName
                        TokenFilePath = $TokenFilePath
                        MaxIterations = $MaxIterations
                        PreviousIterations = $PreviousIterations
                        SleepSeconds = $SleepSeconds
                    }
                    Invoke-CanvasReportMonitor @ReMonitor
                }
                Default {
                    Write-Verbose ("Current status is {0}" -f $CurrentStatus.status)
                    Start-Sleep -Seconds $SleepSeconds
                    $ReMonitor = @{
                        ReportJobId = $ReportJobId
                        ReportName = $ReportName
                        TokenFilePath = $TokenFilePath
                        MaxIterations = $MaxIterations
                        PreviousIterations = $PreviousIterations
                        SleepSeconds = $SleepSeconds
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
        Write-Verbose $_
        Write-Verbose $_.ScriptStackTrace
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

function New-InstructorTrainingMembership {
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$CanvasUsername
    
    ,[Parameter(Mandatory=$false)]
    [string]$CanvasCourse="sis_course_id:TRN-OE-FacCert"

    ,[Parameter(Mandatory=$true)]
    [string]$TokenFilePath    
)
    [string]$CanvasUserSpecifier = "sis_login_id:{0}" -f $CanvasUsername
    $EnrParams = @{
        CanvasCourse = $CanvasCourse
        CanvasUser = $CanvasUserSpecifier
        CourseRole = "student"
        Notify = $false
        TokenFilePath = $TokenFilePath
    }
    $EnrollmentResult = New-CanvasMembership @EnrParams
    return $EnrollmentResult
}

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
    $UpdateUrl += "?course_navigation[deafult]={2}&name={3}" -f $Visibility,$ToolName
    $UpdateParams = @{
        CanvasApiUrl = $UpdateUrl
        ApiVerb = "PUT"
        TokenFilePath = $TokenFilePath
    }
    $UpdateResult = Send-CanvasUpdate @UpdateParams
    return $UpdateResult
}

function New-CanvasCourseSection {
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

function Get-CollegeEmailAddressFromAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CollegeUsername
    )
    $EmamilSearchResult = "not found"
    try {
        $ADSearchResult = Get-ADUser -Identity $CollegeUsername -Properties EmailAddress
        if (($null -ne $ADSearchResult) -and ($null -ne $ADSearchResult.EmailAddress) -and ($ADSearchResult.EmailAddress -ne "")){
            $EmamilSearchResult = $ADSearchResult.EmailAddress
        }
    } catch { 
        #log error conditions 
    }
    return $EmamilSearchResult
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

<#
function new-genericfunction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ItemId
        
        ,[Parameter(Mandatory=$false)]
        [string]$Optional=""

        ,[Parameter(Mandatory=$true)]
        [string]$TokenFilePath
    )
    # format the api url
    $ApiUrl = "https://{0}/api/v1/endpoint/{1}" -f $global:CanvasSite,$ItemId
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
