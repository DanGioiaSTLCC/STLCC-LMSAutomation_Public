<#
.Synopsis 
Bb Learn REST API classes and functions as well as integration upload
Token class:
$tkn = [BbLearnToken]::new("learnSite")
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$PrimaryLearnSite = "school.blackboard.com"

class BbLearnToken {
    [string]$BbLearnSite
    [bool]$TokenStatus
    [string]$TokenString
    [string]$TokenExpires
    
    [bool]Authorize([string]$BbRESTKey, [string]$BbRESTSecret){
        [bool]$success = $false;
        # string format the key and secret pair
        $creds="{0}:{1}" -f $BbRESTKey,$BbRESTSecret
        # base 64 encode the key and secret text
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($creds))
        # format the authentication text for the http auth header
        $basicAuthValue = "Basic $encodedCreds"
        # add the authentication to the header
        $ReqHeaders = @{Authorization = $basicAuthValue}
        # body of the post request
        $ReqBody = "grant_type=client_credentials"
        # destination URI
        $ReqUrl="https://" + $this.BbLearnSite + "/learn/api/public/v1/oauth2/token"
        # REST arguments
        $TokenArgs = @{}
        $TokenArgs.Add("Headers",$ReqHeaders)
        $TokenArgs.Add("URI",$ReqUrl)
        $TokenArgs.Add("Method", "POST")
        $TokenArgs.Add("Body",$ReqBody)
        $TokenArgs.Add("ContentType","application/x-www-form-urlencoded")
        try {
            $TokenResponse = Invoke-RestMethod @TokenArgs
            if ($TokenResponse.access_token){
                $this.TokenStatus = $true
                $this.TokenString = $TokenResponse.access_token
                $this.TokenExpires = (Get-Date).AddSeconds($TokenResponse.expires_in)
                $success = $true
            }
            else {
                Write-Verbose $TokenResponse.tostring()
                $this.TokenStatus = $false
                $success = $false
            }
        }
        catch {
            Write-Error $Error[0].Exception.Message
        }
        if (!$success){
            Write-Verbose "no token"
        }
        else {
            Write-Verbose "Token retrieved."
        }
        return $success
    }
    # validate if token is configured and current, try to refresh if not
    [bool]validate([string]$BbRESTKey, [string]$BbRESTSecret){
        [bool]$validationResult = $false
        if ($this.TokenStatus -and ($this.TokenExpires -gt (get-date))){
            $validationResult = $true
        }
        else {
            $validationResult = $this.Authorize([string]$BbRESTKey, [string]$BbRESTSecret)
        }
        return $validationResult
    }
    # init config
    BbLearnToken(
        [string]$site
    ){
        $this.BbLearnSite = $site
        $this.TokenStatus = $false
        $this.TokenString = ""
        $this.TokenExpires = (Get-Date).AddDays(-1)
    }
}

class BbLearnDuration {
    [string]$type
    [string]$start
    [string]$end
    [int]$daysOfUse    
}

class BbLearnAvailability {
    [string]$available
    [BbLearnDuration]$duration = [BbLearnDuration]::new()
}

class BbLearnCourse {
    [string]$id
    [string]$uuid
    [string]$externalId
    [string]$dataSourceId
    [string]$courseId
    [string]$name
    [string]$description
    [string]$created
    [bool]$organization
    [string]$ultraStatus
    [bool]$allowGuests
    [bool]$readOnly
    [string]$termId
    [string]$hasChildren
    [string]$parentId
    [string]$externalAccessUrl
    [string]$guestAccessUrl
    [BbLearnAvailability]$availability = [BbLearnAvailability]::new()
}
<#
####### ############ ################ ########
#>
[BbLearnToken]$global:sharedToken = [BbLearnToken]::new($PrimaryLearnSite)
<#
####### ############ ################ ########
#>

$global:PracticeToken = @{}
$global:PracticeToken.TokenStatus = $false
$global:PracticeToken.TokenString = ""
$global:PracticeToken.TokenExpires = "8/4/1984"
$global:tplCommon = "CommonTemplateCourseId"

function Send-BbFrameworkFile{
    Param(
        [string]$UploadUsername
        ,[string]$UploadPassword
        ,[string]$Uri
        ,[string]$Filepath
    )
    try
    {
        $creds="$($UploadUsername):$($UploadPassword)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($creds))
        $basicAuthValue = "Basic $encodedCreds"
        $Headers = @{Authorization = $basicAuthValue}
        $uploadResponse = Invoke-RestMethod -Uri $Uri -Method POST -ContentType "text/plain" -Headers $Headers -InFile $Filepath
    }
    catch
    {
        $exception = $_.Exception.ToString()
        throw "There was an error uploading the Feed File: $($exception)"
    }
    
    try
    {
        # The Data Set UID is the 9th "word" in the response for an upload
        $words = $uploadResponse.split()
        $statusID = $words[9]
        Add-LogEntry "Upload reference ID: $statusID "
    }
    catch
    {
        $exception = $_.Exception.ToString()
        throw "There was an error getting the Data Set ID from the feed file response: $($exception)"
        Add-LogEntry "There was an error getting the Data Set ID from the feed file response: $($exception)"
    }    
}

function Get-BbFrameworkStatus {
    Param(
        [string]$StatusCode    
        ,[string]$FrameworkUsername="SIS_Un"
        ,[string]$FrameworkPassword="SIS_Pw"
        ,[string]$BbHost="$PrimaryLearnSite"
        ,[string]$BbInstanceId="InstanceId"
        
    )
    [string]$CheckerUrl = Get-BbFrameworkUrl -UrlType "status" -BbLearnSite $BbHost -BbSchema $BbInstanceId
    $CheckerUrl += "$StatusCode"
    $creds="$($FrameworkUsername):$($FrameworkPassword)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($creds))
    $basicAuthValue = "Basic $encodedCreds"
    $Headers = @{Authorization = $basicAuthValue}
    try {
        $response = Invoke-RestMethod -Method GET -Headers $Headers -Uri $CheckerUrl
        return $response.dataSetStatus
    }
    catch
    {
        $exception = $_.Exception.ToString()
        throw "There was an error retrieving the Feed File status: $($exception)"
        Add-LogEntry "There was an error retrieving the Feed File status: $($exception)"
    }    
}

function Get-BbLearnApiToken {
    Param(
        [string]
        $BbRESTKey

        ,[string]
        $BbRESTSecret

        ,[string]
        $BbRESTHost
    )

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
                $global:PracticeToken.TokenStatus = $true
                $global:PracticeToken.TokenString = $BbCurentToken.access_token
                $global:PracticeToken.TokenExpires = (Get-Date).AddSeconds($BbCurentToken.expires_in)
            }
            else {
                $global:PracticeToken.TokenStatus = $false
            }
        }
    }
    catch {
        Write-Host $Error[0].Exception.Message
    }
    return $global:PracticeToken
}
function Test-BbLearnApiToken {
    Param(
        [string]$BbRESTKey    
        ,[string]$BbRESTSecret
        ,[string]$BbRESTHost
    )
    $dtNow = Get-Date 
    if ($dtNow -lt (get-date $global:PracticeToken.TokenExpires)) {
        return  $global:PracticeToken.TokenString
    }
    else {
        $NewToken = Get-BbLearnApiToken -BbRESTKey $BbRESTKey -BbRESTSecret $BbRESTSecret -BbRESTHost $BbRESTHost
        return $NewToken.TokenString
    }
}

function Send-BbLearnApiCall-Generic {
    Param(
        [string]$RestVerb
        ,[string]$RestUrl
        ,[string]$RestTokenString
        ,[string]$jsonBody=""
    )
    if (($RestVerb -eq "PATCH") -or ($RestVerb -eq "POST")){
        $result = Invoke-RestMethod -Headers @{Authorization="Bearer $RestTokenString"} -uri $RestUrl -Method $RestVerb -Body $jsonBody -ContentType "application/json"    
    }
    else {
        $result = Invoke-RestMethod -Headers @{Authorization="Bearer $RestTokenString"} -uri $RestUrl -Method $RestVerb -ContentType "application/json"
    }
    return $result    
}

function Get-BbFrameworkUrl {
	Param (
        [string]$UrlType
        ,[string]$BbLearnSite="$PrimaryLearnSite"
        ,[string]$BbSchema="InstanceId"
	)
	$strUploadUrl=""
	$UrlType = $UrlType.ToLower();

	switch ($UrlType) {
		"coursestore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/course/store"
			break;
		}
		"coursetemplate" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/course/store"
			break;
		}
		"userstore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/person/store"
			break;
		}
		"userrefresh" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/person/refreshlegacy"
			break;
		}
		"enrollmentstore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/membership/store"
			break;
		}
		"enrollmentrefresh" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/membership/refreshlegacy"
			break;
		}
		"orgenrollstore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/organizationmembership/store"
			break;
		}
		"orgenrollrefresh" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/organizationmembership/refreshlegacy"
			break;
		} 
		"categorystore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/coursecategory/store "
			break;
		}
		"categorylink" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/coursecategorymembership/store"
			break;
		}
		"term" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/term/store"
			break;
		}
		"rolestore" {
			$strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/secondaryinstrole/store"
			break;
        }
        "nodestore" {
            $strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/node/store"
            break;
        }
        "coursenodestore" {
            $strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/courseassociation/store"
            break;
        }
        "coursenodesecondarystore" {
            $strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/standardsassociation/store"
            break;
        }
        "status" {
            $strUploadUrl = "https://$BbLearnSite/webapps/bb-data-integration-flatfile-$BbSchema/endpoint/dataSetStatus/"
        }
		default {
			break;
		}
	}
	return $strUploadUrl
}

function Get-BbCrnOld {
    Param(
        [string]$shortCrn
        ,[string]$termCode
    )
    return $termCode + $shortCrn
}

function Get-BbCrnNew {
    Param(
        [string]$shortCrn
        ,[string]$termCode        
    )
    return $shortCrn + "." + $termCode
}

function New-BbLearnCourseListFileHeader {
    Param(
        [string]$OutFile
    )
    Set-Content -Path $OutFile -Value "courseid,name,isorg,available,isparent,ischild,start,stop,created"
}

function Get-BbLearnCourseListToFile {
    Param(
        [string]$CourseListUrl
        ,[string]$OutFile
        ,[string]$BbHost="$PrimaryLearnSite"
    )
    Add-LogEntry "Getting Courses ..."
    $RestContType = "application/x-www-form-urlencoded"
    Write-Verbose "URL - $CourseListUrl"
    $CourseList = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $global:sharedToken.TokenString)} -Uri $CourseListUrl -Method GET -ContentType $RestContType
    
    if ($CourseList.results){
        foreach($CourseInfo in $CourseList.results){
            $ParentStatus = "No"
            $ChildStatus = "No"
            if ($CourseInfo.hasChildren -eq "true"){$ParentStatus = "Yes"}
            if ($CourseInfo.parentId){
                $ChildStatus = $CourseInfo.parentId
            }
            $CourseLine = $CourseInfo.courseId
            $CourseLine += ",""" + $CourseInfo.name
            $CourseLine += """," + $CourseInfo.organization
            $CourseLine += "," + $CourseInfo.availability.available
            $CourseLine += "," + $ParentStatus
            $CourseLine += "," + $ChildStatus
            $CourseLine += "," + $CourseInfo.availability.duration.start
            $CourseLine += "," + $CourseInfo.availability.duration.end
            $CourseLine += "," + $CourseInfo.created
            Add-Content -path "$OutFile" -value "$CourseLine"
        }
    }
    if ($CourseList.paging.nextPage -and ($CourseList.results.count -ne 1)){
        # Add-LogEntry $CourseList.paging.nextPage
        [string]$NextUrl = "https://" + $BbHost + $CourseList.paging.nextPage
        $CourseListParams = @{}
        $CourseListParams.Add("CourseListUrl", $NextUrl)
        $CourseListParams.Add("OutFile", $OutFile)
        $CourseListParams.Add("BbHost", $BbHost)
        Get-BbLearnCourseListToFile @CourseListParams
    }
}

function Get-BbLearnUserListToFile {
    Param(
        [string]$UserListUrl
        ,[string]$OutFile
        ,[string]$BbHost
        ,[string]$BbKey
        ,[string]$BbSec
    )
    Test-BbLearnApiToken -BbRESTKey $BbKey -BbRESTSecret $BbSec -BbRESTHost $BbHost
    Add-LogEntry "Getting Courses ..."
    $RestContType = "application/x-www-form-urlencoded"
    Write-Verbose "URL - $UserListUrl"
    $UserList = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $global:sharedToken.TokenString)} -Uri $UserListUrl -Method GET -ContentType $RestContType
    
    if ($UserList.results){
        foreach($UserInfo in $UserList.results){
            $LastLogin = "1940-01-01T00:00:00.000Z"
            if ($UserInfo.lastLogin){
                $LastLogin = $UserInfo.lastLogin
            }
            $UserLine = $UserInfo.id
            $UserLine += "," + $UserInfo.externalId
            $UserLine += "," + $UserInfo.username
            $UserLine += "," + $UserInfo.availability.available
            $UserLine += "," + $UserInfo.created
            $UserLine += "," + $UserInfo.modified
            $UserLine += "," + $LastLogin
            Add-Content -path "$OutFile" -value "$UserLine"
        }
    }
    if ($UserList.paging.nextPage -and ($UserList.results.count -ne 1)){
        #Add-LogEntry $UserList.paging.nextPage
        [string]$NextUrl = "https://" + "$BbHost" + $UserList.paging.nextPage
        $ListParams = @{}
        $ListParams.Add("UserListUrl", $NextUrl)
        $ListParams.Add("OutFile", $OutFile)
        $ListParams.Add("BbHost", $BbHost)
        $ListParams.Add("BbKey",$BbKey)
        $ListParams.Add("BbSec",$BbSec)
        Get-BbLearnUserListToFile @ListParams
    }
}

function Get-BbLearnCourseTOC {
    Param(
        [string]$BbRESTHost
        ,[string]$BbCourseId
        ,[string]$BbTokenString        
    )
    # Add-LogEntry "Getting Course TOC"
    $ContentRoute = "/learn/api/public/v1/courses/$BbCourseId/contents"
    $CourseTocUrl = "https://" + $BbRESTHost + "$ContentRoute"
    $CourseTocList = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -Uri $CourseTocUrl -Method GET
    return $CourseTocList
}

function Invoke-CourseCopy {
    Param(
        [string]$BbRESTKey    
        ,[string]$BbRESTSecret    
        ,[string]$BbRESTHost    
        ,[string]$BbSourceCourse
        ,[string]$BbTargetCourse
    )
    
    $BbTokenString = Test-BbLearnApiToken -BbRESTKey $BbRESTKey -BbRESTSecret $BbRESTSecret -BbRESTHost $BbRESTHost
    [string]$BbCopyRoute = "/learn/api/public/v2/courses/courseId:$BbSourceCourse/copy"
    [string]$BbCopyUrl = "https://" + $BbRESTHost + $BbCopyRoute
    $TargetCourse = @{
        id = "courseId:$BbTargetCourse"
    }
    $CopySettings = @{
        availability = $false
        bannerImage = $true
        duration = $false
        enrollmentOptions = $false
        guestAccess = $false
        languagePack = $false
        navigationSettings = $true
        observerAccess = $false
    }
    $CopyOptions = @{
        adaptiveReleaseRules = $true
        announcements = $true
        assessments = $true
        blogs = $true
        calendar = $true
        contacts = $true
        contentAlignments = $true
        contentAreas = $true
        discussions = "ForumsAndStarterPosts"
        glossary = $true
        gradebook = $true
        groupSettings = $true
        journals = $true
        retentionRules = $true
        rubrics = $true
        settings = $CopySettings
        tasks = $true
        wikis = $true
    }
    $CopyObject = @{
        targetCourse = $TargetCourse
        copy = $CopyOptions
    }
    # convert the PSObject to JSON text to submit
    $jsonBody = $CopyObject|ConvertTo-Json
    $jsonBody = $jsonBody.ToString()
    # send the body to Bb
    $PostResult = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -uri $BbCopyUrl -Method POST -Body $jsonBody -ContentType "application/json"
    return $PostResult
}

function Get-BbLearnCourseDetails {
    Param(
        [string]$BbCourseId
        ,[string]$BbRESTHost
        ,[string]$BbTokenString
    )
    $CourseRoute = "/learn/api/public/v3/courses/$BbCourseId"
    $FullCourseRoute = "https://" + $BbRESTHost + $CourseRoute
    $result = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -Uri $FullCourseRoute -Method GET -ContentType $RestContType
    return $result
}
function Remove-BbLearnCourseContent {
    Param(
        [string]$BbCourseId
        ,[string]$BbContentId
        ,[string]$BbRESTHost
        ,[string]$BbTokenString
    )
    $ContentDeleteRoute = "/learn/api/public/v1/courses/$BbCourseId/contents/$BbContentId"
    $ContentDelteUrl = "https://" + $BbRESTHost +$ContentDeleteRoute
    $result = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -Uri $ContentDelteUrl -Method DELETE
    return $result
}

function Get-CourseGradebookCategories {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$BbCourseId,
        [Parameter(Mandatory=$true)]
        [string]$BbRESTHost,
        [Parameter(Mandatory=$true)]
        [string]$BbTokenString
    )
    $GradeCategoriesRoute = "/learn/api/public/v1/courses/courseId:" + $BbCourseId + "/gradebook/categories"
    $GradeCategoriesUrl = "https://" + $BbRESTHost + $GradeCategoriesRoute + "?limit=200"
    $result = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -Uri $GradeCategoriesUrl.ToString() -Method GET
    return $result
}

function Get-CourseGradebookColumns {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$BbCourseId,
        [Parameter(Mandatory=$true)]
        [string]$BbRESTHost,
        [Parameter(Mandatory=$true)]
        [string]$BbTokenString
    )
    $GradeColumnsRoute = "/learn/api/public/v1/courses/courseId:" + $BbCourseId + "/gradebook/columns"
    $GradeColumnsUrl = "https://" + $BbRESTHost + $GradeColumnsRoute + "?limit=200"
    $result = Invoke-RestMethod -Headers @{Authorization = ("Bearer " + $BbTokenString)} -Uri $GradeColumnsUrl.ToString() -Method GET
    return $result
}