# configure
$ArchiveDir = "C:\TEMP\Archive\"
$CsvFilePath = $ArchiveDir + "CanvasMigrationCourseArchives-Req.csv"
$LogPath = "C:\logs\Canvas-BbCourseMigration"
$TokenPath = "~\pathToToken"
$script:CanvasSite = "school.beta.instructure.com"
# -------------------------------------
# end configure

Add-Type -AssemblyName System.Web
# not sure if PowerShell or Windows issue but not setting TLS 1.2 can cause issues randomly so I always set it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-LogStamp() {
	$strTimestamp = get-date -uFormat %Y-%m-%d_%H.%M.%S
	$strTimestamp = "[" + $strTimestamp + "]"
	return $strTimestamp
}
function Add-LogMessage {
	Param(
		[string]$strLogMsg
	)
	$stamp = Get-LogStamp
	add-content -path $LogPath -value ("{0}{1}" -f $stamp,$strLogMsg)
	write-verbose "$stamp$strLogMsg"
}
function Get-CanvasSecret {
	[CmdletBinding()]
    param (
        [Parameter()]
        [string]$KeeperFile,

        [Parameter(Mandatory=$false)]
        [bool]$Classic=$false
    )
    # setup return var
    [string]$UserPwPlainText = ""
    # read the content of the file (must be read by same user and computer that encrypted it)
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

# Begin ----------------------
$ProcessedCount = 0; $UploadCount = 0
$LogStart = get-date -uFormat %Y-%m-%d_%H%M
$LogPath = $LogPath + "-" + $LogStart + ".log"
Add-LogMessage "Starting Migration Process."
Add-LogMessage "Reading Import List"
$ImportList = import-csv -path $CsvFilePath

# Get Token String
$TokenString = Get-CanvasSecret -KeeperFile $TokenPath

# iterate throught the imports from the csv
foreach ($ImportEntry in $ImportList){
    $ProcessedCount++
    $PackageFilePath = "{0}{1}" -f $ArchiveDir,$ImportEntry.source
    $PackageFileSize = (Get-Item -Path $PackageFilePath).Length
    $DestCourseId = "sis_course_id:{0}" -f $ImportEntry.destination_id
    $MigrationsUrl = "https://{0}/api/v1/courses/{1}/content_migrations" -f $script:CanvasSite,$DestCourseId
    # configure migration settings and file details
    $MigPreAttach = @{
        "name" = $ImportEntry.source
        "size" = $PackageFileSize.ToString()
        "content_type" = "application/zip"
    }
    $Mig = @{
        "migration_type" = "blackboard_exporter"
        "pre_attachment" = $MigPreAttach
    }
    # convert migration info to JSON for REST call
    $MigJson = $Mig | ConvertTo-Json
    Add-LogMessage ("Creating Migration for {0}" -f $ImportEntry.destination_id)
    # make the REST call to create the migration
    $MigPreResult = Invoke-RestMethod -Method POST -Headers @{"Authorization"="Bearer $TokenString"} -Uri $MigrationsUrl -Body $MigJson -ContentType "application/json"
    # log message
    $MigrationInfoMsg = "Migration {0} for {2} created. Track progress at {1}" -f $MigPreResult.id,$MigPreResult.progress_url,$ImportEntry.destination_id
    Add-LogMessage $MigrationInfoMsg
    # now upload the file with to the tokenized url for this migration
    Add-LogMessage "Uploading file"
    # specify the file in multipart form data
    $FormData = @{file = Get-Item -Path $PackageFilePath}
    # send the form
    $UploadResult = Invoke-WebRequest -Method POST -Uri $MigPreResult.pre_attachment.upload_url -Form $FormData
    # hand results of POST
    if ($UploadResult.StatusCode -eq "201"){
        Add-LogMessage "File uploaded successfully"
        $UploadCount++
        $UploadInfo = $UploadResult.Content|ConvertFrom-Json
        # id, uuid, filename
        $MsgUploadResult = "{0} uploaded with ID {1}" -f $UploadInfo.filename,$UploadInfo.id
        Add-LogMessage $MsgUploadResult
    }
    else {
        $UploadResult
    }
}
$msgFinal = "Migration creation complete. {0} migrations created, {1} files uploaded." -f $ProcessedCount.ToString(),$UploadCount.ToString()
Add-LogMessage $msgFinal