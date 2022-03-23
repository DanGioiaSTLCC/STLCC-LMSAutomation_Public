$ArchiveToFix = "C:\TEMP\FileToFix.zip"
$WorkingDirectory = "C:\TEMP\ArhiveFixer" # be careful, the contents of this folder get purged
$DestinationDirectory = "C:\TEMP\ArchiveGood"
$NewFileName = "Bb-FixedArchive.zip"

if ((test-path $WorkingDirectory) -eq $false){mkdir $WorkingDirectory|Out-Null}
if ((test-path $DestinationDirectory) -eq $false){mkdir $DestinationDirectory|Out-Null}

# prep working directory by deleting everything
Get-ChildItem -path "$WorkingDirectory\*" | ForEach-Object{Remove-Item $_.fullname -Recurse}

# unzip
Expand-Archive -path $ArchiveToFix -DestinationPath $WorkingDirectory

# get resources list from archive manifest
$ManifestResources = Select-Xml -Path "$WorkingDirectory\imsmanifest.xml" -XPath "/manifest/resources"
$UserInfo = $ManifestResources.node.resource | Where-Object{$_."title" -eq "Users"}
$Memberships = $ManifestResources.node.resource | Where-Object{$_."title" -eq "Course Memberships"}

$MembershipFile = "{0}\{1}" -f $WorkingDirectory,$Memberships.file
(Get-Content $MembershipFile).replace('ROW_STATUS value="2"','ROW_STATUS value="0"')|out-file $MembershipFile -Encoding utf8


# replace user status
$UserInfoFile = "{0}\{1}" -f $WorkingDirectory,$UserInfo.file
(Get-Content $UserInfoFile).replace('ROW_STATUS value="2"','ROW_STATUS value="0"')|out-file $UserInfoFile -Encoding utf8

# create the new zip file
Compress-Archive -Path "$WorkingDirectory\*" -DestinationPath "$DestinationDirectory\$NewFileName"
