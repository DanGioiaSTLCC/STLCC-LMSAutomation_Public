# ## ### #### ##### ###### ##### #### ### ## #
# these two settings could easily be replaced with script params
$BbHost = "institution.blackboard.com"
$WorkingDir = $env:SystemDrive + "\batch_tmp"
# ## ### #### ##### ###### ##### #### ### ## #
$BbVersion = Invoke-RestMethod -Method GET -Uri "https://$BbHost/learn/api/public/v1/system/version"
$BbRepoVersion = "{0}.{1}.0" -f $BbVersion.learn.major,$BbVersion.learn.minor
$BbSchemaUrl = "https://bbprepo.blackboard.com/repository/public/bbdn/schema/{0}/schema-{0}.zip" -f $BbRepoVersion
$SchemaDir = "{0}\{1}" -f $WorkingDir,$BbRepoVersion
if (!(test-path $SchemaDir)){
    mkdir $SchemaDir | Out-Null
    Invoke-WebRequest -Uri $BbSchemaUrl -OutFile ("{0}\{1}.zip" -f $SchemaDir,$BbRepoVersion)
    Expand-Archive -Path ("{0}\{1}.zip" -f $SchemaDir,$BbRepoVersion) -DestinationPath $SchemaDir
} else {write-host "latest schema already downloaded to $SchemaDir\"}
