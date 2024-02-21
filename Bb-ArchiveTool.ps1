<#
.SYNOPSIS
PowerShell with Windows Presentation Framework UI to look at parts of a Blackboard course archive file.  
You will need to expand the zip file and add that folder to the empty text input box and hit load manifest to start
#>
Add-Type -AssemblyName PresentationFramework
[string]$script:WorkingDirectory = ""
[string]$script:ManifestPath = ""
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"
    Title="Bb Archive Tools" Height="600" Width="1300" FontSize="14">
    <Grid x:Name="LayoutGrid">
    <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto" MaxHeight="1000"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto" MinWidth="331"/>
            <ColumnDefinition Width="Auto" MinWidth="26"/>
        </Grid.ColumnDefinitions>
        <Label x:Name="lblTxtArchPath" Content="Path to Extracted Bb Course Archvie" Grid.Column="0" Grid.Row="0" FontSize="14"/>
        <TextBox x:Name="txtArchPath" Grid.Column="0" Grid.Row="1" Margin="10,10,0,0" VerticalAlignment="Top" Height="53.62" />
        <Button x:Name="btnManifest" Content="Read Manifest" Grid.Column="0" Grid.Row="1" FontSize="14" Margin="10,42,10,43" HorizontalAlignment="Right" VerticalAlignment="Center"/>
        <Button x:Name="btnUserInfo" Content="User Info" Grid.Column="1" HorizontalAlignment="Left" Margin="68,10,-172,0" VerticalAlignment="Top" Width="140"/>
        <Button x:Name="btnGradeColumns" Content="Grade Columns" Grid.Column="1" HorizontalAlignment="Left" Margin="68,14,-173,0" Grid.Row="1" VerticalAlignment="Top" Width="140"/>
        <Button x:Name="btnGradesForUser" Content="Grades for User" Grid.Column="1" HorizontalAlignment="Left" Margin="68,56,-174,-15" Grid.Row="1" VerticalAlignment="Top" Width="140"/>
        <TextBox x:Name="txtUsername" Grid.Column="1" HorizontalAlignment="Left" Height="23" Margin="68,94,-169,-50" Grid.Row="1" TextWrapping="Wrap" Text="username" VerticalAlignment="Top" Width="140"/>
        <Label Content="Data" HorizontalAlignment="Left" Margin="10,154,0,-63" Grid.Row="1" VerticalAlignment="Top" Height="36"/>
        <TextBlock x:Name="statusMsg" Grid.Column="1" HorizontalAlignment="Left" Margin="258,20,-292,0" TextWrapping="Wrap" Text="Status Messages" VerticalAlignment="Top" Height="112" Grid.RowSpan="2" Width="235"/>
        <Button x:Name="btnClear" Content="Clear" Grid.Column="1" HorizontalAlignment="Left" Margin="71,131,0,-28" Grid.Row="1" VerticalAlignment="Top" Width="75"/>
        <Button x:Name="btnVideos" Content="Videos" HorizontalAlignment="Left" Margin="20,114,0,0" Grid.Row="1" VerticalAlignment="Top" Width="75"/>

        <TabControl Grid.Row="2" Grid.ColumnSpan="2" Margin="10,190,0,0" MaxHeight="800">
            <TabItem Header="Course Info" Name="tabCourseInfo">
                <TextBox Name="CourseInfo"
            TextWrapping="Wrap"
            AcceptsReturn="True"
            ></TextBox>
            </TabItem>
            <TabItem Header="Users" Name="tabUsers">
            <ScrollViewer MaxHeight="775" MaxWidth="1900" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Visible">
                <DataGrid Name="DatagridPeople" AutoGenerateColumns="True">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Username" Binding="{Binding USERNAME}"/>
                        <DataGridTextColumn Header="Database ID" Binding="{Binding ID}"/>
                        <DataGridTextColumn Header="Person Key" Binding="{Binding BATCHUID}"/>
                        <DataGridTextColumn Header="Role" Binding="{Binding COURSEROLE}"/>
                        <DataGridTextColumn Header="First Name" Binding="{Binding GIVEN}"/>
                        <DataGridTextColumn Header="Last Name" Binding="{Binding FAMILY}"/>
                        <DataGridTextColumn Header="Email Address" Binding="{Binding EMAIL}"/>
                        <DataGridTextColumn Header="Last Access" Binding="{Binding LASTACCESS}"/>
                    </DataGrid.Columns>
                </DataGrid>
            </ScrollViewer>
            </TabItem>
            <TabItem Header="Grades" Name="tabGradeHistory">
            <ScrollViewer MaxHeight="775" MaxWidth="1900" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Visible">
                <DataGrid Name="DatagridGrades">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Grade" Binding="{Binding GRADE}"/>
                        <DataGridTextColumn Header="Num Grade" Binding="{Binding NUMERIC_GRADE}"/>
                        <DataGridTextColumn Header="Instructor Comments" Binding="{Binding INSTRUCTOR_COMMENTS}"/>
                        <DataGridTextColumn Header="Feedback" Binding="{Binding FEEDBACK_TO_USER}"/>
                        <DataGridTextColumn Header="Attempt Date" Binding="{Binding DATEATTEMPTED}"/>
                        <DataGridTextColumn Header="Graded Date" Binding="{Binding DATE_LOGGED}"/>
                        <DataGridTextColumn Header="Grader" Binding="{Binding MODIFIER_USERNAME}"/>
                        <DataGridTextColumn Header="Grade Entry ID" Binding="{Binding id}"/>
                        <DataGridTextColumn Header="Outcome ID" Binding="{Binding GRADABLE_ITEM_ID}"/>
                        <DataGridTextColumn Header="Grading Period" Binding="{Binding GRADING_PERIODID}"/>
                        <DataGridTextColumn Header="Title" Binding="{Binding TITLE}"/>
                        <DataGridTextColumn Header="Display Title" Binding="{Binding DISPLAY_TITLE}"/>
                        <DataGridTextColumn Header="External Ref" Binding="{Binding EXTERNALREF}"/>
                        <DataGridTextColumn Header="Handle" Binding="{Binding HANDLERURL}"/>
                        <DataGridTextColumn Header="Weight" Binding="{Binding WEIGHT}"/>
                        <DataGridTextColumn Header="Points Possible" Binding="{Binding POINTSPOSSIBLE}"/>
                        <DataGridTextColumn Header="Multiple Attempts" Binding="{Binding MULTIPLEATTEMPTS}"/>
                    </DataGrid.Columns>
                </DataGrid>
            </ScrollViewer>
            </TabItem>
            <TabItem Header="Grade Columns" Name="tabGradeColumns">
            <ScrollViewer MaxHeight="775" MaxWidth="1900" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Visible">
                <DataGrid Name="DatagridGradeColumns">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Outcome ID" Binding="{Binding GRADABLE_ITEM_ID}"/>
                        <DataGridTextColumn Header="Grading Period" Binding="{Binding GRADING_PERIODID}"/>
                        <DataGridTextColumn Header="Title" Binding="{Binding TITLE}"/>
                        <DataGridTextColumn Header="Display Title" Binding="{Binding DISPLAY_TITLE}"/>
                        <DataGridTextColumn Header="Description" Binding="{Binding DESCRIPTION}"/>
                        <DataGridTextColumn Header="External Ref" Binding="{Binding EXTERNALREF}"/>
                        <DataGridTextColumn Header="Handle" Binding="{Binding HANDLERURL}"/>
                        <DataGridTextColumn Header="Weight" Binding="{Binding WEIGHT}"/>
                        <DataGridTextColumn Header="Points Possible" Binding="{Binding POINTSPOSSIBLE}"/>
                        <DataGridTextColumn Header="Multiple Attempts" Binding="{Binding MULTIPLEATTEMPTS}"/>
                        <DataGridTextColumn Header="Formulation" Binding="{Binding FORMULATION}"/>
                    </DataGrid.Columns>
                </DataGrid>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Videos" Name="tabVideos">
            <ScrollViewer MaxHeight="775" MaxWidth="1900" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Visible">    
            <DataGrid Name="DatagridVideos" >
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Res File ID" Binding="{Binding RESOURCE_FILE}"/>
                        <DataGridTextColumn Header="Cont Title" Binding="{Binding RESOURCE_TITLE}"/>
                        <DataGridTextColumn Header="File Path" Binding="{Binding FILE_PATH }"/>
                        <DataGridTextColumn Header="Link File Name" Binding="{Binding FILE_NAME}"/>
                        <DataGridTextColumn Header="File Size (MB)" Binding="{Binding FILE_SIZE}"/>
                    </DataGrid.Columns>
                </DataGrid>
            </ScrollViewer>
            </TabItem>
        </TabControl>
    </Grid>
</Window>
"@
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$inputDir = $window.FindName("txtArchPath")
$inputUser = $window.FindName("txtUsername")
$manifestButton = $window.FindName("btnManifest")
$userButton = $window.FindName("btnUserInfo")
$gradesButton = $window.FindName("btnGradesForUser")
$gradeColumnsButton = $window.FindName("btnGradeColumns")
$clearButton = $window.FindName("btnClear")
$statusBlock = $window.FindName("statusMsg")
$DataOutputGrades = $window.FindName("DatagridGrades")
$DataOutputPeople = $window.FindName("DatagridPeople")
$DataOutputColumns = $window.FindName("DatagridGradeColumns")
$DataOutputCourseInfo = $window.FindName("CourseInfo")
$TabGradeColumns = $window.FindName("tabGradeColumns")
$TabGradeHistory = $window.FindName("tabGradeHistory")
$tabUsers = $window.FindName("tabUsers")
$tabCourseInfo = $window.FindName("tabCourseInfo")
$tabVideos = $window.FindName("tabVideos")
$videosButton = $window.FindName("btnVideos")
$DataOutputVides = $window.FindName("DatagridVideos")

$manifestButton.Add_Click({
    $script:WorkingDirectory = $inputDir.Text
    if (Test-Path $script:WorkingDirectory){
        $statusBlock.Text = "$WorkingDirectory exists."
        $manPath = "$($script:WorkingDirectory)\imsmanifest.xml"
        if (Test-Path $manPath){
            $Msg = "manifest found"
            $script:ManifestPath = $manPath
            $ManifestResources = Select-Xml -Path "$script:ManifestPath" -XPath "/manifest/resources"
            $CrsSettings = $ManifestResources.node.resource|Where-Object{$_."type" -eq 'course/x-bb-coursesetting'}
            $gradebook = $ManifestResources.node.resource|Where-Object{$_."type" -eq 'course/x-bb-gradebook'}
            $UserInfo = $ManifestResources.node.resource | Where-Object{$_."type" -eq 'course/x-bb-user'}
            $Memberships = $ManifestResources.node.resource | Where-Object{$_."type" -eq 'membership/x-bb-coursemembership'}
            $TOC = $ManifestResources.node.resource | Where-Object{$_."type" -eq 'course/x-bb-coursetoc'}
            $CourseInfo = select-xml -Path "$($script:WorkingDirectory)\$($CrsSettings.file)" -XPath "/COURSE"
            $Msg += "`n Users:$($UserInfo.file)"
            $Msg += "`n Enroll:$($Memberships.file)"
            $Msg += "`n Grades:$($gradebook.file)"
            $Msg += "`n-------------------"
            $Msg += "`n Course ID:$($CourseInfo.node.COURSEID.value)"
            $Msg += "`n Course Name:$($CourseInfo.node.TITLE.value)"
            $Msg += "`n Created: $($CourseInfo.node.DATES.CREATED.value)"
            $Msg += "`n Modified: $($CourseInfo.node.DATES.UPDATED.value)"
            $Msg += "`n Open: $($CourseInfo.node.DATES.COURSESTART.value)"
            $Msg += "`n Close: $($CourseInfo.node.DATES.COURSEEND.value)"
            $Msg += "`n ---- Course Menu ----"
            foreach ($contItem in $TOC){
                $Msg += "`n $($contItem.title) ($($contItem.identifier))"
            }
            $DataOutputCourseInfo.Text = $Msg
            $tabCourseInfo.IsSelected = $true;
        }
        else {
            $statusBlock.Text = "manifest not found in $script:WorkingDirectory"
        }
    }
    else {
        $statusBlock.Text = "$WorkingDirectory Not Found!"
    }
})

$userButton.Add_Click({
    if (Test-Path $script:ManifestPath){
        $ManifestResources = Select-Xml -Path "$script:ManifestPath" -XPath "/manifest/resources"
        $UserFileInfo = $ManifestResources.node.resource | Where-Object{$_."type" -eq 'course/x-bb-user'}
        $Memberships = $ManifestResources.node.resource | Where-Object{$_."type" -eq 'membership/x-bb-coursemembership'}
        $UserData = Select-Xml -Path "$script:WorkingDirectory\$($UserFileInfo.file)" -XPath "/USERS"
        $MembershipData = select-xml -Path "$script:WorkingDirectory\$($Memberships.file)" -XPath "/COURSEMEMBERSHIPS"
        foreach ($Person in $UserData.Node.USER){
            $MemberInfo = $MembershipData.Node.COURSEMEMBERSHIP|Where-Object{$_.USERID.value -eq $Person.id}
            $DataOutputPeople.AddChild([pscustomobject]@{
                USERNAME = $Person.USERNAME.value;
                COURSEROLE = $MemberInfo.ROLE.value;
                ID = $Person.id;
                BATCHUID = $Person.BATCHUID.value;
                GIVEN = $Person.NAMES.GIVEN.value;
                FAMILY = $Person.NAMES.FAMILY.value;
                EMAIL = $Person.EMAILADDRESS.value;
                LASTACCESS = $MemberInfo.DATES.LASTACCESS.value;
            })
        }
        $statusBlock.Text = "finished outputing users"
        $tabUsers.IsSelected = $true;
    }
    else {
        $statusBlock.Text = "mainfest not found, add path and load the manifest first"
    }
})

$gradesButton.Add_Click({
    if (Test-Path $script:ManifestPath){
        $ManifestResources = Select-Xml -Path "$script:ManifestPath" -XPath "/manifest/resources"
        $GradebookFile = $ManifestResources.node.resource|Where-Object{$_."type" -eq 'course/x-bb-gradebook'}
        $GradebookData = Select-Xml -Path "$script:WorkingDirectory\$($GradebookFile.file)" -XPath "/GRADEBOOK"
        $StuEntries = $GradebookData.Node.GRADE_HISTORY_ENTRIES.GRADE_HISTORY_ENTRY|Where-Object{$_.USERNAME.value -eq $inputUser.Text}
        if ($StuEntries.count -lt 1){
            $statusBlock.Text = "No grades fround for $($inputUser.Text)"
        } 
        else {
            foreach ($GradeEntyr in $StuEntries){
                $GradeColumnInfo = $GradebookData.Node.OUTCOMEDEFINITIONS.OUTCOMEDEFINITION | Where-Object {$_.id -eq $GradeEntyr.GRADABLE_ITEM_ID.value}
                $DataOutputGrades.AddChild([pscustomobject]@{
                    GRADE = $GradeEntyr.GRADE.value;
                    NUMERIC_GRADE = $GradeEntyr.NUMERIC_GRADE;
                    INSTRUCTOR_COMMENTS = $GradeEntyr.INSTRUCTOR_COMMENTS.TEXT.value;
                    FEEDBACK_TO_USER = $GradeEntyr.FEEDBACK_TO_USER.TEXT.value;
                    DATEATTEMPTED = $GradeEntyr.DATEATTEMPTED.value;
                    DATE_LOGGED = $GradeEntyr.DATE_LOGGED.value;
                    MODIFIER_USERNAME = $GradeEntyr.MODIFIER_USERNAME.value;
                    id = $GradeEntyr.id;
                    GRADABLE_ITEM_ID = $GradeEntyr.GRADABLE_ITEM_ID.value;
                    GRADING_PERIODID = "outcome data";
                    TITLE = $GradeColumnInfo.TITLE.value
                    DISPLAY_TITLE = $GradeColumnInfo.DISPLAY_TITLE.value;
                    EXTERNALREF = $GradeColumnInfo.EXTERANLREF.value;
                    HANDLERURL = $GradeColumnInfo.HANDLERURL.value;;
                    WEIGHT = $GradeColumnInfo.WEIGHT.value;;
                    POINTSPOSSIBLE = $GradeColumnInfo.POINTSPOSSIBLE.value;;
                    MULTIPLEATTEMPTS = $GradeColumnInfo.MULTIPLEATTEMPTS.value;;
                })
            }
            $statusBlock.Text = "finished outputing grades"
            $TabGradeHistory.IsSelected = $true;
        }
    }
    else {
        $statusBlock.Text = "mainfest not found, add path and load the manifest first"
    }    
})

$gradeColumnsButton.Add_Click({
    if (Test-Path $script:ManifestPath){
        $ManifestResources = Select-Xml -Path "$script:ManifestPath" -XPath "/manifest/resources"
        $GradebookFile = $ManifestResources.node.resource|Where-Object{$_."type" -eq 'course/x-bb-gradebook'}
        $GradebookData = Select-Xml -Path "$script:WorkingDirectory\$($GradebookFile.file)" -XPath "/GRADEBOOK"
        $GradeColumns = $GradebookData.Node.OUTCOMEDEFINITIONS.OUTCOMEDEFINITION
        foreach ($GradeColumn in $GradeColumns){
            $Formula = $GradebookData.Node.FORMULAE.FORMULA|Where-Object{$_.GRADABLE_ITEM_ID.value -eq $GradeColumn.id}
            $DataOutputColumns.AddChild([pscustomobject]@{
                GRADABLE_ITEM_ID = $GradeColumn.id;
                TITLE =  $GradeColumn.Title.Value;
                DISPLAY_TITLE = $GradeColumn.DISPLAY_TITLE.value;
                DESCRIPTION = $GradeColumn.DESCRIPTION.TEXT
                EXTERNALREF = $GradeColumn.EXTERANLREF.value;
                HANDLERURL = $GradeColumn.HANDLERURL.value;
                WEIGHT = $GradeColumn.WEIGHT.value;
                POINTSPOSSIBLE = $GradeColumn.POINTSPOSSIBLE.value;
                MULTIPLEATTEMPTS = $GradeColumn.MULTIPLEATTEMPTS.value;
                FORMULATION = $Formula.JSON_TEXT;
            })
        }
        $TabGradeColumns.IsSelected = $true;
    }
    else {
        $statusBlock.Text = "mainfest not found, add path and load the manifest first"
    }    
})

$clearButton.Add_Click({
    $statusBlock.Text = ""
})
$videosButton.Add_Click({
    if (Test-Path $script:ManifestPath){
        $tabVideos.IsSelected = $true;
        $ManifestResources = Select-Xml -Path "$script:ManifestPath" -XPath "/manifest/resources"
        $AllDocs = $ManifestResources.node.resource|Where-Object{$_."type" -in ('resource/x-bb-document','resource/x-bb-blog')}
        $statusBlock.Text = $AllDocs.Count.ToString();
        foreach ($doc in $AllDocs){
            $ResourceTitle = $doc.title
            $ResourceInfoFile = $doc.file
            $ResourceInfo = Select-Xml -Path "$($script:WorkingDirectory)\$($ResourceInfoFile)" -XPath "/CONTENT"
            if ($ResourceInfo.Node.CONTENTHANDLER.value -eq "resource/x-bb-video"){
                #"\csfiles\home_dir\" 
                foreach ($Attachment in $ResourceInfo.Node.FILES.FILE){
                    $LinkName = $Attachment.LINKNAME.value
                    $LinkExtension = $LinkName.substring($LinkName.length - 4, 4).ToLower()
                    $LinkFilename = $Attachment.NAME.ToString().Replace('/','\')
                    $LinkFilename = $LinkFilename.Substring(1,($LinkFilename.length - 1))
                    $FileName = "{0}\csfiles\home_dir\__{1}{2}" -f $script:WorkingDirectory,$LinkFilename,$LinkExtension
                    $FileSize = [int]($Attachment.SIZE.value / (1024*1024))
                    $DataOutputVides.AddChild([PSCustomObject]@{
                        RESOURCE_FILE = $ResourceInfoFile
                        RESOURCE_TITLE = $ResourceTitle
                        FILE_PATH = $FileName
                        FILE_NAME = $LinkName
                        FILE_SIZE = $FileSize
                    })
                }
            }
            else {
                foreach ($Attachment in $ResourceInfo.Node.FILES.FILE){
                    $LinkName = $Attachment.LINKNAME.value
                    $LinkExtension = $LinkName.substring($LinkName.length - 4, 4).ToLower()
                    if ($LinkExtension -eq ".mp4"){
                        $LinkFilename = $Attachment.NAME.ToString().Replace('/','\')
                        $LinkFilename = $LinkFilename.Substring(1,($LinkFilename.length - 1))
                        $FileName = "{0}\csfiles\home_dir\__{1}{2}" -f $script:WorkingDirectory,$LinkFilename,$LinkExtension
                        $FileSize = [int]($Attachment.SIZE.value / (1024*1024))
                        $DataOutputVides.AddChild([PSCustomObject]@{
                            RESOURCE_FILE = $ResourceInfoFile
                            RESOURCE_TITLE = $ResourceTitle
                            FILE_PATH = $FileName
                            FILE_NAME = $LinkName
                            FILE_SIZE = $FileSize
                        })
                    }
                }                
            }
        }
    }
})
# display the WPF window
$window.ShowDialog()

<#
# ## ### #### ##### ###### ####### ######## ######### ########## ############## ############### ################ ################# 
#>

