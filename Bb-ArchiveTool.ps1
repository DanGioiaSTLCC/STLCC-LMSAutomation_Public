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
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto" MinWidth="331"/>
            <ColumnDefinition Width="Auto" MinWidth="26"/>
        </Grid.ColumnDefinitions>
        <Label x:Name="lblTxtArchPath" Content="Path to Extracted Bb Course Archvie" Grid.Column="0" Grid.Row="0" FontSize="14"/>
        <TextBox x:Name="txtArchPath" Grid.Column="0" Grid.Row="1" Margin="10,10,0,94" />
        <Button x:Name="btnManifest" Content="Read Manifest" Grid.Column="0" Grid.Row="1" FontSize="14" Margin="10,42,10,43"/>
        <Button x:Name="btnUserInfo" Content="User Info" Grid.Column="1" HorizontalAlignment="Left" Margin="68,10,-172,0" VerticalAlignment="Top" Width="140"/>
        <Button x:Name="btnGradeColumns" Content="Grade Columns" Grid.Column="1" HorizontalAlignment="Left" Margin="68,14,-173,0" Grid.Row="1" VerticalAlignment="Top" Width="140"/>
        <Button x:Name="btnGradesForUser" Content="Grades for User" Grid.Column="1" HorizontalAlignment="Left" Margin="68,56,-174,-15" Grid.Row="1" VerticalAlignment="Top" Width="140"/>
        <TextBox x:Name="txtUsername" Grid.Column="1" HorizontalAlignment="Left" Height="23" Margin="68,94,-169,-50" Grid.Row="1" TextWrapping="Wrap" Text="username" VerticalAlignment="Top" Width="140"/>

        <Label Content="Data" HorizontalAlignment="Left" Margin="10,154,0,-63" Grid.Row="1" VerticalAlignment="Top" Height="36"/>
        <TextBlock x:Name="statusMsg" Grid.Column="1" HorizontalAlignment="Left" Margin="258,20,-292,0" TextWrapping="Wrap" Text="Status Messages" VerticalAlignment="Top" Height="112" Grid.RowSpan="2" Width="235"/>
        <Button Content="Clear" Grid.Column="1" HorizontalAlignment="Left" Margin="71,131,0,-28" Grid.Row="1" VerticalAlignment="Top" Width="75"/>
        <TabControl HorizontalAlignment="Left" Height="291" Margin="10,190,-407,-351" Grid.Row="1" VerticalAlignment="Top" Width="1207" Grid.ColumnSpan="2">
            <TabItem Header="Course Info">
                <TextBox Name="CourseInfo"
                TextWrapping="Wrap"
                AcceptsReturn="True"
                VerticalScrollBarVisibility="Visible"
                ></TextBox>
            </TabItem>
            <TabItem Header="Users">
                <DataGrid Name="DatagridPeople" AutoGenerateColumns="True">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Username" Binding="{Binding USERNAME}"/>
                        <DataGridTextColumn Header="Database ID" Binding="{Binding ID}"/>
                        <DataGridTextColumn Header="Person Key" Binding="{Binding BATCHUID}"/>
                        <DataGridTextColumn Header="First Name" Binding="{Binding GIVEN}"/>
                        <DataGridTextColumn Header="Last Name" Binding="{Binding FAMILY}"/>
                        <DataGridTextColumn Header="Email Address" Binding="{Binding EMAIL}"/>
                    </DataGrid.Columns>
                </DataGrid>
            </TabItem>
            <TabItem Header="Grades">
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
            </TabItem>
            <TabItem Header="Grade Columns">
                <DataGrid Name="DatagridGrades">
                    <DataGrid.Columns>
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
$statusBlock = $window.FindName("statusMsg")
$DataOutputGrades = $window.FindName("DatagridGrades")
$DataOutputPeople = $window.FindName("DatagridPeople")
$DataOutputCourseInfo = $window.FindName("CourseInfo")

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
            $CourseInfo = select-xml -Path "$($script:WorkingDirectory)\$($CrsSettings.file)" -XPath "/COURSE"
            $Msg += "`n Users:$($UserInfo.file)"
            $Msg += "`n Enroll:$($Memberships.file)"
            $Msg += "`n Grades:$($gradebook.file)"
            $statusBlock.Text = $Msg
            $Msg += "`n-------------------"
            $Msg += "`n Course ID:$($CourseInfo.node.COURSEID.value)"
            $Msg += "`n Course Name:$($CourseInfo.node.TITLE.value)"
            $Msg += "`n Created: $($CourseInfo.node.DATES.CREATED.value)"
            $Msg += "`n Modified: $($CourseInfo.node.DATES.UPDATED.value)"
            $Msg += "`n Open: $($CourseInfo.node.DATES.COURSESTART.value)"
            $Msg += "`n Close: $($CourseInfo.node.DATES.COURSEEND.value)"
            $DataOutputCourseInfo.Text = $Msg
            $DataOutputCourseInfo.Focus()
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
        $UserData = Select-Xml -Path "$script:WorkingDirectory\$($UserFileInfo.file)" -XPath "/USERS"
        foreach ($Person in $UserData.Node.USER){
            $DataOutputPeople.AddChild([pscustomobject]@{
                USERNAME = $Person.USERNAME.value;
                ID = $Person.id;
                BATCHUID = $Person.BATCHUID.value;
                GIVEN = $Person.NAMES.GIVEN.value;
                FAMILY = $Person.NAMES.FAMILY.value;
                EMAIL = $Person.EMAILADDRESS.value
            })
        }
        $statusBlock.Text = "finished outputing users"
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
        }
    }
    else {
        $statusBlock.Text = "mainfest not found, add path and load the manifest first"
    }    
})
# display the WPF window
$window.ShowDialog()

<#
# ## ### #### ##### ###### ####### ######## ######### ########## ############## ############### ################ ################# 
$WorkingDirectory = "C:\TEMP\ArhiveFixer" 
#>

