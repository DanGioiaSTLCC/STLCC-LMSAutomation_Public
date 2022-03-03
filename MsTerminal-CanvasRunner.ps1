import-module ~\ProfilePathTo\Canvas-API-Lib.ps1
$VerbosePreference = "Continue"
$global:CanvasSite = "school.instructure.com"
$host.ui.rawui.WindowTitle = "Canvas Runner"
[string]$ConsoleLoggerName = "{1}\logs\CanvasRunnerLog-{0}.log" -f (Get-Date -uFormat %Y-%m-%d_%H.%M),$env:systemdrive
Start-Transcript -Path $ConsoleLoggerName -NoClobber
$tknPath = "~\PathTo\CanvasTokenFile"
Clear-Host
