import-module ~\dev\LMS-AdminTasks\Canvas-API-Tasks.ps1
$beta = "school.beta.instructure.com"
$prod = "school.instructure.com"
$global:CanvasSite = $prod
$global:CanvasSite = $prod
$global:DirectoryDomain = "institution.tld"
$global:DirectoryUserPath = "OU=container name,DC=DirectoryDomain,DC=DirectoryTld"
$host.ui.rawui.WindowTitle = "Canvas Runner"
[string]$ConsoleLoggerName = "{1}\logs\CanvasRunnerLog-{0}.log" -f (Get-Date -uFormat %Y-%m-%d_%H.%M),$env:systemdrive

function Set-EnvVar {
    $env:CNVSITE=$($global:CanvasSite)
}
New-Alias -Name 'Set-PoshContext' -Value 'Set-EnvVar' -Scope Global -Force
Start-Transcript -Path $ConsoleLoggerName -NoClobber
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\material.cnv.json" | Invoke-Expression
$VerbosePreference = "Continue"
