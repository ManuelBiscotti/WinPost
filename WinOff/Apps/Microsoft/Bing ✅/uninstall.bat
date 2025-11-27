<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# disable web search
If (!(Test-Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer')) {
	New-Item -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
New-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 1 -Force

# uninstall bing
$ProgressPreference = 'SilentlyContinue'
Get-AppxPackage -allusers *Microsoft.BingSearch* | Remove-AppxPackage

# restart explorer
Stop-Process -name explorer -force -ErrorAction SilentlyContinue | Out-Null

