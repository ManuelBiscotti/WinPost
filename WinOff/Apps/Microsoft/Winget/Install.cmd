<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
Add-AppxPackage ".\Microsoft.DesktopAppInstaller.msixbundle"
winget upgrade Microsoft.AppInstaller | Out-Null
