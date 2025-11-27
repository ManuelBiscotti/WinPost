<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'

Get-AppxPackage -AllUsers | Where-Object {
    $_.Name -notlike '*NVIDIA*' -and
    $_.Name -notlike '*CBS*' -and
	$_.Name -notlike '*Store*' -and
	$_.Name -notlike '*AppInstaller*' -and
	$_.Name -notlike '*Winget*' -and
	$_.Name -notlike '*VCLibs*' -and
    $_.Name -notlike '*Microsoft.Windows.Ai.Copilot.Provider*' -and
    $_.Name -notlike '*Microsoft.Copilot*' -and
    $_.Name -notlike '*Gaming*' -and
    $_.Name -notlike '*Xbox*' -and
    $_.Name -notlike '*Widgets*' -and
    $_.Name -notlike '*Experience*' -and
    $_.Name -notlike '*Microsoft.BingSearch*'
} | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml" }