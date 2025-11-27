<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
# install store
# Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# fix store
Start-Process "ms-windows-store://"
if (Get-Process -Name OpenWith -ErrorAction SilentlyContinue) {
    Stop-Process -Name OpenWith -Force
    Add-AppxPackage ".\Package\Microsoft.WindowsStore.msixbundle" -ForceApplicationShutdown
	Stop-Process -Name OpenWith -Force
} else { Stop-Process -Name OpenWith -Force -ErrorAction SilentlyContinue }
