$ProgressPreference = 'SilentlyContinue'

$windir = [Environment]::GetFolderPath('Windows')
& "$windir\AtlasModules\initPowerShell.ps1"

$packageInstall = "$windir\AtlasModules\Scripts\packageInstall.ps1"
if (!(Test-Path $packageInstall)) {
    Write-Host "Missing package install script, can't continue."
    Read-Pause
    exit 1
}

$package = "*Z-Atlas-NoTelemetry-Package*"

# Remove NoTelemetry package 
if ($TelemetryEnabled) { Menu }

Clear-Host
Write-Host "Removing the NoTelemetry package... This will take a moment." -ForegroundColor Yellow

& $packageInstall -NoInteraction -UninstallPackages @($package)
