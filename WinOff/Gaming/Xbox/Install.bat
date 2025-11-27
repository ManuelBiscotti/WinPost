<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
# fix gaming services
wsreset
takeown /a /r /f "$($env:USERPROFILE)\Documents\SEGA"
icacls "$($env:USERPROFILE)\Documents\SEGA" /reset /t /c
Get-AppxPackage -Name "Microsoft.GamingServices" | Remove-AppxPackage -PreserveApplicationData:$false -Verbose
Get-AppxPackage -Name "Microsoft.GamingServices" | Remove-AppxPackage -AllUsers -Verbose
Remove-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\MrtCache\*Microsoft.GamingServices*" -Recurse -Verbose
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\GamingServices" -Recurse -Verbose
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\GamingServicesNet" -Recurse -Verbose
# install xbox
Write-Host "Installing: Xbox . . ."
Get-AppXPackage -AllUsers *Microsoft.GamingApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Xbox.TCUI* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxIdentityProvider* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# install gaming services
Write-Host "Installing: Gaming Services . . ."
# Get-AppxPackage -AllUsers *Microsoft.GamingServices* | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
Add-AppxPackage ".\Gaming Services\Microsoft.GamingServices.AppxBundle"
# install microsoft store
Write-Host "Installing: Microsoft Store . . ."
Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# fix xbox sign in
# enable UAC
New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -PropertyType Dword -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -ErrorAction SilentlyContinue | Out-Null
# install webview2
Write-Host "Installing: WebView2 . . ."
Start-Process ".\Fix Xbox Sign In\MicrosoftEdgeWebview2Setup.exe"


