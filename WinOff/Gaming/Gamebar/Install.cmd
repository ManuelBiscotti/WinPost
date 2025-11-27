<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
# gamebar regedit				
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f | Out-Null				
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f | Out-Null				
# open xbox game bar using game controller regedit				
cmd.exe /c "reg delete `"HKCU\Software\Microsoft\GameBar`" /v `"UseNexusForGameBarEnabled`" /f >nul 2>&1"				
# gameinput service				
reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# gamedvr and broadcast user service regedit				
reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# xbox accessory management service regedit				
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# xbox live auth manager service regedit				
reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# xbox live game save service regedit				
reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# xbox live networking service regedit				
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null				
# ms-gamebar notifications with xbox controller plugged in regedit				
# create reg file				
$MultilineComment = @"				
Windows Registry Editor Version 5.00

; ms-gamebar notifications with xbox controller plugged in regedit
[-HKEY_CLASSES_ROOT\ms-gamebar]
[-HKEY_CLASSES_ROOT\ms-gamebarservices]
[-HKEY_CLASSES_ROOT\ms-gamingoverlay\shell]

[HKEY_CLASSES_ROOT\ms-gamingoverlay]
"URL Protocol"=""
@="URL:ms-gamingoverlay"
"@
Set-Content -Path "$env:TEMP\MsGamebarNotiOn.reg" -Value $MultilineComment -Force	
# import reg file
Regedit.exe /S "$env:TEMP\MsGamebarNotiOn.reg"		
# install gamebar app
Get-AppXPackage -AllUsers *Microsoft.XboxGameOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxGamingOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}			

Clear-Host
pause