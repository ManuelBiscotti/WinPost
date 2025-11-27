<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# uninstall GameInput
Write-Output "Uninstalling: Microsoft GameInput . . ."
Start-Process "msiexec.exe" -ArgumentList "/x `"$((Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter GameInputRedist.msi -ErrorAction SilentlyContinue | Select-Object -First 1).FullName)`" /quiet /norestart" -Wait
Start-Process "msiexec.exe" -ArgumentList '/x {F563DC73-9550-F772-B4BF-2F72C83F9F30} /qn /norestart'
Start-Process "msiexec.exe" -ArgumentList '/x {0812546C-471E-E343-DE9C-AECF3D0137E6} /qn /norestart'
# disable GameInput service
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v Start /t REG_DWORD /d 4 /f | Out-Null
