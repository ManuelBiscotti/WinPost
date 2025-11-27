<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# install GameInput
Write-Host "Installing: GameInput . . ."
Start-Process "msiexec.exe" -ArgumentList "/i `"$PWD\microsoft.gameinput\redist\GameInputRedist.msi`"" -Wait
# silent 
# Start-Process "msiexec.exe" -ArgumentList "/i `"$PWD\microsoft.gameinput\redist\GameInputRedist.msi`" /quiet /norestart" -Wait
# enable GameInput service
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v Start /t REG_DWORD /d 3 /f | Out-Null

