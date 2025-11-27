<# :
@echo off
setlocal EnableExtensions
fltmc >nul 2>&1 || (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
endlocal & exit /b
#>

Invoke-RestMethod https://get.activated.win | Invoke-Expression                    
Start-Process 'ms-settings:activation'					