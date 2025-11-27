<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

iwr -Uri "https://www.openal.org/downloads/oalinst.zip" -OutFile "$env:Temp\oalinst.zip"
Expand-Archive "$env:TEMP\oalinst.zip" $env:TEMP -Force
Start-Process "$env:TEMP\oalinst.exe" -ArgumentList "/silent" -Wait