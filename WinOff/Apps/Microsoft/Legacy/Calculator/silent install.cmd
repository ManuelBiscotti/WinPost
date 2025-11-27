<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

# install
Start-Process ".\setup\OldClassicCalc-setup.exe" -Argumentlist "/SILENT" -Wait
Rename-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator (classic).lnk" "Calculator.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:Public\Desktop\Calculator (classic).lnk" -Force -ErrorAction SilentlyContinue