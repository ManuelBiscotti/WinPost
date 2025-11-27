<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

# remove shortcut
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator.lnk" -Force -ErrorAction SilentlyContinue
# uninstall
Start-Process "${env:ProgramFiles}\OldClassicCalc\unins000.exe" -ArgumentList "/SILENT" -Wait -ErrorAction SilentlyContinue
Start-Process "${env:ProgramFiles}\Calc\unins000.exe" -ArgumentList "/SILENT" -Wait -ErrorAction SilentlyContinue


