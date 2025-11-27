<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

Copy-Item ".\SetTimerResolution.exe" "C:\" -Force

$action  = New-ScheduledTaskAction -Execute "C:\SetTimerResolution.exe" -Argument "--resolution 5000 --no-console"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden

Register-ScheduledTask -TaskName "SetTimerResolution" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
