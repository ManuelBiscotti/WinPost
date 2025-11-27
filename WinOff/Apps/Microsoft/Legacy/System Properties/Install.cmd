<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System Properties.lnk")
$shortcut.TargetPath  = "$env:SystemRoot\System32\SystemPropertiesAdvanced.exe"
$shortcut.IconLocation = "$env:SystemRoot\System32\SystemPropertiesAdvanced.exe"
$shortcut.Save()
