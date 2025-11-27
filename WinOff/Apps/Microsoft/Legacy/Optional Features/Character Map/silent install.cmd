<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

# create Character Map start menu shortcut
$shell = New-Object -ComObject WScript.Shell
$lnk = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk"

New-Item -ItemType Directory -Path (Split-Path $lnk) -Force | Out-Null 2>&1
$shortcut = $shell.CreateShortcut($lnk)
$shortcut.TargetPath  = "$env:SystemRoot\System32\charmap.exe"
$shortcut.IconLocation = "$env:SystemRoot\System32\charmap.exe"
$shortcut.Save()

Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator (classic).lnk" -Force -ErrorAction SilentlyContinue

