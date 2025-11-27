<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

# uninstall remote desktop connection
Start-Process "mstsc" -ArgumentList "/Uninstall"
Clear-Host
# silent window for remote desktop connection
$processExists = Get-Process -Name mstsc -ErrorAction SilentlyContinue
if ($processExists) {
$running = $true
do {
$openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
foreach ($window in $openWindows) {
if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
Stop-Process -Force -Name mstsc -ErrorAction SilentlyContinue | Out-Null
$running = $false
}
}
} while ($running)
} else {
}
