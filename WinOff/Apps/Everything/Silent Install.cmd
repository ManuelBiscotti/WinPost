<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

Start-Process ".\setup\Everything-x64-Setup.exe" -ArgumentList "/S" -Wait

# Rename Start Menu shortcut and remove desktop shortcut
$start      = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$everything = Join-Path $start 'Everything.lnk'

if (Test-Path Join-Path $start 'Search.lnk') {Remove-Item $everything -Force}
elseif (Test-Path $everything) {Rename-Item $everything 'Search.lnk' -Force}

Remove-Item "$env:PUBLIC\Desktop\Everything.lnk" -Force

<#
	Pin Everything.exe to the Taskbar Using PS-TBPin https://github.com/DanysysTeam/PS-TBPin (Flag by AV)
	powershell -ExecutionPolicy Bypass -command "& { 
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DanysysTeam/PS-TBPin/main/TBPin.ps1'))
		Add-TaskbarPin 'C:\Program Files\Everything\Everything.exe' 
	}"
#>

# Disable Windows Search
Stop-Service -Name WSearch -Force | Out-Null
Set-Service -Name WSearch -StartupType Disabled | Out-Null

# Disable Search Engine (breaks Search App)
# Dism /Online /NoRestart /Disable-Feature /FeatureName:SearchEngine-Client-Package | Out-Null