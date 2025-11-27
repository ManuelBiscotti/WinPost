<# : batch portion
@echo off
setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || >nul 2>&1 net session || (
    if not defined _elev (
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c', '!_PSarg!' -Verb RunAs" && exit /b 0
        exit /b 1
    )
)
where pwsh.exe>nul 2>&1 && set "PS1=pwsh" || set "PS1=powershell"
Color 0F
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = "UninstallOneDrive"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
$ProgressPreference = 'SilentlyContinue'
Write-Host "Uninstalling OneDrive..."

try {
	
	Invoke-RestMethod 'https://github.com/asheroto/UninstallOneDrive/raw/refs/heads/master/UninstallOneDrive.ps1' | Invoke-Expression
	
} catch {
	
	# stop onedrive running
	Stop-Process -Force -Name OneDrive -ErrorAction SilentlyContinue | Out-Null
	# uninstall onedrive w10
	cmd /c "C:\Windows\SysWOW64\OneDriveSetup.exe -uninstall >nul 2>&1"
	# uninstall onedrive w11
	cmd /c "C:\Windows\System32\OneDriveSetup.exe -uninstall >nul 2>&1"
	# delete onedrive tasks
	Get-ScheduledTask | Where-Object {$_.Taskname -match 'OneDrive'} | Unregister-ScheduledTask -Confirm:$false
	
}