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
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
Color 0F
goto :eof
: end batch / begin powershell #>

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = 'WPD | Privacy dashboard for Windows'
$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'
Clear-Host

<#

	.SYNOPSIS
	WPD | Privacy dashboard for Windows
	
	.LINK
	https://wpd.app/
	
#>

# disable firewall
netsh advfirewall set allprofiles state off | Out-Null	
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f > $null 2>&1	

# run WPD
cmd /c "curl.exe -Lo %tmp%\latest.zip https://wpd.app/get/latest.zip && tar -xf %tmp%\latest.zip -C %tmp% && %tmp%\WPD.exe -wfpOnly -wfp on -recommended -close"
