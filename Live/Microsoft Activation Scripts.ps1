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

<#	
	
	.SYNOPSIS	
	Activates a permanent Microsoft Digital License for Windows 10/11.    
	
	.DESCRIPTION	
	Permanently activates Windows using the TSforge activation method, 100% open-source and works completely offline. (suitable for older systems and VMs).	
	Check Windows activation status and only proceeds with activation if Windows is not already activated.	
	Fully Open Source and based on Batch scripts.	
	
	.NOTES	
	Name: Microsoft Activation Scripts	
	About: Open-source Windows and Office activator	
	Version: Always uses the latest release (https://massgrave.dev/#mas-latest-release)    
	Author: MASSGRAVE    
	
	.LINK	
	Website: https://massgrave.dev/    
	Source: https://github.com/massgravel/Microsoft-Activation-Scripts 	
	
	.EXAMPLE	
	iex "& {$((irm https://get.activated.win))} /Z-Windows"    
	
	.PARAMETER /Z-Windows	
	Permanent Activation for Win 10/11 (Offline)	
	
	.PARAMETER /HWID	
	Permanent HWID Digital License for Win 10/11	
	
	.PARAMETER /KMS38	
	KMS Activation for Win 10/11/Server until 2038	
	
	.PARAMETER /K-Windows	
	Online KMS Activation (180-day renewable)	
	
#>

# ----------------------------------------------------------
# --------------------Activate Windows----------------------
# ----------------------------------------------------------
# https://github.com/massgravel/Microsoft-Activation-Scripts
$status=$null;try{$status=(Get-CimInstance -Class SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'"|Where-Object{$_.PartialProductKey}).LicenseStatus}catch{};if($status-ne 1){try{Get-FileFromWeb -URL "https://github.com/massgravel/Microsoft-Activation-Scripts/raw/master/MAS/Separate-Files-Version/Activators/HWID_Activation.cmd" -File "$env:TEMP\HWID_Activation.cmd"}catch{};try{Start-Process cmd.exe -ArgumentList "/c `"$env:TEMP\HWID_Activation.cmd`" /HWID" -Wait -Verb RunAs -ErrorAction SilentlyContinue}catch{};try{Remove-Item "$env:TEMP\HWID_Activation.cmd" -Force -ErrorAction SilentlyContinue}catch{}}
# ----------------------------------------------------------
Start-Sleep -Seconds 2


Invoke-Expression "& {$((Invoke-RestMethod https://get.activated.win))} /Z-Windows"	
Invoke-Expression "& {$((Invoke-RestMethod https://get.activated.win))} /HWID"
Invoke-Expression "& {$((Invoke-RestMethod https://get.activated.win))} /KMS38"	
Invoke-Expression "& {$((Invoke-RestMethod https://get.activated.win))} /K-Windows"	