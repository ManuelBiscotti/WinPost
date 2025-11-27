<# : batch portion
@echo off & setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || (if not defined _elev powershell -NoProfile "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" & exit /b)
set "PS1=powershell"
where pwsh.exe>nul 2>&1 && set "PS1=pwsh"
Color 0F
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = 'Portmaster'
$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'
Clear-Host

# get latest portmaster windows installer
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
$html = Invoke-WebRequest "https://safing.io/download/" -Headers @{ "User-Agent" = $ua } -UseBasicParsing
$url = ($html.Links | Where-Object { $_.href -match '\.exe$' } | Select-Object -First 1).href
$filename = [System.IO.Path]::GetFileName($url)

# download and install
curl.exe -L "$url" -o "$env:TEMP\$filename"
Start-Process "$env:TEMP\$filename" -ArgumentList "/S" -Wait
