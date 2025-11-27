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

$Host.UI.RawUI.WindowTitle = 'AchillesScript'
$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'
Clear-Host

cmd /c "curl.exe -Lo %tmp%\AchillesScript.cmd https://github.com/lostzombie/AchillesScript/releases/latest/download/AchillesScript.cmd && %tmp%\AchillesScript.cmd"



