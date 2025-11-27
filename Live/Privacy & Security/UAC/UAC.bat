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

Invoke-RestMethod "https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/8%20Advanced/8%20UAC.ps1" | Invoke-Expression
