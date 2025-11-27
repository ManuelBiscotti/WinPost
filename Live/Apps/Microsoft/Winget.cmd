<# : batch portion
@REM Credits: MAS & ASDCORP
@echo off & setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || (if not defined _elev powershell -NoProfile "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" & exit /b)
set "PS1=powershell"
where pwsh.exe>nul 2>&1 && set "PS1=pwsh"
Color 0F
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
:: Restore previous environment settings
endlocal
:: Exit the script successfully
goto :eof
: end batch / begin powershell #>

# download winget
curl.exe -L -o "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle" "https://aka.ms/getwinget"
Clear-Host
# install winget
Add-AppxPackage "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"
Clear-Host
# update winget
winget upgrade Microsoft.AppInstaller --silent --accept-source-agreements --accept-package-agreements


