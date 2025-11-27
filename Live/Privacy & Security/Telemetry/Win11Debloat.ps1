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

$Host.UI.RawUI.WindowTitle = 'Win11Debloat'
$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'
Clear-Host

& ([scriptblock]::Create((Invoke-RestMethod "https://debloat.raphi.re/"))) `
    -Silent `
    -DisableTelemetry `
    -DisableSuggestions `
    -DisableEdgeAds `
    -DisableDesktopSpotlight `
    -DisableLockscreenTips `
    -DisableSettings365Ads `
    -DisableSettingsHome `
    -DisableClickToDo `
    -DisableRecall `
    -DisableEdgeAI `
    -DisablePaintAI `
    -DisableNotepadAI `
    -DisableStickyKeys `
    -DisableModernStandbyNetworking `
    -HideChat `
    -HideHome `
    -HideGallery `
    -ExplorerToThisPC `
    -Hide3dObjects `
    -HideIncludeInLibrary `
    -HideGiveAccessTo `
    -HideShare