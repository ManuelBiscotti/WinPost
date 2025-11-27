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

$Host.UI.RawUI.WindowTitle = "Chris Titus Tech's Windows Utility"
$ProgressPreference = "SilentlyContinue"  
$ErrorActionPreference = "SilentlyContinue"
Clear-Host

$json = @'
{
    "WPFTweaks": [
        "WPFTweaksTeredo",
        "WPFTweaksWifi",
        "WPFTweaksRazerBlock",
        "WPFTweaksDebloatAdobe",
        "WPFTweaksDisableWpbtExecution",
        "WPFTweaksDisableLMS1",
        "WPFTweaksConsumerFeatures",
        "WPFTweaksTele",
        "WPFTweaksAH",
        "WPFTweaksBlockAdobeNet",
        "WPFTweaksEdgeDebloat",
        "WPFTweaksLoc",
        "WPFTweaksDisableExplorerAutoDiscovery",
        "WPFTweaksBraveDebloat",
        "WPFTweaksPowershell7Tele",
        "WPFTweaksDisableCrossDeviceResume"
    ]
}
'@

$config = "$env:TEMP\tweaks.json"
$script = "$env:TEMP\winutil.ps1"

Set-Content -Path $config -Value $json -Encoding UTF8

curl.exe -L "https://github.com/ChrisTitusTech/winutil/releases/latest/download/winutil.ps1" -o "$script"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "powershell.exe"
$psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$script`" -Config `"$config`" -Run"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
$p.Start() | Out-Null

$reader = $p.StandardOutput
while (-not $p.HasExited) {
    $line = $reader.ReadLine()
    if ($line) {
        Write-Host $line
        if ($line -match "Tweaks are Finished") {
            $p.CloseMainWindow() | Out-Null
            Start-Sleep -Milliseconds 500
            if (-not $p.HasExited) { $p.Kill() }
            break
        }
    }
}
