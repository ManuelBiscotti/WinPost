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

$Host.UI.RawUI.WindowTitle = "Web Installer DirectX End-User Runtime"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
$ProgressPreference = 'SilentlyContinue'
function Get-FileFromWeb {
	param([string]$URL, [string]$File)
 	try{if(Get-Command curl.exe -ErrorAction SilentlyContinue){curl.exe -L $URL -o $File -s}
 	elseif((Get-Service BITS -ErrorAction SilentlyContinue).Status -eq 'Running'){
 	Start-BitsTransfer -Source $URL -Destination $File -ErrorAction Stop
 	}else{Invoke-WebRequest -Uri $URL -OutFile $File -UseBasicParsing -ErrorAction Stop}
	}catch{throw $_}
}

Write-Host "Installing DirectX End-User Runtime..."
try {
    Get-FileFromWeb "https://download.microsoft.com/download/1/7/1/1718ccc4-6315-4d8e-9543-8e28a4e18c4c/dxwebsetup.exe" "$env:TEMP\dxwebsetup.exe"
    Start-Process "$env:TEMP\dxwebsetup.exe" -ArgumentList "/Q" -Wait -ErrorAction Stop
}
catch {
    try {
        Remove-Item "$env:TEMP\DirectX","$env:SystemRoot\Temp\DirectX" -Recurse -Force -ErrorAction SilentlyContinue
        Get-FileFromWeb "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe" "$env:TEMP\DirectX.exe"
        Start-Process "$env:TEMP\DirectX.exe" -ArgumentList "/Q /T:`"$env:TEMP\DirectX`"" -Wait -ErrorAction Stop
        Start-Process "$env:TEMP\DirectX\DXSETUP.exe" -ArgumentList "/silent" -Wait -ErrorAction Stop
    }
    catch {
        Write-Host "$($_.Exception.Message)" -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
}

# Remove "DirectX Configuration Database" capability
Remove-WindowsCapability -Online -Name "DirectX.Configuration.Database~~~~0.0.1.0" | Out-Null

# Clear DirectX recent application history
$bat = @'
@echo off & setlocal DisableDelayedExpansion
:: https://privacy.sexy — v0.13.8 — Mon, 24 Nov 2025 16:33:05 GMT
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
echo "%*" | find /i "-el" >nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || (
    if not defined _elev powershell -NoProfile "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" && exit /b 0
    echo Right-click on the script and select "Run as administrator".
    pause & exit 1
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: ---------Clear DirectX recent application history---------
:: ----------------------------------------------------------
echo --- Clear DirectX recent application history
:: Clear registry values from "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" 
PowerShell -ExecutionPolicy Unrestricted -Command "$rootRegistryKeyPath = 'HKCU\Software\Microsoft\Direct3D\MostRecentApplication'; function Clear-RegistryKeyValues { try { $currentRegistryKeyPath = $args[0]; Write-Output "^""Clearing registry values from `"^""$currentRegistryKeyPath`"^""."^""; $formattedRegistryKeyPath = $currentRegistryKeyPath -replace '^([^\\]+)', '$1:'; if (-Not (Test-Path -LiteralPath $formattedRegistryKeyPath)) { Write-Output "^""Skipping: Registry key not found: `"^""$formattedRegistryKeyPath`"^""."^""; return; }; $directValueNames=(Get-Item -LiteralPath $formattedRegistryKeyPath -ErrorAction Stop | Select-Object -ExpandProperty Property); if (-Not $directValueNames) { Write-Output 'Skipping: Registry key has no direct values.'; } else { foreach ($valueName in $directValueNames) { Remove-ItemProperty -LiteralPath $formattedRegistryKeyPath -Name $valueName -ErrorAction Stop; Write-Output "^""Successfully deleted value: `"^""$valueName`"^"" from `"^""$formattedRegistryKeyPath`"^""."^""; }; Write-Output "^""Successfully cleared all direct values in `"^""$formattedRegistryKeyPath`"^""."^""; }; } catch { Write-Error "^""Failed to clear registry values in `"^""$formattedRegistryKeyPath`"^"". Error: $_"^""; Exit 1; }; }; Clear-RegistryKeyValues $rootRegistryKeyPath"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
'@
Set-Content -Path "$env:TEMP\privacy-script.bat" -Value $bat -Encoding ASCII
& "$env:TEMP\privacy-script.bat" | Out-Null

# DirectX Tweaks
try {
	# Disable variable refresh rate and enable optimizations for windowed games
	& reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /d "SwapEffectUpgradeEnable=1;VRROptimizeEnable=0;" /f | Out-Null
	# D3D11 - D3D12 Tweaks
    $reg = "$env:TEMP\D3D11 - D3D12 Tweaks.reg"
    Get-FileFromWeb "https://github.com/HakanFly/Windows-Tweaks/raw/refs/heads/main/DirectX%20Tweaks/D3D11%20-%20D3D12%20Tweaks.reg" "$reg"
	& Regedit.exe /S "$reg"
	# DirectX Driver DXGKrnl Advanced Tweaks (2)
    $reg = "$env:TEMP\DirectX Driver DXGKrnl Advanced Tweaks (2).reg"
    Get-FileFromWeb "https://github.com/HakanFly/Windows-Tweaks/raw/refs/heads/main/DirectX%20Tweaks/DirectX%20Driver%20DXGKrnl%20Advanced%20Tweaks%20(2).reg" "$reg"
	& Regedit.exe /S "$reg"
}
catch {
    Write-Host "$($_.Exception.Message)" -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}