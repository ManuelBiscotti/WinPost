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

$Host.UI.RawUI.WindowTitle = "EdgeRemover"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
$ProgressPreference = 'SilentlyContinue'
Write-Host "Uninstalling Microsoft Edge..."
$build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
if ($build -ge 26200) {
    # Windows 11 25H2+
	<#		    
	    .SYNOPSIS
	    Uninstall Microsoft Edge 					
	    .DESCRIPTION
	    Microsoft Edge will be completely uninstalled. The Microsoft Edge Update service might remain, this is normal as it is required for updating WebView2.			    
	    .LINK
	    https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6
			    
	#>
	Invoke-RestMethod "https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6/raw/UninstallEdge.ps1" |
	ForEach-Object {$_ -replace '\$ErrorActionPreference = "Stop"', '$ErrorActionPreference = "SilentlyContinue"'} |
	Set-Content -Path ([System.IO.Path]::Combine($env:TEMP, 'UninstallEdge.ps1')) -Encoding UTF8
	Start-Process -Wait -FilePath "PowerShell.exe" -ArgumentList ('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', [System.IO.Path]::Combine($env:TEMP, 'UninstallEdge.ps1'))
} else {
    try{
        <#
			.SYNOPSIS
			Uninstalls or reinstalls Microsoft Edge and its related components. Made by @he3als.
				
			.Description
			Uninstalls or reinstalls Microsoft Edge and its related components in a non-forceful manner, based upon switches or user choices in a TUI.
				
			.PARAMETER UninstallEdge
			Uninstalls Edge, leaving the Edge user data.
				
			.PARAMETER InstallEdge
			Installs Edge, leaving the previous Edge user data.
				
			.PARAMETER InstallWebView
			Installs Edge WebView2 using the Evergreen installer.
				
			.PARAMETER RemoveEdgeData
			Removes all Edge user data. Compatible with -InstallEdge.
				
			.PARAMETER KeepAppX
			Doesn't check for and remove the AppX, in case you want to use alternative AppX removal methods. Doesn't work with UninstallEdge.
				
			.PARAMETER NonInteractive
			When combined with other parameters, this does not prompt the user for anything.
				
			.LINK
			https://github.com/he3als/EdgeRemover
		#>

		Invoke-WebRequest -Uri "https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1" -OutFile ([System.IO.Path]::Combine($env:TEMP, 'EdgeRemover.ps1')) -UseBasicParsing
		
		Start-Process -Wait -FilePath "powershell.exe" -ArgumentList (
			'-NoProfile','-ExecutionPolicy', 'Bypass',
			'-File', [System.IO.Path]::Combine($env:TEMP, 'EdgeRemover.ps1'),
			'-UninstallEdge', '-RemoveEdgeData', '-NonInteractive'
		)
		
    }catch{
        Write-Host "$($_.Exception.Message)" -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
}
