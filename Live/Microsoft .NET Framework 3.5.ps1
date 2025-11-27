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

$Host.UI.RawUI.WindowTitle = "Microsoft .NET Framework 3.5"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
$ProgressPreference = 'SilentlyContinue'
try{$feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop}catch{
	Write-Host "$($_.Exception.Message)" -ForegroundColor Red
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	exit 1
}
if ($feature.State -eq 'Enabled') {$null}
else {
	$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild # OS build
	function Show-WindowsInfo {
		$reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
		$build    = [int]$reg.CurrentBuildNumber
		$edition  = $reg.EditionID
		if ($build -ge 22000) {$os = "Windows 11"} else {$os = "Windows 10"}
		Write-Host "Installing Microsoft .NET Framework 3.5..."
		Write-Host "Edition "  -NoNewLine; Write-Host "$os $edition" -ForegroundColor DarkGray
		Write-Host "OS build " -NoNewLine; Write-Host $build -ForegroundColor DarkGray
		Write-Host ""
	}
	function GetFileFromWeb {
		param([string]$URL, [string]$File)
 		try{if(Get-Command curl.exe -ErrorAction SilentlyContinue){curl.exe -L $URL -o $File}
 			elseif((Get-Service BITS -ErrorAction SilentlyContinue).Status -eq 'Running'){
 			Start-BitsTransfer -Source $URL -Destination $File -ErrorAction Stop
 			}else{Invoke-WebRequest -Uri $URL -OutFile $File -UseBasicParsing -ErrorAction Stop}
		}catch{throw $_}
	}
	function Invoke-Download {
		try{GetFileFromWeb $URL $File -ErrorAction Stop}catch{
			Write-Host "$($_.Exception.Message)" -ForegroundColor Red
			$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			exit 1
		}
	}
	function Install-Feature {
		try { Start-Process -FilePath $File -ArgumentList "/ai" -Wait -ErrorAction Stop } catch {
			Clear-Host
			Write-Host "$($_.Exception.Message)" -ForegroundColor Red
			$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			exit 1
		}
	}

	<#
		.SYNOPSIS
		.NET 3.5 Feature Installer for Windows 10 x86/x64
		.DESCRIPTION
		Standalone Offline Installer to enable (install .NET Framework 3.5 feature for Windows 10
		Windows 10 images already contain language resources for .NET 3.5
		this is basically an AIO for microsoft-windows-netfx3-ondemand-package.cab for x86 and x64 arhitectures.
		.NOTES
		Author: Ionuț Bara
		GitHub: @ionuttbara
		.LINK
		https://github.com/ionuttbara/dotNet2035onW1X	
	#>

	# for Windows 10 build 14393/15063/16299 - dotNet2035_W10P1.exe
    if ($build -le 16299) {
		Show-WindowsInfo
		$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P1.exe"
        $File = "$env:TEMP\dotNet2035_W10P1.exe"
		Invoke-Download
		Install-Feature
    }

	# for Windows 10 17134/17363/18362/19041  -dotNet2035_W10P2.exe
    elseif ($build -ge 16299 -and $build -lt 22000) {
		Show-WindowsInfo
    	$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P2.exe"
		$File = "$env:TEMP\dotNet2035_W10P2.exe"
		Invoke-Download
		Install-Feature
    }

    # for Windows 11 22000/22621 - dotNet2035_W11.exe
    elseif ($build -ge 22000) {
		Show-WindowsInfo
		$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W11.exe"
		$File = "$env:TEMP\dotNet2035_W11.exe"
		Invoke-Download
		Install-Feature
		Start-Sleep -Seconds 5
    	$feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3
		if ($feature.State -eq 'Enabled') {$null} 
		else {
			Write-Host ""
			Write-Host "Feature installation failed." -ForegroundColor Red
			Write-Host "Trying second method..."
			Write-Host ""
			<#
				.SYNOPSIS
				Windows 11 .NET Framework 3.5 Offline Installer
				.DESCRIPTION
				Are you facing this issue?
				Error code: 0x800F0950
				This tool will help you to install .NET Framework 3.5 on Windows 11.
				.NOTES
				Author: Muhammad Akbar Habiby Khalid
				GitHub: @akbarhabiby
				.LINK
				https://github.com/akbarhabiby/Windows11_dotNET-3.5
			#>
			$URL = "https://github.com/akbarhabiby/Windows11_dotNET-3.5/archive/refs/tags/v1.1.zip"
			$File = "$env:TEMP\v1.1.zip"
			Invoke-Download
			Expand-Archive $File $env:TEMP -Force
			$batch = "$env:TEMP\Windows11_dotNET-3.5-1.1\app\start.bat"
			(Get-Content $batch) | Where-Object {$_ -notmatch '^\s*pause\s*$'} | Set-Content $batch	
			Start-Process -Wait -FilePath $batch
		}
	}
	# Unsupported build
    else {
		Show-WindowsInfo
		dism.exe /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart
	}	
}