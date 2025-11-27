<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

function Invoke-WingetFix {
    # Ensure TLS 1.2 for secure web requests
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install or Update Chocolatey and Winget
    if (Get-Command choco.exe) {
        choco upgrade chocolatey -y --ignore-checksums --no-progress --quiet | Out-Null
    } else {
        Write-Host "Installing Chocolatey..." -ForegroundColor Green

        # Clean old remnants safely
        Remove-Item "C:\ProgramData\Chocolatey*" -Recurse -Force
        Remove-Item "C:\ProgramData\ChocolateyHttpCache" -Recurse -Force
        Start-Sleep -Seconds 2

        # Install Chocolatey
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        # Wait until Chocolatey is ready (max 60 sec)
        $timeout = 0
        while (-not (Get-Command choco.exe) -and $timeout -lt 20) {
            Start-Sleep -Seconds 3
            $timeout++
        }
    }

    # Winget
    $winget = Get-Command winget.exe
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild

    if ($winget) {
        choco upgrade winget -y --ignore-checksums # -quiet | Out-Null
    } else {
        if ($build -le 19045) {
            Write-Host "Repairing Winget for Windows 10 . . ." -ForegroundColor Green
            Start-Process powershell.exe -ArgumentList @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command', 'Invoke-RestMethod https://asheroto.com/winget | Invoke-Expression'
            ) -Wait
        } elseif ($build -ge 22000) {
            Write-Host "Repairing Winget for Windows 11 . . ." -ForegroundColor Green
            choco install winget -y --force --ignore-checksums --quiet | Out-Null
        } else {
            Write-Host "Unsupported Windows build: $build" -ForegroundColor Red
        }
    }
}

function Get-FileFromWeb {

    param ([Parameter(Mandatory)][string]$URL, [Parameter(Mandatory)][string]$File)
	
    function Show-Progress {
		param ([Parameter(Mandatory)][Single]$TotalValue, [Parameter(Mandatory)][Single]$CurrentValue, [Parameter(Mandatory)][string]$ProgressText, [Parameter()][int]$BarSize = 10, [Parameter()][switch]$Complete)
		$percent = $CurrentValue / $TotalValue
		$percentComplete = $percent * 100
		if ($psISE) { Write-Progress "$ProgressText" -id 0 -percentComplete $percentComplete }
		else { Write-Host -NoNewLine "`r$ProgressText $(''.PadRight($BarSize * $percent, [char]9608).PadRight($BarSize, [char]9617)) $($percentComplete.ToString('##0.00').PadLeft(6)) % " }
    }
	
    try {
		$request = [System.Net.HttpWebRequest]::Create($URL)
		$response = $request.GetResponse()
		if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) { throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'." }
		if ($File -match '^\.\\') { $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1] }
		if ($File -and !(Split-Path $File)) { $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File }
		if ($File) { $fileDirectory = $([System.IO.Path]::GetDirectoryName($File)); if (!(Test-Path($fileDirectory))) { [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null } }
		[long]$fullSize = $response.ContentLength
		[byte[]]$buffer = new-object byte[] 1048576
		[long]$total = [long]$count = 0
		$reader = $response.GetResponseStream()
		$writer = new-object System.IO.FileStream $File, 'Create'
		do {
			$count = $reader.Read($buffer, 0, $buffer.Length)
			$writer.Write($buffer, 0, $count)
			$total += $count
			if ($fullSize -gt 0) { Show-Progress -TotalValue $fullSize -CurrentValue $total -ProgressText " $($File.Name)" }
		} while ($count -gt 0)
    }
	
    finally {
		$reader.Close()
		$writer.Close()
    }
	
}

function Invoke-DotNetDesktopRuntimesAIO {
	foreach($id in "Microsoft.DotNet.DesktopRuntime.3_1","Microsoft.DotNet.DesktopRuntime.5","Microsoft.DotNet.DesktopRuntime.6","Microsoft.DotNet.DesktopRuntime.7","Microsoft.DotNet.DesktopRuntime.8","Microsoft.DotNet.DesktopRuntime.9"){
		winget.exe install --id=$id -a x64 --exact --source winget --accept-source-agreements --accept-package-agreements --force | Out-Null
	}   	
}

Write-Host "Installing: Microsoft .NET Desktop Runtimes . . ."

try {

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Invoke-DotNetDesktopRuntimesAIO
    } else {
        Invoke-WingetFix
        Invoke-DotNetDesktopRuntimesAIO
    }

} catch {

    Get-FileFromWeb -URL "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/5.0.17/windowsdesktop-runtime-5.0.17-win-x64.exe" -File "$env:TEMP\windowsdesktop-runtime-5.0.17.exe"
    Get-FileFromWeb -URL "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/6.0.36/windowsdesktop-runtime-6.0.36-win-x64.exe" -File "$env:TEMP\windowsdesktop-runtime-6.0.36.exe"
    Get-FileFromWeb -URL "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/7.0.20/windowsdesktop-runtime-7.0.20-win-x64.exe" -File "$env:TEMP\windowsdesktop-runtime-7.0.20.exe"
    Get-FileFromWeb -URL "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/8.0.21/windowsdesktop-runtime-8.0.21-win-x64.exe" -File "$env:TEMP\windowsdesktop-runtime-8.0.21.exe"
    Get-FileFromWeb -URL "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.10/windowsdesktop-runtime-9.0.10-win-x64.exe" -File "$env:TEMP\windowsdesktop-runtime-9.0.10.exe"

    Start-Process "$env:TEMP\windowsdesktop-runtime-5.0.17.exe" -ArgumentList "/install /quiet /norestart" -Wait
    Start-Process "$env:TEMP\windowsdesktop-runtime-6.0.36.exe" -ArgumentList "/install /quiet /norestart" -Wait
    Start-Process "$env:TEMP\windowsdesktop-runtime-7.0.20.exe" -ArgumentList "/install /quiet /norestart" -Wait
    Start-Process "$env:TEMP\windowsdesktop-runtime-8.0.21.exe" -ArgumentList "/install /quiet /norestart" -Wait
    Start-Process "$env:TEMP\windowsdesktop-runtime-9.0.10.exe" -ArgumentList "/install /quiet /norestart" -Wait
}