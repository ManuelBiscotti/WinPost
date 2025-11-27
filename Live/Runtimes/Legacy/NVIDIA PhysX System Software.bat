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

function Invoke-PhysX { winget.exe install --id "Nvidia.PhysX" --exact --source winget --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force | Out-Null }

try {

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Invoke-PhysX
    } else {
        Invoke-WingetFix
        Invoke-PhysX
    }

} catch {

	Get-FileFromWeb -URL "https://us.download.nvidia.com/Windows/9.23.1019/PhysX_9.23.1019_SystemSoftware.exe" -File "$env:TEMP\PhysX_9.23.1019_SystemSoftware.exe"
	Start-Process "$env:TEMP\PhysX_9.23.1019_SystemSoftware.exe" -ArgumentList "/s /noreboot" -Wait

}