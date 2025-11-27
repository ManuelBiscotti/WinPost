<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

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

Write-Host "Installing .NET Freamework 3.5 (includes .NET 2.0 and 3.0) . . ."

try {

	# DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart
	Start-Process "dism.exe" -ArgumentList "/Online","/Enable-Feature","/FeatureName:NetFx3","/All","/NoRestart" -Wait -NoNewWindow

} catch {
	
	# Windows 10
	if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
	
		Get-FileFromWeb -URL "https://github.com/abbodi1406/dotNetFx35W10/releases/download/v0.20.01/dotNetFx35_WX_9_x86_x64.zip" -File "$env:TEMP\dotNetFx35_WX_9_x86_x64.zip" 	
		Expand-Archive "$env:TEMP\dotNetFx35_WX_9_x86_x64.zip" $env:TEMP -Force	
		Start-Process "$env:TEMP\dotNetFx35_WX_9_x86_x64.exe" -ArgumentList "/ai /S /NORESTART" -Wait
		
	}
	
	# Windows 11
	elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
	
		Get-FileFromWeb -URL "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W11.exe" -File "$env:TEMP\dotNet2035_W11.exe"
	    Start-Process "$env:TEMP\dotNet2035_W11.exe" -ArgumentList "/ais /gm2" -Wait

	} else {
	}
	
}
