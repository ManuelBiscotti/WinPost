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

Write-Host "Installing: Direct X . . ."

<#
Remove-Item "$env:TEMP\DirectX","$env:SystemRoot\Temp\DirectX" -Recurse -Force
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe" -File "$env:TEMP\DirectX.exe"
Start-Process "$env:TEMP\DirectX.exe" -ArgumentList "/Q /T:`"$env:TEMP\DirectX`"" -Wait
Start-Process "$env:TEMP\DirectX\DXSETUP.exe" -ArgumentList "/silent" -Wait	
#>

Get-FileFromWeb -URL "https://download.microsoft.com/download/1/7/1/1718ccc4-6315-4d8e-9543-8e28a4e18c4c/dxwebsetup.exe" -File "$env:TEMP\dxwebsetup.exe"
Start-Process "$env:TEMP\dxwebsetup.exe" -ArgumentList "/Q" -Wait

# D3D11 - D3D12 Tweaks
Invoke-WebRequest -Uri "https://github.com/HakanFly/Windows-Tweaks/raw/refs/heads/main/DirectX%20Tweaks/D3D11%20-%20D3D12%20Tweaks.reg" -OutFile "$env:TEMP\D3D11 - D3D12 Tweaks.reg"
# import reg file
Regedit.exe /S "$env:TEMP\D3D11 - D3D12 Tweaks.reg"
Timeout /T 1 | Out-Null
# DirectX Driver DXGKrnl Advanced Tweaks (2)
Invoke-WebRequest -Uri "https://github.com/HakanFly/Windows-Tweaks/raw/refs/heads/main/DirectX%20Tweaks/DirectX%20Driver%20DXGKrnl%20Advanced%20Tweaks%20(2).reg" -OutFile "$env:TEMP\DirectX Driver DXGKrnl Advanced Tweaks (2).reg"
# import reg file
Regedit.exe /S "$env:TEMP\DirectX Driver DXGKrnl Advanced Tweaks (2).reg"
Timeout /T 1 | Out-Null