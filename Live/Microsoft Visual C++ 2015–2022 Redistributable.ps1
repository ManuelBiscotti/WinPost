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

$Host.UI.RawUI.WindowTitle = 'Microsoft Visual C++ 2015–2022 Redistributable'
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

try {
	Write-Host "Installing Microsoft Visual C++ 2015–2022 Redistributable..."
	Get-FileFromWeb "https://aka.ms/vs/17/release/vc_redist.x86.exe" "$env:TEMP\vc_redist.x86.exe"
	Get-FileFromWeb "https://aka.ms/vs/17/release/vc_redist.x64.exe" "$env:TEMP\vc_redist.x64.exe"
	Start-Process -wait "$env:TEMP\vc_redist.x86.exe" -ArgumentList "/passive /norestart"
	Start-Process -wait "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/passive /norestart"
}catch {
    Write-Host "$($_.Exception.Message)" -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
