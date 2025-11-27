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

$Host.UI.RawUI.WindowTitle = "Removes both Edge, and WebView."
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
Write-Host "Removing both Edge, and WebView..."
try {
	# Batch Version
	$batch = "$env:TEMP\Both.bat"
	Invoke-WebRequest 'https://github.com/ShadowWhisperer/Remove-MS-Edge/raw/refs/heads/main/Batch/Both.bat' -OutFile $batch -UseBasicParsing
	(Get-Content $batch -Raw) -replace '(?s)echo \[uac\(\)\].*?:uac\.done','fltmc >nul || (powershell "Start ''%~f0''" & exit) & cd /D "%~dp0"' | Set-Content $batch -Force -Encoding ASCII	
	& $batch -ErrorAction Stop
} catch {
	# EXE Version
	Invoke-WebRequest -Uri "https://github.com/ShadowWhisperer/Remove-MS-Edge/releases/latest/download/Remove-EdgeWeb.exe" -OutFile "$env:TEMP\Remove-EdgeWeb.exe"
	Start-Process "$env:TEMP\Remove-EdgeWeb.exe" -Args "/s" -Wait -ErrorAction Stop
	Remove-Item "$env:TEMP\Remove-EdgeWeb.exe" -Force -ErrorAction SilentlyContinue
	if ($LASTEXITCODE -ne 0) { throw "Batch removal also failed" }
}