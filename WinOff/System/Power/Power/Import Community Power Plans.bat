@Echo Off & Set "_F0=%~f0" & Title

PowerShell.exe -NoProfile -Command "Set-Content -LiteralPath $Env:Temp\_.ps1 -Value ([RegEx]::Matches([System.IO.File]::ReadAllText($Env:_F0), '(?smi)^(Pause|Exit)(.*)$').Groups[2].Value) -Encoding Unicode -Force"
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%Temp%\_.ps1"
exit

function Del-PS1 {Remove-Item -LiteralPath $Env:Temp\_.ps1 -Force}

if ((Get-Item -LiteralPath 'Registry::HKU\S-1-5-19' -ErrorAction SilentlyContinue)) {Del-PS1} Else {
    try {Start-Process -FilePath PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Env:Temp\_.ps1`"" -Verb RunAs} Catch {Del-PS1}
    exit
}

$z="$env:TEMP\\PowerPlans.zip";$e=Join-Path $env:TEMP 'pow';Invoke-WebRequest "https://github.com/ManueITest/Accel/raw/refs/heads/main/zip/PowerPlans.zip" -OutFile $z;Expand-Archive $z $e -Force;Get-ChildItem $e -Filter *.pow | % { powercfg -import $_.FullName *>$null }
Start-Process powercfg.cpl

clear-host
write-host "Press any key to continue . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit