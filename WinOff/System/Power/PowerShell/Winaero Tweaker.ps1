# Run as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Paths
$downloadUrl = "https://winaerotweaker.com/download/winaerotweaker.zip"
$zipPath = "$env:TEMP\winaerotweaker.zip"
$extractPath = "$env:TEMP\winaerotweaker"

# Download
Write-Host "Downloading Winaero Tweaker..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

# Extract
Write-Host "Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Run SilentSetup.cmd
$cmdPath = Get-ChildItem -Path $extractPath -Recurse -Filter "SilentSetup.cmd" | Select-Object -First 1
if ($cmdPath) {
    Write-Host "Running silent setup..."
    Start-Process -FilePath $cmdPath.FullName -WindowStyle Hidden -Wait
} else {
    Write-Host "SilentSetup.cmd not found!"
    exit 1
}

# Cleanup
Remove-Item $zipPath -Force
Remove-Item $extractPath -Recurse -Force

Write-Host "Winaero Tweaker installed. Exiting..."
Start-Sleep -Seconds 2
exit
