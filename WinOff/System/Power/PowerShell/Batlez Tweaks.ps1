# Get Desktop and Temp folder paths
$desktop = [Environment]::GetFolderPath('Desktop')
$temp = [IO.Path]::GetTempPath()

# GitHub repo info
$repo = "Batlez/Batlez-Tweaks"
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"

# Get latest release info
$release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }

# Find the asset with the correct file name
$asset = $release.assets | Where-Object { $_.name -eq "Batlez.Folder.zip" }

if ($null -eq $asset) {
    Write-Error "Batlez.Folder.zip not found in the latest release."
    exit 1
}

# Download to temp folder
$zipPath = Join-Path $temp $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

# Unzip to Desktop
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $desktop)

# Cleanup and autoclose
Remove-Item $zipPath
exit
