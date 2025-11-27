# SPDX-FileCopyrightText: Copyright (c) 2023 ave9858 <edging.duj6i@simplelogin.com>
# SPDX-License-Identifier: CC0-1.0

$ErrorActionPreference = "Stop"
$regView = [Microsoft.Win32.RegistryView]::Registry32
$microsoft = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $regView).
OpenSubKey('SOFTWARE\Microsoft', $true)
$edgeUWP = "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
$uninstallRegKey = $microsoft.OpenSubKey('Windows\CurrentVersion\Uninstall\Microsoft Edge')
if ($null -eq $uninstallRegKey) {
	Write-Error "Edge is not installed!"
}
$uninstallString = $uninstallRegKey.GetValue('UninstallString') + ' --force-uninstall'
$tempPath = "$env:SystemRoot\SystemTemp"
if (-not (Test-Path -Path $tempPath) ) {
	$tempPath = New-Item "$env:SystemRoot\Temp\$([Guid]::NewGuid().Guid)" -ItemType Directory
}
$fakeDllhostPath = "$tempPath\dllhost.exe"

$edgeClient = $microsoft.OpenSubKey('EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}', $true)
if ($null -ne $edgeClient.GetValue('experiment_control_labels')) {
	$edgeClient.DeleteValue('experiment_control_labels')
}

$microsoft.CreateSubKey('EdgeUpdateDev').SetValue('AllowUninstall', '')

# Don't you have anything better to do?
Copy-Item "$env:SystemRoot\System32\cmd.exe" -Destination $fakeDllhostPath

[void](New-Item $edgeUWP -ItemType Directory -ErrorVariable fail -ErrorAction SilentlyContinue)
[void](New-Item "$edgeUWP\MicrosoftEdge.exe" -ErrorAction Continue)
Start-Process $fakeDllhostPath "/c $uninstallString" -WindowStyle Hidden -Wait
[void](Remove-Item "$edgeUWP\MicrosoftEdge.exe" -ErrorAction Continue)

[void](Remove-Item $fakeDllhostPath -ErrorAction Continue)

if (-not $fail) {
	[void](Remove-Item "$edgeUWP")
}

Write-Output "Edge should now be uninstalled!"