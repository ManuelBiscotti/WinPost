#######################
# .ps1 script content #
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent(
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"

Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.TopMost = $true
$form.FormBorderStyle = 'None'
$form.ShowInTaskbar = $false
$form.BackColor = [System.Drawing.Color]::Black
$form.Opacity = 0.40
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.StartPosition = "Manual"
$form.Show()
$form.Activate()

Start-Sleep -Milliseconds 200

function Get-FileFromWeb {
    param($URL, $File)
    $resp = [System.Net.HttpWebRequest]::Create($URL).GetResponse()
    if ($resp.StatusCode -in 401, 403, 404) { return }
    if (!(Split-Path $File)) { $File = Join-Path (Get-Location) $File }
    $dir = [System.IO.Path]::GetDirectoryName($File)
    if (!(Test-Path $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    $buf = [byte[]]::new(1MB)
    $r = $resp.GetResponseStream()
    $w = [System.IO.File]::Open($File, 'Create')
    while (($cnt = $r.Read($buf, 0, $buf.Length)) -gt 0) { $w.Write($buf, 0, $cnt) }
    $r.Close(); $w.Close(); $resp.Close()
}

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'


# ----------------------------------------------------------
# -------------------Registry Tweaks------------------------
# ----------------------------------------------------------
$temp="$env:TEMP\Registry.ps1"; Get-FileFromWeb -URL "https://github.com/ManueITest/RegistryTweaks/raw/refs/heads/main/Registry.ps1" -File $temp; powershell -NoProfile -ExecutionPolicy Bypass -File $temp; Remove-Item $temp -Force
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# ----------Pause Windows updates until 7/11/3000-----------
# ----------------------------------------------------------
Write-Host "--- Pausing Windows updates until 7/11/3000"
$pauseExpiry="3000-07-11T12:00:00Z"; $pauseStart=(Get-Date).ToString("yyyy-MM-ddT00:00:00Z")
$updateKeys=@("PauseUpdatesExpiryTime",$pauseExpiry),("PauseUpdatesStartTime",$pauseStart),("PauseFeatureUpdatesStartTime",$pauseStart),("PauseFeatureUpdatesEndTime",$pauseExpiry),("PauseQualityUpdatesStartTime",$pauseStart),("PauseQualityUpdatesEndTime",$pauseExpiry)
$path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; if(!(Test-Path $path)){New-Item $path -Force|Out-Null}; $updateKeys|%{Set-ItemProperty -Path $path -Name $_[0] -Value $_[1] -Type String}
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# ------------Raphire Win11Debloat Automation---------------
# ----------------------------------------------------------
# https://github.com/Raphire/Win11Debloat/wiki/How-To-Use#parameters
Get-FileFromWeb -URL "https://github.com/Raphire/Win11Debloat/archive/refs/heads/master.zip" -File "$env:TEMP\win11debloat.zip"; if (Test-Path "$env:TEMP\Win11Debloat") {Get-ChildItem "$env:TEMP\Win11Debloat" -Exclude CustomAppsList,SavedSettings,Win11Debloat.log|Remove-Item -Recurse -Force}; Expand-Archive "$env:TEMP\win11debloat.zip" "$env:TEMP" -Force; $f=Get-ChildItem "$env:TEMP"|?{$_.PSIsContainer -and $_.Name -like "Win11Debloat*"}|Select-Object -First 1; if ($f) {Rename-Item $f.FullName "$env:TEMP\Win11Debloat" -Force}; Remove-Item "$env:TEMP\win11debloat.zip" -Force
$p=Start-Process powershell.exe -ArgumentList ('-executionpolicy bypass -file "'+"$env:TEMP\Win11Debloat\Win11Debloat.ps1"+'" -CreateRestorePoint -Silent -RemoveHPApps -DisableDVR -ClearStartAllUsers -DisableStartRecommended -DisableTelemetry -DisableSuggestions -DisableDesktopSpotlight -DisableLockscreenTips -DisableSettings365Ads -DisableSettingsHome -DisableBing -DisableCopilot -DisableRecall -RevertContextMenu -DisableMouseAcceleration -DisableStickyKeys -DisableFastStartup -ShowHiddenFolders -ShowKnownFileExt -HideDupliDrive -EnableDarkMode -DisableTransparency -DisableAnimations -TaskbarAlignLeft -HideSearchTb -HideTaskview -HideChat -DisableWidgets -EnableEndTask -HideHome -HideGallery -ExplorerToThisPC -HideOnedrive -Hide3dObjects -HideIncludeInLibrary -HideGiveAccessTo -HideShare') -Wait -PassThru -Verb RunAs; if ($p) {$p.WaitForExit()}; Remove-Item "$env:TEMP\Win11Debloat" -Recurse -Force
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# ------Chris Titus Tech's Windows Utility Automation-------
# ---------------------------------------------------------- 
# https://winutil.christitus.com/userguide/automation/
$script="$env:TEMP\winutil.ps1";$config="$env:TEMP\tweaks.json";Get-FileFromWeb "https://github.com/ChrisTitusTech/winutil/releases/latest/download/winutil.ps1" $script;Get-FileFromWeb "https://github.com/ManueITest/Accel/raw/refs/heads/main/json/tweaks.json" $config
$p=Start-Process powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script,'-Config',$config,'-Run') -PassThru;Start-Sleep 85;if($p){Stop-Process $p.Id -Force}
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# --------------------Activate Windows----------------------
# ----------------------------------------------------------
# https://github.com/massgravel/Microsoft-Activation-Scripts
$status=$null;try{$status=(Get-CimInstance -Class SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'"|Where-Object{$_.PartialProductKey}).LicenseStatus}catch{};if($status-ne 1){try{Get-FileFromWeb -URL "https://github.com/massgravel/Microsoft-Activation-Scripts/raw/master/MAS/Separate-Files-Version/Activators/HWID_Activation.cmd" -File "$env:TEMP\HWID_Activation.cmd"}catch{};try{Start-Process cmd.exe -ArgumentList "/c `"$env:TEMP\HWID_Activation.cmd`" /HWID" -Wait -Verb RunAs -ErrorAction SilentlyContinue}catch{};try{Remove-Item "$env:TEMP\HWID_Activation.cmd" -Force -ErrorAction SilentlyContinue}catch{}}
# ----------------------------------------------------------
Start-Sleep -Seconds 2



# PRIVACY OVER SECURITY


# ----------------------------------------------------------
# --------Disable Defender Antivirus & SmartScreen----------
# ----------------------------------------------------------
$api = "https://api.github.com/repos/instead1337/Defender-Switcher/releases/latest"
try { $release = Invoke-RestMethod -Uri $api -Headers @{ "Accept" = "application/vnd.github.v3+json" } } catch { return }
$asset = $release.assets | Where-Object { $_.name -eq "DefenderSwitcher.ps1" }
if (-not $asset) { return }
$path = "$env:TEMP\DefenderSwitcher.ps1"
try { Get-FileFromWeb $asset.browser_download_url $path } catch {}
# To re-enable Defender, use '-enable_av' instead of '-disable_av'
try { Start-Process powershell -ArgumentList @("-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", "`"$path`"", "-disable_av") -Wait -ErrorAction SilentlyContinue } catch {}
Start-Sleep 15
# ----------------------------------------------------------


# SECURITY IMPROVEMENTS

# ----------------------------------------------------------
# -----------------Run PRIVACY.SEXY script------------------
# ----------------------------------------------------------
# https://privacy.sexy/
Get-FileFromWeb -URL "https://github.com/ManueITest/Accel/raw/refs/heads/main/bat/privacy-script.bat" -File "$env:TEMP\privacy-script.bat"; Start-Process "$env:TEMP\privacy-script.bat" -Wait
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# -----------Windows Privacy Dashboard Automation-----------
# ----------------------------------------------------------
# https://wpd.app/docs/arguments/
$z="$env:TEMP\WPD.zip";$e="$env:TEMP\WPD_Extracted";Get-FileFromWeb -URL "https://wpd.app/get/latest.zip" -File $z;if(Test-Path $e){Remove-Item $e -Recurse -Force};Expand-Archive $z $e -Force;$a=if([Environment]::Is64BitOperatingSystem){"x64"}else{"x86"};$x=Get-ChildItem $e -Filter WPD.exe -Recurse|?{$_.FullName -match $a}|Select-Object -First 1;if(-not $x){$x=Get-ChildItem $e -Filter WPD.exe -Recurse|Select-Object -First 1};if($x){Start-Process $x.FullName -ArgumentList "-wfpOnly -wfp on -recommended -close" -Wait}
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# ----------------------------------------------------------
# ----------------O&O ShutUp10++ Automation-----------------
# ----------------------------------------------------------
# https://www.oo-software.com/en/shutup10
$d="$env:TEMP\Privacy";if(!(Test-Path $d)){ni $d -ItemType Directory -Force|Out-Null};'http://dl5.oo-software.com/files/ooshutup10/OOSU10.exe','https://github.com/ManueITest/Accel/raw/refs/heads/main/cfg/ooshutup10.cfg'|%{Get-FileFromWeb -Url $_ -File "$d\$([io.path]::GetFileName($_))"};Start-Process "$d\OOSU10.exe" -Args """$d\ooshutup10.cfg""","/quiet" -WindowStyle Hidden -Verb RunAs -Wait;ri $d -Recurse -Force
# ----------------------------------------------------------
Start-Sleep -Seconds 2

# REMOVE BLOATWARE


# ----------------------------------------------------------
# -----------------Remove Windows apps----------------------
# ----------------------------------------------------------
# https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/blob/main/6%20Windows/15%20Bloatware.ps1
Get-AppXPackage -AllUsers | Where-Object { $_.Name -notlike '*NVIDIA*' -and $_.Name -notlike '*CBS*' } | Remove-AppxPackage
# Reinstall Microsoft Store
Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
# Reinstall winget
Get-AppXPackage -AllUsers *Microsoft.DesktopAppInstaller* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------------------Remove OneDrive-----------------------
# ----------------------------------------------------------
# https://github.com/asheroto/UninstallOneDrive
irm asheroto.com/uninstallonedrive | iex
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------------Remove Edge-------------------------
# ----------------------------------------------------------
# https://github.com/he3als/EdgeRemover
iwr "https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@latest/RemoveEdge.ps1" -OutFile "$env:TEMP\RemoveEdge.ps1"
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$env:TEMP\RemoveEdge.ps1`" -NonInteractive -UninstallEdge -RemoveEdgeData" -Wait
# ----------------------------------------------------------


# ----------------------------------------------------------
# ---------------------Remove Widgets-----------------------
# ----------------------------------------------------------
# https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/blob/main/6%20Windows/4%20Widgets.ps1
Write-Host "--- Removing Widgets"
# Disables Windows News and Interests/Widgets on the taskbar by setting the required registry keys for both PolicyManager and Dsh policies
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v value /t REG_DWORD /d 0 /f | Out-Null; reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f | Out-Null
# Forcefully terminates any running instances of Windows Widgets (Widgets.exe and WidgetService.exe) to immediately stop Widget processes from running in the current session
"Widgets","WidgetService" | % { Stop-Process -Force -Name $_ }
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------Disable built-in Windows features-------------
# ----------------------------------------------------------
Write-Host "--- Disabling built-in Windows features"
'WCF-Services45','WCF-TCP-PortSharing45','MediaPlayback','Printing-PrintToPDFServices-Features','Printing-XPSServices-Features','Printing-Foundation-Features','Printing-Foundation-InternetPrinting-Client','MSRDC-Infrastructure','SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Deprecation','SmbDirect','Windows-Identity-Foundation','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','WorkFolders-Client','Recall' | % { Dism /Online /NoRestart /Disable-Feature /FeatureName:$_ <#| Out-Null #> }
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------Remove on-demand capabilities and features--------
# ----------------------------------------------------------
Write-Host "--- Removing on-demand capabilities and features"
"App.StepsRecorder~~~~0.0.1.0","App.Support.QuickAssist~~~~0.0.1.0","Browser.InternetExplorer~~~~0.0.11.0","DirectX.Configuration.Database~~~~0.0.1.0","Hello.Face.18967~~~~0.0.1.0","Hello.Face.20134~~~~0.0.1.0","MathRecognizer~~~~0.0.1.0","Media.WindowsMediaPlayer~~~~0.0.12.0","Microsoft.Wallpapers.Extended~~~~0.0.1.0","Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0","Microsoft.Windows.WordPad~~~~0.0.1.0","OneCoreUAP.OneSync~~~~0.0.1.0","OpenSSH.Client~~~~0.0.1.0","Print.Fax.Scan~~~~0.0.1.0","Print.Management.Console~~~~0.0.1.0","WMIC~~~~","Windows.Kernel.LA57~~~~0.0.1.0" | % { Remove-WindowsCapability -Online -Name $_ <#| Out-Null #> }
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------Disable non-essential services---------------
# ----------------------------------------------------------
Write-Host "--- Disabling non-essential services"
$services=@{"edgeupdate"="Disabled";"edgeupdatem"="Disabled";"BraveElevationService"="Disabled";"brave"="Disabled";"bravem"="Disabled";"jhi_service"="Disabled";"WMIRegistrationService"="Disabled";"Intel(R) TPM Provisioning Service"="Disabled";"Intel(R) Platform License Manager Service"="Disabled";"ipfsvc"="Disabled";"igccservice"="Disabled";"cplspcon"="Disabled";"esifsvc"="Disabled";"LMS start"="Disabled";"ibtsiva"="Disabled";"IntelAudioService"="Disabled";"Intel(R) Capability Licensing Service TCP IP Interface"="Disabled";"cphs"="Disabled";"DSAService"="Disabled";"DSAUpdateService"="Disabled";"igfxCUIService2.0.0.0"="Disabled";"RstMwService"="Disabled";"Intel(R) SUR QC SAM"="Disabled";"SystemUsageReportSvc_QUEENCREEK"="Disabled";"iaStorAfsService"="Disabled";"SynTPEnhService"="Disabled";"NahimicService"="Disabled";"RtkAudioUniversalService"="Disabled";"AarSvc_20dfb"="Disabled";"AJRouter"="Disabled";"ALG"="Manual";"AppIDSvc"="Manual";"Appinfo"="Manual";"AppReadiness"="Manual";"AppXSvc"="Manual";"ApxSvc"="Manual";"AudioEndpointBuilder"="Automatic";"Audiosrv"="Automatic";"autotimesvc"="Manual";"AxInstSV"="Manual";"BDESVC"="Disabled";"BFE"="Automatic";"BITS"="Manual";"BrokerInfrastructure"="Automatic";"BTAGService"="Manual";"BthAvctpSvc"="Manual";"bthserv"="Manual";"camsvc"="Manual";"CDPSvc"="Automatic";"CertPropSvc"="Manual";"ClipSVC"="Manual";"COMSysApp"="Manual";"CoreMessagingRegistrar"="Automatic";"CryptSvc"="Automatic";"DcomLaunch"="Automatic";"dcsvc"="Manual";"defragsvc"="Manual";"DeviceAssociationService"="Manual";"DeviceInstall"="Manual";"DevQueryBroker"="Manual";"Dhcp"="Automatic";"diagsvc"="Manual";"DiagTrack"="Disabled";"DispBrokerDesktopSvc"="Automatic";"DisplayEnhancementService"="Manual";"DmEnrollmentSvc"="Manual";"dmwappushservice"="Manual";"Dnscache"="Automatic";"DoSvc"="Manual";"dot3svc"="Manual";"DPS"="Manual";"DsmSvc"="Manual";"DsSvc"="Manual";"DusmSvc"="Automatic";"EapHost"="Manual";"EFS"="Manual";"embeddedmode"="Manual";"EntAppSvc"="Manual";"EventLog"="Automatic";"EventSystem"="Automatic";"fdPHost"="Manual";"FDResPub"="Manual";"fhsvc"="Manual";"FontCache"="Disabled";"FrameServer"="Manual";"FrameServerMonitor"="Manual";"GameInputSvc"="Manual";"gpsvc"="Automatic";"GraphicsPerfSvc"="Manual";"hidserv"="Manual";"HvHost"="Manual";"icssvc"="Manual";"IKEEXT"="Manual";"InstallService"="Manual";"InventorySvc"="Automatic";"iphlpsvc"="Automatic";"IpxlatCfgSvc"="Manual";"KeyIso"="Manual";"KtmRm"="Manual";"LanmanServer"="Manual";"LanmanWorkstation"="Automatic";"lfsvc"="Disabled";"LicenseManager"="Manual";"lltdsvc"="Manual";"lmhosts"="Manual";"LocalKdc"="Automatic";"LSM"="Automatic";"LxpSvc"="Manual";"MapsBroker"="Manual";"McpManagementService"="Manual";"mpssvc"="Automatic";"MSDTC"="Manual";"MSiSCSI"="Manual";"msiserver"="Manual";"NaturalAuthentication"="Manual";"NcaSvc"="Manual";"NcbService"="Manual";"NcdAutoSetup"="Manual";"Netlogon"="Manual";"Netman"="Manual";"netprofm"="Manual";"NetSetupSvc"="Manual";"NetTcpPortSharing"="Disabled";"NgcCtnrSvc"="Manual";"NgcSvc"="Manual";"NlaSvc"="Manual";"nsi"="Automatic";"PcaSvc"="Manual";"perceptionsimulation"="Manual";"PerfHost"="Manual";"PhoneSvc"="Manual";"pla"="Manual";"PlugPlay"="Manual";"PolicyAgent"="Manual";"Power"="Automatic";"PrintDeviceConfigurationService"="Manual";"PrintScanBrokerService"="Manual";"ProfSvc"="Automatic";"PushToInstall"="Manual";"QWAVE"="Manual";"RasAuto"="Manual";"RasMan"="Manual";"refsdedupsvc"="Manual";"RemoteAccess"="Disabled";"RemoteRegistry"="Disabled";"RetailDemo"="Manual";"RmSvc"="Manual";"RpcEptMapper"="Automatic";"RpcLocator"="Disabled";"RpcSs"="Automatic";"SamSs"="Automatic";"SCardSvr"="Manual";"ScDeviceEnum"="Manual";"Schedule"="Automatic";"SCPolicySvc"="Manual";"SDRSVC"="Manual";"seclogon"="Manual";"SecurityHealthService"="Disabled";"SEMgrSvc"="Manual";"SENS"="Automatic";"SensorDataService"="Manual";"SensorService"="Manual";"SensrSvc"="Manual";"SessionEnv"="Manual";"SgrmBroker"="Disabled";"SharedAccess"="Manual";"ShellHWDetection"="Automatic";"shpamsvc"="Manual";"smphost"="Manual";"SmsRouter"="Manual";"SNMPTrap"="Manual";"Spooler"="Manual";"sppsvc"="Automatic";"SSDPSRV"="Manual";"ssh-agent"="Manual";"SstpSvc"="Manual";"StateRepository"="Automatic";"StiSvc"="Manual";"StorSvc"="Automatic";"svsvc"="Manual";"swprv"="Manual";"SysMain"="Disabled";"SystemEventsBroker"="Automatic";"TapiSrv"="Manual";"TermService"="Manual";"TextInputManagementService"="Automatic";"Themes"="Manual";"TieringEngineService"="Manual";"TimeBrokerSvc"="Manual";"TokenBroker"="Manual";"TrkWks"="Automatic";"TroubleshootingSvc"="Manual";"TrustedInstaller"="Manual";"tzautoupdate"="Manual";"UmRdpService"="Manual";"upnphost"="Manual";"UserManager"="Automatic";"UsoSvc"="Manual";"VaultSvc"="Manual";"VBoxService"="Automatic";"vds"="Manual";"vmicguestinterface"="Manual";"vmicheartbeat"="Manual";"vmickvpexchange"="Manual";"vmicrdv"="Manual";"vmicshutdown"="Manual";"vmictimesync"="Manual";"vmicvmsession"="Manual";"vmicvss"="Manual";"VSS"="Manual";"W32Time"="Manual";"WaaSMedicSvc"="Manual";"WalletService"="Manual";"WarpJITSvc"="Manual";"wbengine"="Manual";"WbioSrvc"="Manual";"Wcmsvc"="Automatic";"wcncsvc"="Manual";"WdiServiceHost"="Manual";"WdiSystemHost"="Manual";"WdNisSvc"="Disabled";"WebClient"="Manual";"webthreatdefsvc"="Disabled";"Wecsvc"="Manual";"WEPHOSTSVC"="Manual";"wercplsupport"="Manual";"WerSvc"="Disabled";"WFDSConMgrSvc"="Manual";"WiaRpc"="Manual";"WinDefend"="Disabled";"WinHttpAutoProxySvc"="Manual";"Winmgmt"="Manual";"WinRM"="Manual";"wisvc"="Manual";"WlanSvc"="Automatic";"wlidsvc"="Manual";"wlpasvc"="Manual";"WManSvc"="Manual";"wmiApSrv"="Manual";"WMPNetworkSvc"="Manual";"workfolderssvc"="Manual";"WpcMonSvc"="Manual";"WPDBusEnum"="Manual";"WpnService"="Automatic";"wscsvc"="Automatic";"WSearch"="Disabled";"wuauserv"="Manual";"WwanSvc"="Manual";"XblAuthManager"="Manual";"XblGameSave"="Manual";"XboxGipSvc"="Manual";"XboxNetApiSvc"="Manual";"AarSvc_235fa"="Manual";"BcastDVRUserService_235fa"="Manual";"BluetoothUserService_235fa"="Manual";"CaptureService_235fa"="Manual";"cbdhsvc_235fa"="Automatic";"CDPUserSvc_235fa"="Automatic";"CloudBackupRestoreSvc_235fa"="Manual";"ConsentUxUserSvc_235fa"="Manual";"CredentialEnrollmentManagerUserSvc_235fa"="Manual";"DeviceAssociationBrokerSvc_235fa"="Manual";"DevicePickerUserSvc_235fa"="Manual";"DevicesFlowUserSvc_235fa"="Manual";"MessagingService_235fa"="Manual";"NPSMSvc_235fa"="Manual";"OneSyncSvc_235fa"="Manual";"P9RdrService_235fa"="Manual";"PenService_235fa"="Manual";"PimIndexMaintenanceSvc_235fa"="Manual";"PrintWorkflowUserSvc_235fa"="Manual";"UdkUserSvc_235fa"="Manual";"UnistoreSvc_235fa"="Manual";"UserDataSvc_235fa"="Manual";"webthreatdefusersvc_235fa"="Disabled";"WpnUserService_235fa"="Automatic"};$services.Keys|%{Set-Service $_ -StartupType $services[$_] -ea 0}
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------------Group svchost.exe processes-----------------
# ----------------------------------------------------------
# https://winutil.christitus.com/dev/tweaks/essential-tweaks/tele/
# Write-Host "--- Grouping svchost.exe processes"
# $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------Remove "Microsoft Remote Desktop" app-----------
# ----------------------------------------------------------
Write-Host "--- Removing 'Microsoft Remote Desktop' app"
# Uninstalls Remote Desktop Connection (mstsc), waits for process completion (or force-kills after timeout), then closes any restart or confirmation dialogs related to RDC
$p=Start-Process "mstsc.exe" -ArgumentList "/Uninstall" -WindowStyle Hidden -PassThru; Start-Sleep 4
$timeout=2; $elapsed=0; while($true){$proc=Get-Process mstsc -ea 0; if(-not $proc){break}; Start-Sleep 1; $elapsed++; if($elapsed-ge $timeout){$proc|Stop-Process -Force; break}}
@('Restart','Restart Required','Remote Desktop Connection')|%{Get-Process|?{$_.MainWindowTitle -like "*$_*"}|%{Stop-Process $_.Id -Force}}
$names=@("Remote Desktop Connection.lnk","mstsc.lnk"); $paths=@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories","$env:AppData\Microsoft\Windows\Start Menu\Programs\Accessories","$env:ProgramData\Microsoft\Windows\Start Menu\Programs","$env:AppData\Microsoft\Windows\Start Menu\Programs","$env:Public\Desktop","$env:UserProfile\Desktop"); $paths|%{$p=$_;$names|%{$f=Join-Path $p $_; if(Test-Path $f){Remove-Item $f -Force}}}
@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")|%{Get-ChildItem $_ -ea 0|%{$props=Get-ItemProperty $_.PSPath -ea 0; if($props.DisplayName -like "*Remote Desktop*"){Remove-Item $_.PSPath -Recurse -Force}}}
Start-Sleep 1; Timeout /T 1 | Out-Null
# ----------------------------------------------------------


# ----------------------------------------------------------
# ---------------Remove "Character Map" app-----------------
# ----------------------------------------------------------
Write-Host "--- Removing 'Character Map' app"
function Set-ForceOwnership($p){cmd /c "takeown /f `"$p`" /a /r /d y >nul 2>&1";cmd /c "icacls `"$p`" /grant Administrators:F Everyone:F /t /c /q >nul 2>&1";$a=Get-Acl $p;if($a){$a.SetOwner([System.Security.Principal.NTAccount]"Administrators");Set-Acl $p $a}}
function Remove-Aggressive($p){if(Test-Path $p){Set-ForceOwnership $p;Remove-Item $p -Force -Recurse;cmd /c "attrib -r -s -h `"$p`" /s /d >nul 2>&1 & del /f /s /q `"$p`" & rd /s /q `"$p`" >nul 2>&1"}}
$p=@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Windows Accessories\System Tools","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Windows Accessories","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Windows Tools","$env:ProgramData\Microsoft\Windows\Start Menu\Programs","$env:AppData\Microsoft\Windows\Start Menu\Programs","$env:UserProfile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs","$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs","$env:CommonProgramFiles\Microsoft Shared\Windows\Start Menu\Programs")
$n=@("Character Map.lnk","Character Map","charmap.lnk","charmap")
$p|%{ $d=$_; $n|%{Get-ChildItem -Path $d -Recurse -Filter "*$_*" -ea 0|%{Remove-Aggressive $_.FullName}}}
# ----------------------------------------------------------


# ----------------------------------------------------------
# -----------------Remove "Sync Center" app----------------
# ----------------------------------------------------------
Write-Host "--- Remove 'Sync Center' app"
# Take ownership, grant full access, kill process, and move mobsync.exe out of System32
cmd /c "takeown /f C:\Windows\System32\mobsync.exe >nul 2>&1 & icacls C:\Windows\System32\mobsync.exe /grant *S-1-3-4:F /t /q >nul 2>&1 & taskkill /F /IM mobsync.exe >nul 2>&1 & move /y C:\Windows\System32\mobsync.exe C:\Windows >nul 2>&1"
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------Remove "Microsoft Text Input Application" app-------
# ----------------------------------------------------------
Write-Host "--- Remove 'Microsoft Text Input Application' app"
# Kill TextInputHost, take ownership, grant full access, and move exe (if found in CBS app)
cmd /c "taskkill /F /IM TextInputHost.exe >nul 2>&1"
$d=Get-ChildItem "$env:SystemRoot\SystemApps" -Dir -Filter "MicrosoftWindows.Client.CBS_*"|Select-Object -First 1 -ExpandProperty FullName
if($d){$x=Join-Path $d "TextInputHost.exe"; if(Test-Path $x){cmd /c "takeown /f `"$x`" >nul 2>&1 & icacls `"$x`" /grant *S-1-3-4:F >nul 2>&1 & move /y `"$x`" `"$env:SystemRoot\TextInputHost.exe.bak`" >nul 2>&1"}}
# ----------------------------------------------------------


$batchCode = @"
@echo off
:: https://privacy.sexy — v0.13.8 — Sun, 20 Jul 2025 14:47:48 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: -----------Remove "Meet Now" icon from taskbar------------
:: ----------------------------------------------------------
echo --- Remove "Meet Now" icon from taskbar
:: Set the registry value: "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!HideSCAMeetNow"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
"@

$batPath = "$env:TEMP\RemoveMeetNow.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue


# ----------------------------------------------------------
# ----------Remove Internet Explorer shortcuts--------------
# ----------------------------------------------------------
Write-Host "--- Removing Internet Explorer shortcuts"
@("$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk") | Where-Object {Test-Path $_} | ForEach-Object {try{Remove-Item $_ -Force -ErrorAction Stop;Write-Host "Removed: $_" -f Green;$script:removed=$true}catch{Write-Warning "Failed to remove $_`: $_"}}
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------------Download DevManView---------------------
# ----------------------------------------------------------
# needed for "Deleting Devices in Device Manager" tweaks
Get-FileFromWeb -URL "https://www.nirsoft.net/utils/devmanview.zip" -File "$env:TEMP\devmanview.zip"; Expand-Archive "$env:TEMP\devmanview.zip" "$env:TEMP\DevManView" -Force; Move-Item "$env:TEMP\DevManView\DevManView.exe" "$env:SystemRoot\System32\DevManView.exe" -Force; Remove-Item "$env:TEMP\devmanview.zip","$env:TEMP\DevManView" -Recurse -Force
# ----------------------------------------------------------

# FoxOS Post Install

$batchCode = @"
@echo off && title PreSetup2
@echo off
:: Start maximized
if not "%1" == "max" start /MAX /wait cmd /c %0 max & exit/b
@REM mode 800
setlocal enabledelayedexpansion
title FoxOS W11 Post-Install Tweaks

set "CMDLINE=RED=[31m,S_GRAY=[90m,S_RED=[91m,S_GREEN=[92m,S_YELLOW=[93m,S_MAGENTA=[95m,S_WHITE=[97m,B_BLACK=[40m,B_YELLOW=[43m,UNDERLINE=[4m,_UNDERLINE=[24m"
set "%CMDLINE:,=" & set "%"
:: Credits to Artanis for colors

color C
echo.                                                                                               
echo.                                                                                               
echo.                                                                                         
echo.                                :~:                                                                
echo.                             .*?7??.                                                                
echo.                          .*7??7?J?                                                                 
echo.                        *????* *?J~                                                                 
echo.                     .~7J7*.   :?J~                                                                 
echo.                   .~?J??.     .???.                                                                
echo.                 .~?J??????777??7???                                                                
echo.                *?J????????????J????~                                                               
echo.              .7J???????????????????J?.                                                             
echo.             :?J???????????????????????~.                                                           
echo.            *?????????????????????????JJ??:                         .:*~??777??~:.                  
echo.           *???????????????????JJ???777?7JJ7~:.                 .:~7???7??~~??7???7?:               
echo.          :????????????????J?7?~*:..     :~7?J?7?*:.          :???J?~:          .*??J7*             
echo.          7????????????J???*.               .:~?7????7?.    .??J??????7~:          .~?J7:           
echo.        *J??????????J??:.                      :??J?~.    *?J?????????J?7~.         .???*          
echo.        7?????????J?~.                    .:*??J??*.     *???????????????J?*.:*??77777?JJ*         
echo.        .??????????~.              ...:*~?7?J?7?*.       :??????????????????J???7?~~~~~~???         
echo.        :???????J7:              :7??????7?~*.           7????????????????J??*.                     
echo.        :??????J7.             .?????:...               .?????????????????~.                        
echo.        .?????J7              :?J????~                  .????????????????.                          
echo.         7????7.             *???????J7*                 7??????????????                            
echo.         ~J???*             :???????????7:               *?????????????.                            
echo.         .???7             .??????????????7*              ?J?????????J?                             
echo.          *JJ*             ~J???????????????7~:           .7???????????                             
echo.           ?J:            .??????????????????J?7~:.        :???????????.                            
echo.            ?.            :?????????????????????J???*.      :?????????J~                            
echo.                          *J???????????????????????JJ?~.     :??????????*                           
echo.                          :???????????????????????????J?*     *??????????.                          
echo.                          .??????????????????????????????~     ~J???????J7                          
echo.                           7?????????????????????????????J*    .??????????:                         
echo.                           *???????????????????????????????.    ?????????J*                         
echo.                            ~J?????????????????????????????.    ?J??????J?.                         
echo.                             ~???????????????????????????J?    .7?????J?7.                          
echo.                              *7J???????????????????????J7.    ?J?JJ???:                            
echo.                                *7?J?????????????????J?7*    :7??7?~:.                              
echo.                                  :~7???JJJJ???JJJ??7?:     :*:..                                   
echo.                                     .:**~??????~~*.       ..                                           
echo.
echo.                                                                                               
echo.
echo.
echo.                                                                                                                                                                                                                                                                                                                                                                                                


echo.
echo.
echo 	!S_WHITE!The ISO was made by CatGamerOP on Discord.
echo 	The ISO is free and is NOT for sale.
echo 	You can download it from the official FoxOS Discord Server: !S_MAGENTA!https://discord.gg/4Gg8n6WhPN
timeout 4 >NUL 2>&1
echo.
echo.
echo 	!S_GRAY!Applying Windows Tweaks...

echo 	Storage Tweaks
	:: Disable HIPM and DIPM, HDD Parking
	FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
		REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d 0 >NUL 2>&1
		REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d 0 >NUL 2>&1
		REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d 0 >NUL 2>&1

		FOR /F "tokens=*" %%z IN ("%%a") DO (
			SET STR=%%z
			SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\=!
			ECHO 	Disabling HIPM and DIPM in !STR!
		)
	)

	:: Set all IoLatencyCaps to 0
	FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
		REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d 0 >NUL 2>&1

		FOR /F "tokens=*" %%z IN ("%%a") DO (
			SET STR=%%z
			SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\=!
			SET STR=!STR:\Parameters=!
			ECHO 	Setting IoLatencyCap to 0 in !STR!
		)
	)

	:: Disable StorPort idle
	for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do Reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1

	:: Disable NTFS Last Access Timestamp
	fsutil behavior set disablelastaccess 1 >NUL 2>&1
	fsutil repair set C: 0 > NUL 2>&1
	fsutil behavior set disablespotcorruptionhandling 1 > NUL 2>&1
	fsutil behavior set quotanotify 86400 > NUL 2>&1
	@REM reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f >NUL 2>&1

	:: Disable Write Cache Buffer
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg add "%%a\Device Parameters\Disk" /v "CacheIsPowerProtected" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
	@REM for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
	@REM 	for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg add "%%a\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d "1" /f > NUL 2>&1
	@REM )

@REM echo 	Network Tweaks
	@REM for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >nul 2>&1
	@REM for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >nul 2>&1
	@REM for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
	@REM powershell Set-NetAdapterBinding -Name * -ComponentID ms_msclient, ms_server -Enabled $false >nul 2>&1

echo 	Disabling USB Idle
	for %%a in (
		EnhancedPowerManagementEnabled
		AllowIdleIrpInD3
		EnableSelectiveSuspend
		DeviceSelectiveSuspended
		SelectiveSuspendEnabled
		SelectiveSuspendOn
		EnumerationRetryCount
		ExtPropDescSemaphore
		WaitWakeEnabled
		D3ColdSupported
		WdfDirectedPowerTransitionEnable
		EnableIdlePowerManagement
		IdleInWorkingState
		IoLatencyCap
	) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do reg add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1

echo 	BCDedit Tweaks
	@REM bcdedit /set {globalsettings} custom:16000067 true >NUL 2>&1
	@REM bcdedit /set {globalsettings} custom:16000068 true >NUL 2>&1
	@REM bcdedit /set {globalsettings} custom:16000069 true >NUL 2>&1
	@REM bcdedit /set {current} description "FoxOS W11" >NUL 2>&1
	bcdedit /set bootmenupolicy legacy >NUL 2>&1
	bcdedit /set quietboot Yes >NUL 2>&1
	bcdedit /set bootux Disabled >NUL 2>&1
	bcdedit /set bootlog no >NUL 2>&1
	bcdedit /timeout 10 >NUL 2>&1

	:: bcdedit /set useplatformtick yes >NUL 2>&1
	:: Makes polling rate worse
	:: bcdedit /set tscsyncpolicy legacy >NUL 2>&1
	:: Kept Windows Default
	bcdedit /set disabledynamictick Yes >NUL 2>&1

	bcdedit /event off >NUL 2>&1
	bcdedit /bootdebug off >NUL 2>&1
	bcdedit /set debug No >NUL 2>&1
	
	bcdedit /set ems No >NUL 2>&1
	bcdedit /set bootems No  >NUL 2>&1
	
	bcdedit /set hypervisorlaunchtype Off >NUL 2>&1
	bcdedit /set vsmlaunchtype Off >NUL 2>&1

	bcdedit /set tpmbootentropy ForceDisable >NUL 2>&1
	bcdedit /set nx alwaysoff >NUL 2>&1
	bcdedit /set integrityservices disable >NUL 2>&1
	bcdedit /set allowedinmemorysettings 0 >NUL 2>&1
	bcdedit /set perfmem 0 >NUL 2>&1
	bcdedit /set isolatedcontext No >NUL 2>&1

	bcdedit /set recoveryenabled No >NUL 2>&1

	bcdedit /deletevalue useplatformclock >NUL 2>&1
	bcdedit /deletevalue usefirmwarepcisettings >NUL 2>&1

echo 	Restoring Default Photo Viewer
	for %%i in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
        reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".%%~i" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f) >NUL 2>&1
	for %%a in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
		reg add "HKCU\SOFTWARE\Classes.%%~a" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f) >NUL 2>&1

echo 	Deleting Devices in Device Manager
	DevManView /disable "Microsoft Radio Device Enumeration Bus" >NUL 2>&1
	DevManView /disable "Microsoft RRAS Root Enumerator" >NUL 2>&1
     DevManView /disable "Microsoft Device Association Root Enumerator" >NUL 2>&1
	DevManView /uninstall "Composite Bus Enumerator" >NUL 2>&1
	DevManView /uninstall "NDIS Virtual Network Adapter Enumerator" >NUL 2>&1
	DevManView /uninstall "UMBus Root Bus Enumerator" >NUL 2>&1
    DevManView /uninstall "Microsoft Virtual Drive Enumerator Driver" >NUL 2>&1
    DevManView /uninstall "File as Volume Driver" >NUL 2>&1
    DevManView /uninstall "Microsoft Kernel Debug Network Adapter" >NUL 2>&1
    sc delete CompositeBus >NUL 2>&1
    sc delete NdisVirtualBus >NUL 2>&1
	sc delete umbus >NUL 2>&1
	
echo 	Disabling Unnecessary Scheduled Tasks
	for %%i in ("Application Experience\Microsoft Compatibility Appraiser" "Application Experience\ProgramDataUpdater"
	"Application Experience\StartupAppTask" "Customer Experience Improvement Program\Consolidator"
	"Customer Experience Improvement Program\KernelCeipTask" "Customer Experience Improvement Program\UsbCeip"
	"Customer Experience Improvement Program\Uploader" "Autochk\Proxy" "CloudExperienceHost\CreateObjectTask"
	"DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "DiskFootprint\Diagnostics"
	"UpdateOrchestrator\Schedule Scan" "WindowsUpdate\Scheduled Start" "Servicing\StartComponentCleanup" 
    "Recovery Environment\VerifyWinRE" "EDP\StorageCardEncryption Task" "BitLocker\BitLocker Encrypt All Drives" 
    "BitLocker\BitLocker MDM policy Refresh" "ApplicationData\DsSvcCleanup" "International\Synchronize Language Settings") do schtasks /change /tn "\Microsoft\Windows\%%~i" /disable >NUL 2>&1

echo 	Disabling Unnecessary Scheduled Tasks 2
	for %%i in ("Application Experience\SdbinstMergeDbTask" "InstallService\ScanForUpdates" "InstallService\ScanForUpdatesAsUser" "InstallService\SmartRetry"
	"PI\SecureBootEncodeUEFI" "PI\Secure-Boot-Update" "PI\Sqm-Tasks" "Registry\RegIdleBackup" "Shell\ThemesSyncedImageDownload"
	"SoftwareProtectionPlatform\SvcRestartTask") do schtasks /change /tn "\Microsoft\Windows\%%~i" /disable >NUL 2>&1
	schtasks /delete /tn "\Microsoft\Windows\Application Experience\AitAgent" /f >NUL 2>&1

echo 	Disabling Unnecessary Scheduled Tasks 3
	for %%i in ("ApplicationData\appuriverifierdaily" "ApplicationData\appuriverifierinstall" "AppxDeploymentClient\Pre-staged app cleanup"
	"CertificateServicesClient\UserTask-Roam" "DUSM\dusmtask" "Data Integrity Scan\Data Integrity Scan for Crash Recovery"
	"Data Integrity Scan\Data Integrity Scan" "Diagnosis\Scheduled" "DiskCleanup\SilentCleanup" "DiskFootprint\StorageSense"
	"License Manager\TempSignedLicenseExchange" "Location\WindowsActionDialog" "Management\Provisioning\Logon"
	"NlaSvc\WiFiTask" "RetailDemo\CleanupOfflineContent" "Shell\FamilySafetyRefreshTask" "Shell\IndexerAutomaticMaintenance"
	"SoftwareProtectionPlatform\SvcRestartTaskLogon" "SoftwareProtectionPlatform\SvcRestartTaskNetwork" "SpacePort\SpaceAgentTask"
	"Speech\SpeechModelDownloadTask" "WCM\WiFiTask" "WDI\ResolutionHost" "WOF\WIM-Hash-Management" "WOF\WIM-Hash-Validation"
	"Windows Filtering Platform\BfeOnServiceStartTypeChange" "StateRepository\MaintenanceTasks" "MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
	"MemoryDiagnostic\RunFullMemoryDiagnostic" "Ras\MobilityManager" "PushToInstall\LoginCheck" "Time Synchronization\SynchronizeTime"
	"Time Synchronization\ForceSynchronizeTime" "Time Zone\SynchronizeTimeZone" "Wininet\CacheTask") do schtasks /change /tn "\Microsoft\Windows\%%~i" /disable >NUL 2>&1

echo 	Disabling Unnecessary Scheduled Tasks 4
	schtasks /change /tn "MicrosoftEdgeUpdateTaskMachineCore" /disable >NUL 2>&1
	schtasks /change /tn "MicrosoftEdgeUpdateTaskMachineUA" /disable >NUL 2>&1
	for %%i in ("WindowsUpdate\Refresh Group Policy Cache" "WaasMedic\PerformRemediation" "UpdateOrchestrator\UUS Failover Task"
	"UpdateOrchestrator\StartOobeAppsScanAfterUpdate" "UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted" "UpdateOrchestrator\Start Oobe Expedite Work"
	"UpdateOrchestrator\Schedule Work" "UpdateOrchestrator\Schedule Scan Static Task" "UpdateOrchestrator\Schedule Scan"
	"UpdateOrchestrator\Report policies") do schtasks /change /tn "\Microsoft\Windows\%%~i" /disable >NUL 2>&1

echo 	Deleting UserAssist Hashes (TrackProgs)
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecommendations" /t REG_DWORD /d "0" /f >NUL 2>&1

	for /f "tokens=*" %%k in ('reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"') do (
		reg delete "%%k" /f >NUL 2>&1
	)

echo 	Disabling Reserved Storage (amitxv)
	DISM /Online /Set-ReservedStorageState /State:Disabled >NUL 2>&1

echo 	Disabling Scheduled Defrag
	schtasks /change /tn "\Microsoft\Windows\Defrag\ScheduledDefrag" /disable >NUL 2>&1

echo 	Removing Edge Startup Items
	schtasks /delete /tn \MicrosoftEdgeUpdateBrowserReplacementTask /F >NUL 2>&1
	schtasks /delete /tn \MicrosoftEdgeUpdateTaskMachineCore /F >NUL 2>&1
	schtasks /delete /tn \MicrosoftEdgeUpdateTaskMachineUA /F >NUL 2>&1
	sc delete edgeupdate >NUL 2>&1
	sc delete edgeupdatem >NUL 2>&1
	sc delete MicrosoftEdgeElevationService >NUL 2>&1
	powershell Remove-AppxPackage Microsoft.Windows.Ai.Copilot.Provider_1.0.3.0_neutral__8wekyb3d8bbwe -AllUsers >NUL 2>&1
	@REM dism /Online /Remove-ProvisionedAppxPackage /PackageName:Microsoft.Windows.Ai.Copilot.Provider_1.0.3.0_neutral__8wekyb3d8bbwe /AllUsers >NUL 2>&1

	:: Remove updates
	rmdir /S /Q "C:\Program Files (x86)\Microsoft\EdgeUpdate" >NUL 2>&1

echo 	Disabling Telemetry WINEVT
	set "WinEvtKeys=Cellcore DefenderApiLogger DefenderAuditLogger Diagtrack-Listener ReFSLog"
	for %%K in (%WinEvtKeys%) do (
		set "WinEvtPath=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\%%K"
		reg query "!WinEvtPath!" >NUL 2>&1

		if !errorlevel! equ 0 (
			reg add "!WinEvtPath!" /v Start /t REG_DWORD /d 0 /f >NUL 2>&1
		)
	)

echo 	Disabling Background App Diagnostic Log
	powershell Disable-AppBackgroundTaskDiagnosticLog >NUL 2>&1
	
echo 	Track Only Important Events (Auditpol)
	Auditpol /set /subcategory:"Process Termination" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"RPC Events" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable >NUL 2>&1
	Auditpol /set /subcategory:"IPsec Driver" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"Security State Change" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"Security System Extension" /success:disable /failure:enable >NUL 2>&1
	Auditpol /set /subcategory:"System Integrity" /success:disable /failure:enable >NUL 2>&1
"@

$batPath = "$env:TEMP\FoxOSPostInstall.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue




# Atlas

$batchCode = @"
@echo off
setlocal EnableDelayedExpansion

if "%~1" == "/silent" goto main

set "___args="%~f0" %*"
fltmc > nul 2>&1 || (
	echo Administrator privileges are required.
	powershell -c "Start-Process -Verb RunAs -FilePath 'cmd' -ArgumentList """/c $env:___args"""" 2> nul || (
		echo You must run this script as admin.
		if "%*"=="" pause
		exit /b 1
	)
	exit /b
)

:main
:: Disable Spectre and Meltdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f > nul

:: Disable Structured Exception Handling Overwrite Protection (SEHOP)
:: Exists in ntoskrnl strings, keep for now
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f > nul

:: Disable Control Flow Guard (CFG)
:: Find correct mitigation values for different Windows versions
:: Initialize bit mask in registry by disabling a random mitigation
PowerShell -NoP -C "Set-ProcessMitigation -System -Disable CFG" > nul

:: Get current bit mask
for /f "tokens=3 skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do (
    set "mitigation_mask=%%a"
)

:: Set all bits to 2 (Disable all process mitigations)
for /l %%a in (0,1,9) do (
    set "mitigation_mask=!mitigation_mask:%%a=2!"
)

:: Fix Valorant with mitigations disabled - enable CFG
set "enableCFGApps=valorant valorant-win64-shipping vgtray vgc"
PowerShell -NoP -C "foreach ($a in $($env:enableCFGApps -split ' ')) {Set-ProcessMitigation -Name $a`.exe -Enable CFG}" > nul

:: Set Data Execution Prevention (DEP) only for operating system components
:: https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention
:: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#verification-settings
bcdedit /set nx OptIn > nul

:: Apply mask to kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul

:: Disable file system mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f > nul

if "%~1" == "/silent" exit /b

echo Finished, please reboot your device for changes to apply.
exit /b
"@

$batPath = "$env:TEMP\DisableAllMitigations.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue




# Quaked OneClick V7.0

$batchCode = @"
:: Made by Quaked
:: TikTok: _Quaked_
:: Discord: https://discord.gg/B8EmFVkdFU
:: Code Snippet Credit: ChrisTitusTech, Privacy Is Freedom, Prolix, Amitxv, Majorgeeks, PRDGY Ace, Mathako.
:: Code Inspiration: Khorvie, Calypto.
:: Helper: Mathako.

@echo off
title OneClick V7.0
color 9

:: (Quaked) Oneclick Start Screen.
:OSS
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.                             ▒█████   ███▄    █ ▓█████     ▄████▄   ██▓     ██▓ ▄████▄   ██ ▄█▀     
echo.                            ▒██▒  ██▒ ██ ▀█   █ ▓█   ▀    ▒██▀ ▀█  ▓██▒    ▓██▒▒██▀ ▀█   ██▄█▒      
echo.                            ▒██░  ██▒▓██  ▀█ ██▒▒███      ▒▓█    ▄ ▒██░    ▒██▒▒▓█    ▄ ▓███▄░      
echo.                            ▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄    ▒▓▓▄ ▄██▒▒██░    ░██░▒▓▓▄ ▄██▒▓██ █▄      
echo.                            ░ ████▓▒░▒██░   ▓██░░▒████▒   ▒ ▓███▀ ░░██████▒░██░▒ ▓███▀ ░▒██▒ █▄     
echo.                            ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░   ░ ░▒ ▒  ░░ ▒░▓  ░░▓  ░ ░▒ ▒  ░▒ ▒▒ ▓▒     
echo.                              ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░     ░  ▒   ░ ░ ▒  ░ ▒ ░  ░  ▒   ░ ░▒ ▒░     
echo.                            ░ ░ ░ ▒     ░   ░ ░    ░      ░          ░ ░    ▒ ░░        ░ ░░ ░      
echo.                                ░ ░           ░    ░  ░   ░ ░          ░  ░ ░  ░ ░      ░  ░        
echo. 
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║              Version 7.0 - By Quaked               ║
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.
echo. 
echo. ╔═════════╗                                                                        
echo. ║ Loading ║                                              
echo. ╚═════════╝
timeout 4 > nul 

:: (Quaked) Windows Cleanup.
:Cleanup
cls
color 9
chcp 65001 >nul 2>&1
echo. 
echo.
echo.
echo.
echo.
echo.                                 ██╗    ██╗██╗███╗   ██╗██████╗  ██████╗ ██╗    ██╗███████╗ 
echo.                                 ██║    ██║██║████╗  ██║██╔══██╗██╔═══██╗██║    ██║██╔════╝ 
echo.                                 ██║ █╗ ██║██║██╔██╗ ██║██║  ██║██║   ██║██║ █╗ ██║███████╗ 
echo.                                 ██║███╗██║██║██║╚██╗██║██║  ██║██║   ██║██║███╗██║╚════██║ 
echo.                                 ╚███╔███╔╝██║██║ ╚████║██████╔╝╚██████╔╝╚███╔███╔╝███████║ 
echo.                                  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ 
echo.                                                           
echo.                                  ██████╗██╗     ███████╗ █████╗ ███╗   ██╗██╗   ██╗██████╗ 
echo.                                 ██╔════╝██║     ██╔════╝██╔══██╗████╗  ██║██║   ██║██╔══██╗
echo.                                 ██║     ██║     █████╗  ███████║██╔██╗ ██║██║   ██║██████╔╝
echo.                                 ██║     ██║     ██╔══╝  ██╔══██║██║╚██╗██║██║   ██║██╔═══╝ 
echo.                                 ╚██████╗███████╗███████╗██║  ██║██║ ╚████║╚██████╔╝██║     
echo.                                  ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝   
echo. 
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║        Running Quaked's Windows Cleanup...         ║       
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo. 
echo.
echo.                                                                          
timeout 2 > nul

cls
color D
echo (Quaked) Disabling Browsers Services...
sc config edgeupdate start=disabled >nul 2>&1
sc config edgeupdatem start=disabled >nul 2>&1
sc config GoogleChromeElevationService start=disabled >nul 2>&1
sc config gupdate start=disabled >nul 2>&1
sc config gupdatem start=disabled >nul 2>&1
sc config BraveElevationService start=disabled >nul 2>&1
sc config brave start=disabled >nul 2>&1
sc config bravem start=disabled >nul 2>&1

:: Fake Success Output.
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo Browsers Services disabled successfully.
timeout 1 > nul

cls
color 9
echo (Quaked) Disabling Cpu Services...

:: Intel Bloat.
sc config NcbService start=disabled >nul 2>&1
sc config jhi_service start=disabled >nul 2>&1
sc config WMIRegistrationService start=disabled >nul 2>&1
sc config "Intel(R) TPM Provisioning Service" start=disabled >nul 2>&1
sc config "Intel(R) Platform License Manager Service" start=disabled >nul 2>&1
sc config ipfsvc start=disabled >nul 2>&1
sc config igccservice start=disabled >nul 2>&1
sc config cplspcon start=disabled >nul 2>&1
sc config esifsvc start=disabled >nul 2>&1
sc config LMS start=disabled >nul 2>&1
sc config ibtsiva start=disabled >nul 2>&1
sc config IntelAudioService start=disabled >nul 2>&1
sc config "Intel(R) Capability Licensing Service TCP IP Interface" start=disabled >nul 2>&1
sc config cphs start=disabled >nul 2>&1
sc config DSAService start=disabled >nul 2>&1
sc config DSAUpdateService start=disabled >nul 2>&1
sc config igfxCUIService2.0.0.0 start=disabled >nul 2>&1
sc config RstMwService start=disabled >nul 2>&1
sc config "Intel(R) SUR QC SAM" start=disabled >nul 2>&1
sc config SystemUsageReportSvc_QUEENCREEK start=disabled >nul 2>&1
sc config iaStorAfsService start=disabled >nul 2>&1

:: HP Bloat.
sc config HPAppHelperCap start=disabled >nul 2>&1
sc config HPDiagsCap start=disabled >nul 2>&1
sc config HpTouchpointAnalyticsService start=disabled >nul 2>&1
sc config HPNetworkCap start=disabled >nul 2>&1
sc config HPOmenCap start=disabled >nul 2>&1
sc config HPSysInfoCap start=disabled >nul 2>&1

:: Gigabtye Bloat.
taskkill /f /im spd.exe >nul 2>&1
taskkill /f /im EasyTuneEngineService.exe >nul 2>&1
taskkill /f /im GraphicsCardEngine.exe >nul 2>&1
net stop "cFosSpeedS" >nul 2>&1
net stop "GigabyteUpdateService" >nul 2>&1
sc config cFosSpeedS start=disabled >nul 2>&1
sc config GigabyteUpdateService start=disabled >nul 2>&1
rd /s /q "C:\Program Files\cFosSpeed" >nul 2>&1
rd /s /q "C:\Program Files\GIGABYTE\Control Center\Lib\GBT_VGA\Service" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Gigabyte\EasyTuneEngineService" >nul 2>&1

:: Logitech
sc config logi_lamparray_service start=disabled >nul 2>&1

:: MSI Bloat
sc config SynTPEnhService start=disabled >nul 2>&1
sc config NahimicService start=disabled >nul 2>&1
sc config RtkAudioUniversalService start=disabled >nul 2>&1
:: sc config start=disabled
:: sc config start=disabled

:: Fake Success Output.
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
echo Manufacturer/Prebuild Services disabled successfully.
timeout 1 > nul
"@

$batPath = "$env:TEMP\OneClick.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue




# BitLogiK HushWin

$batchCode = @"
@echo off

echo.
echo ----  HushWin v 0.1  ----
echo   provided by BitLogiK
echo.

REM  HushWin
REM  Copyright (C) 2021  BitLogiK

REM  This program is free software: you can redistribute it and/or modify
REM  it under the terms of the GNU General Public License as published by
REM  the Free Software Foundation, either version 3 of the License, or
REM  (at your option) any later version.

REM  This program is distributed in the hope that it will be useful,
REM  but WITHOUT ANY WARRANTY; without even the implied warranty of
REM  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM  GNU General Public License for more details.

REM  You should have received a copy of the GNU General Public License
REM  along with this program.  If not, see <https://www.gnu.org/licenses/>.


NET SESSION >NUL 2>&1
if %errorlevel% NEQ 0 (
	echo This script needs to be run
	echo with Administrator rights.
	goto end
)
echo.

echo -> Process the Windows cleaning
echo.

echo Disabling Logging Services ...

	echo - Stopping Diagtrack service
	sc stop DiagTrack > NUL 2>&1
	sc config DiagTrack start= disabled > NUL 2>&1

	echo - Stopping dmwappushservice service
	sc stop dmwappushservice > NUL 2>&1
	sc config dmwappushservice start= disabled > NUL 2>&1

	echo - Stopping AutoLogger
	set F=%TEMP%\al.reg
	set F2=%TEMP%\al2.reg
	regedit /e "%F%" "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" > NUL 2>&1
	powershell -Command "Select-String -Pattern "\"Enabled\"", "\[HKEY", "Windows\sRegistry" -Path \"%F%\" | ForEach-Object {$_.Line} | Foreach-Object {$_ -replace '\"Enabled\"=dword:00000001', '\"Enabled\"=dword:00000000'} | Out-File \"%F2%\"" > NUL 2>&1
	regedit /s "%F2%" > NUL 2>&1
	del "%F%" "%F2%" > NUL 2>&1
	del "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\*.etl" "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\*.etl" > NUL 2>&1
	echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1

	echo - Stopping Diagnostics Hub Standard Collector
	sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1

echo.
echo Disabling Telemetry Scheduled Tasks ...
	schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Windows\Application Experience\AITAgent" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1

echo.
echo Removing Compatibility Telemetry Process ...
	takeown /F %windir%\System32\CompatTelRunner.exe > NUL 2>&1
	icacls %windir%\System32\CompatTelRunner.exe /grant %username%:F > NUL 2>&1
	del %windir%\System32\CompatTelRunner.exe /f > NUL 2>&1

echo.
echo Editing the registry ...
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "IsCensusDisabled" /t REG_DWORD /d 1 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "DontRetryOnError" /t REG_DWORD /d 1 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "TaskEnableRun" /t REG_DWORD /d 1 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f > NUL 2>&1

echo.
echo Performing additional actions ...
	echo - Stopping Nvidia Telemetry
	sc stop NvTelemetryContainer > NUL 2>&1
	sc config NvTelemetryContainer start= disabled > NUL 2>&1
	for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmMon"') do schtasks /Change /TN "%%~t" /Disable >nul 2>&1
	for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmRep"') do schtasks /Change /TN "%%~t" /Disable >nul 2>&1
	for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmRepOnLogon"') do schtasks /Change /TN "%%~t" /Disable >nul 2>&1
	for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvProfileUpdaterDaily"') do schtasks /Change /TN "%%~t" /Disable >nul 2>&1
	for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvProfileUpdaterOnLogon"') do schtasks /Change /TN "%%~t" /Disable >nul 2>&1
	reg add "HKCU\SOFTWARE\NVIDIA Corporation\NVControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f > NUL 2>&1
	
	echo - Stopping Office Telemetry
	schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE > NUL 2>&1
	schtasks /change /TN "\Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f > NUL 2>&1
	
	echo - Disabling Remote Assistance 
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f > NUL 2>&1
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f > NUL 2>&1
	
	echo - Disabling Windows Media Player usage tracking
	reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f > NUL 2>&1

echo.
echo HushWin script successfully executed.
echo Your Windows is now safe about telemetry collections.
"@
$batPath = "$env:TEMP\HushWin.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue




# Khorvie Tech mmm pain v3

$batchCode = @"
@echo off

:: bcdedit
bcdedit /set bootux disabled
bcdedit /set tscsyncpolicy enhanced
bcdedit /set uselegacyapicmode No
echo All commands executed successfully.

goto :TSC

one user claimed issues with applying this setting that resulted in the need to restore via a separate usb

to ensure this works properly, check your bios for this setting and make sure it is set to on from within the bios, then it should be safe to apply this batch file; if you are too lazy to go into the bios, then skip this step

bcdedit /set x2apicpolicy Enable

:TSC

bcdedit /deletevalue useplatformclock
bcdedit /deletevalue useplatformtick

:: adjust appearance
REM Set the performance settings to Custom
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

REM Disable animations in the taskbar and window titles
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "WindowAnimations" /t REG_DWORD /d 0 /f

REM Ensure thumbnails previews are enabled
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f

REM Ensure smooth edges of screen fonts are enabled
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FontSmoothing" /t REG_DWORD /d 1 /f

REM Disable desktop composition (Aero Glass)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

REM Disable fading and sliding menus
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "MenuAnimations" /t REG_DWORD /d 0 /f

echo Performance settings have been adjusted

:: timeout
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f

:: tcpip tweaks
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh interface isatap set state disabled
netsh int tcp set global timestamps=disabled


reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xFFFFFFFF /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable Event Trace Sessions (ETS)
for %%X in (
    "NTFSLog"
    "WiFiDriverIHVSession"
    "WiFiDriverSession"
    "WiFiSession"
    "SleepStudyTraceSession"
    "1DSListener"
    "MpWppTracing"
    "NVIDIA-NVTOPPS-NoCat"
    "NVIDIA-NVTOPPS-Filter"
    "Circular Kernel Context Logger"
    "DiagLog"
    "LwtNetLog"
    "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace"
    "NetCore"
    "RadioMgr"
    "ReFSLog"
    "WdiContextLog"
    "ShadowPlay"

) do (
    logman stop %%X -ets
)

:: DWM Schedule MASTER VALUES
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v WindowedGsyncGeforceFlag /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameRateMin /t REG_DWORD /d 0xFFFFFFFF /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreDisplayChangeDuration /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LingerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LicenseInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v RestrictedNvcplUIMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableSpecificPopups /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableExpirationPopups /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v EnableForceIgpuDgpuFromUI /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideXGpuTrayIcon /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v ShowTrayIcon /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideBalloonNotification /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v PerformanceState /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v Gc6State /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayBaseNegOffsetNS /t REG_DWORD /d 0xFFE17B80 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayResDivValue /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreNodeLocked /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreSP /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DontAskAgain /t REG_DWORD /d 1 /f

:: Kernel New Kizzimo
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerPerCpu /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerHighLatency /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerPerCpu /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerHighLatency /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f

bcdedit /set disabledynamictick No

echo All commands executed successfully.
"@

$batPath = "$env:TEMP\Khorvie.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue




# FR33THY Ultimate-Windows-Optimization-Guide
    
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
	
# Msi Mode
Clear-Host
# get all gpu driver ids
$gpuDevices = Get-PnpDevice -Class Display
foreach ($gpu in $gpuDevices) {
$instanceID = $gpu.InstanceId
# enable msi mode for all gpus regedit
reg add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f | Out-Null
}
# display msi mode for all gpus
foreach ($gpu in $gpuDevices) {
$instanceID = $gpu.InstanceId
$regPath = "Registry::HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
try {
$msiSupported = Get-ItemProperty -Path $regPath -Name "MSISupported" -ErrorAction Stop
Write-Output "$instanceID"
Write-Output "MSISupported: $($msiSupported.MSISupported)"
} catch {
Write-Output "$instanceID"
Write-Output "MSISupported: Not found or error accessing the registry."
}
}

# Direct X
Clear-Host
Write-Host "Installing: Direct X . . ."
# download direct x
$dxSetup = "$env:TEMP\DirectX.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe" -File $dxSetup
# install direct x
Start-Process $dxSetup -ArgumentList "/Q /T:`"$env:TEMP\DirectX`"" -Wait
Start-Process "$env:TEMP\DirectX\DXSETUP.exe" -ArgumentList "/silent" -Wait		
			
# C++
Clear-Host
Write-Host "Installing: C ++ . . ."
# download c++ installers
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -File "$env:TEMP\vcredist2005_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -File "$env:TEMP\vcredist2005_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -File "$env:TEMP\vcredist2008_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" -File "$env:TEMP\vcredist2008_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" -File "$env:TEMP\vcredist2010_x86.exe" 
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" -File "$env:TEMP\vcredist2010_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" -File "$env:TEMP\vcredist2012_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" -File "$env:TEMP\vcredist2012_x64.exe"
Get-FileFromWeb -URL "https://aka.ms/highdpimfc2013x86enu" -File "$env:TEMP\vcredist2013_x86.exe"
Get-FileFromWeb -URL "https://aka.ms/highdpimfc2013x64enu" -File "$env:TEMP\vcredist2013_x64.exe"
Get-FileFromWeb -URL "https://aka.ms/vs/17/release/vc_redist.x86.exe" -File "$env:TEMP\vcredist2015_2017_2019_2022_x86.exe"
Get-FileFromWeb -URL "https://aka.ms/vs/17/release/vc_redist.x64.exe" -File "$env:TEMP\vcredist2015_2017_2019_2022_x64.exe"
# start c++ installers
Start-Process -wait "$env:TEMP\vcredist2005_x86.exe" -ArgumentList "/q"
Start-Process -wait "$env:TEMP\vcredist2005_x64.exe" -ArgumentList "/q"
Start-Process -wait "$env:TEMP\vcredist2008_x86.exe" -ArgumentList "/qb"
Start-Process -wait "$env:TEMP\vcredist2008_x64.exe" -ArgumentList "/qb"
Start-Process -wait "$env:TEMP\vcredist2010_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2010_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2012_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2012_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2013_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2013_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2015_2017_2019_2022_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2015_2017_2019_2022_x64.exe" -ArgumentList "/passive /norestart"

# Start Menu Taskbar Clean
Clear-Host
# CLEAN TASKBAR	
# unpin all taskbar icons	
cmd /c "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband /f >nul 2>&1"	
Remove-Item -Recurse -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -ErrorAction SilentlyContinue | Out-Null	
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer" -Name "Quick Launch" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null	
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -Name "User Pinned" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null	
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -Name "TaskBar" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null	
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -Name "ImplicitAppShortcuts" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null	
Windows version branching
$build = try { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild } catch { 0 }
if ($build -le 19045) {	
	# Windows 10
	# CLEAN START MENU W10
	# delete startmenulayout.xml
	Remove-Item -Recurse -Force "$env:SystemDrive\Windows\StartMenuLayout.xml" -ErrorAction SilentlyContinue | Out-Null
	# create startmenulayout.xml
	$MultilineComment = @"
	<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
		<LayoutOptions StartTileGroupCellWidth="6" />
		<DefaultLayoutOverride>
			<StartLayoutCollection>
				<defaultlayout:StartLayout GroupCellWidth="6" />
			</StartLayoutCollection>
		</DefaultLayoutOverride>
	</LayoutModificationTemplate>
"@
	Set-Content -Path "C:\Windows\StartMenuLayout.xml" -Value $MultilineComment -Force -Encoding ASCII
	# assign startmenulayout.xml registry
	$layoutFile="C:\Windows\StartMenuLayout.xml"
	$regAliases = @("HKLM", "HKCU")
	foreach ($regAlias in $regAliases){
	$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
	$keyPath = $basePath + "\Explorer"
	IF(!(Test-Path -Path $keyPath)) {
	New-Item -Path $basePath -Name "Explorer" | Out-Null
	}
	Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1 | Out-Null
	Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile | Out-Null
	}
	# restart explorer
	Stop-Process -Force -Name explorer -ErrorAction SilentlyContinue | Out-Null
	Timeout /T 5 | Out-Null
	# disable lockedstartlayout registry
	foreach ($regAlias in $regAliases){
	$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
	$keyPath = $basePath + "\Explorer"
	Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
	}
	
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Remove-Item $layout -Force -ErrorAction SilentlyContinue
}

elseif ($build -ge 22000) {
	# Windows 11
    # Hide Recommended Section
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "HideRecommendedSection" -Value 1 -Type DWord
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -Type DWord
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education" -Name "IsEducationEnvironment" -Value 1 -Type DWord
	# unpin all start menu icons 
	Get-Process StartMenuExperienceHost | Stop-Process -Force; Start-Sleep -Milliseconds 200
	$url='https://github.com/Raphire/Win11Debloat/raw/refs/heads/master/Assets/Start/start2.bin'; $dst="$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin"
	if (!(Test-Path (Split-Path $dst))){New-Item -Path (Split-Path $dst) -ItemType Directory -Force | Out-Null}; Remove-Item $dst -Force -ErrorAction SilentlyContinue; Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
}
	
# Power Plan
Clear-Host
# import ultimate power plan
cmd /c "powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 99999999-9999-9999-9999-999999999999 >nul 2>&1"
# set ultimate power plan active
cmd /c "powercfg /SETACTIVE 99999999-9999-9999-9999-999999999999 >nul 2>&1"
# get all powerplans
# $output = powercfg /L
# $powerPlans = @()
# foreach ($line in $output) {
# extract guid manually to avoid lang issues
# if ($line -match ':') {
# $parse = $line -split ':'
# $index = $parse[1].Trim().indexof('(')
# $guid = $parse[1].Trim().Substring(0, $index)
# $powerPlans += $guid
# }
# }
# delete all powerplans
# foreach ($plan in $powerPlans) {
# cmd /c "powercfg /delete $plan" | Out-Null
# }
Clear-Host
# disable hibernate
powercfg /hibernate off
cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Power`" /v `"HibernateEnabled`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Power`" /v `"HibernateEnabledDefault`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
# disable lock
# cmd /c "reg add `"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings`" /v `"ShowLockOption`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
# disable sleep
# cmd /c "reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings`" /v `"ShowSleepOption`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
# disable fast boot
cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power`" /v `"HiberbootEnabled`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
# unpark cpu cores
cmd /c "reg add `"HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583`" /v `"ValueMax`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
# disable power throttling
cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling`" /v `"PowerThrottlingOff`" /t REG_DWORD /d `"1`" /f >nul 2>&1"
# unhide hub selective suspend timeout
cmd /c "reg add `"HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683`" /v `"Attributes`" /t REG_DWORD /d `"2`" /f >nul 2>&1"
# unhide usb 3 link power management
cmd /c "reg add `"HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009`" /v `"Attributes`" /t REG_DWORD /d `"2`" /f >nul 2>&1"
# MODIFY DESKTOP & LAPTOP SETTINGS
# hard disk turn off hard disk after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0x00000000
# desktop background settings slide show paused
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 001
# wireless adapter settings power saving mode maximum performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 000
# sleep
# sleep after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0x00000000
# allow hybrid sleep off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 000
# hibernate after
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0x00000000
# allow wake timers disable
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 000
# usb settings
# hub selective suspend timeout 0
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 0x00000000
# usb selective suspend setting disabled
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 000
# usb 3 link power management - off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 000
# power buttons and lid start menu power button shut down
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 002
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 002
# pci express link state power management off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 000
# processor power management
# minimum processor state 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 0x00000064
# system cooling policy active
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 001
# maximum processor state 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 0x00000064
# display
# turn off display after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0x00000000
# display brightness 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 0x00000064
# dimmed display brightness 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 0x00000064
# enable adaptive brightness off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 000
# video playback quality bias video playback performance bias
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 001
# when playing video optimize video quality
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 000
# MODIFY LAPTOP SETTINGS
# intel(r) graphics settings intel(r) graphics power plan maximum performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 002
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 002
Clear-Host
# amd power slider overlay best performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 003
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 003
Clear-Host
# ati graphics power settings ati powerplay settings maximize performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 001
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 001
Clear-Host
# switchable dynamic graphics global settings maximize performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 003
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 003
Clear-Host
# battery
# critical battery notification off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 000
# critical battery action do nothing
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 000
# low battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 0x00000000
# critical battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 0x00000000
# low battery notification off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 000
# low battery action do nothing
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 000
# reserve battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 0x00000000
# immersive control panel
# low screen brightness when using battery saver disable
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 0x00000064
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 0x00000064
Clear-Host
# immersive control panel
# turn battery saver on automatically at never
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0x00000000
Clear-Host
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0x00000000

# Timer Resolution
Clear-Host
Write-Host "Installing: Set Timer Resolution Service . . ."
# create .cs file
$MultilineComment = @"
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Management;
using System.Threading;
using System.Diagnostics;
[assembly: AssemblyVersion("2.1")]
[assembly: AssemblyProduct("Set Timer Resolution service")]
namespace WindowsService
{
    class WindowsService : ServiceBase
    {
        public WindowsService()
        {
            this.ServiceName = "STR";
            this.EventLog.Log = "Application";
            this.CanStop = true;
            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = false;
            this.CanPauseAndContinue = false;
            this.CanShutdown = false;
        }
        static void Main()
        {
            ServiceBase.Run(new WindowsService());
        }
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            ReadProcessList();
            NtQueryTimerResolution(out this.MininumResolution, out this.MaximumResolution, out this.DefaultResolution);
            if(null != this.EventLog)
                try { this.EventLog.WriteEntry(String.Format("Minimum={0}; Maximum={1}; Default={2}; Processes='{3}'", this.MininumResolution, this.MaximumResolution, this.DefaultResolution, null != this.ProcessesNames ? String.Join("','", this.ProcessesNames) : "")); }
                catch {}
            if(null == this.ProcessesNames)
            {
                SetMaximumResolution();
                return;
            }
            if(0 == this.ProcessesNames.Count)
            {
                return;
            }
            this.ProcessStartDelegate = new OnProcessStart(this.ProcessStarted);
            try
            {
                String query = String.Format("SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE (TargetInstance isa \"Win32_Process\") AND (TargetInstance.Name=\"{0}\")", String.Join("\" OR TargetInstance.Name=\"", this.ProcessesNames));
                this.startWatch = new ManagementEventWatcher(query);
                this.startWatch.EventArrived += this.startWatch_EventArrived;
                this.startWatch.Start();
            }
            catch(Exception ee)
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Error); }
                    catch {}
            }
        }
        protected override void OnStop()
        {
            if(null != this.startWatch)
            {
                this.startWatch.Stop();
            }

            base.OnStop();
        }
        ManagementEventWatcher startWatch;
        void startWatch_EventArrived(object sender, EventArrivedEventArgs e) 
        {
            try
            {
                ManagementBaseObject process = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
                UInt32 processId = (UInt32)process.Properties["ProcessId"].Value;
                this.ProcessStartDelegate.BeginInvoke(processId, null, null);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}

            }
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(UInt32 DesiredAccess, Int32 InheritHandle, UInt32 ProcessId);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 CloseHandle(IntPtr Handle);
        const UInt32 SYNCHRONIZE = 0x00100000;
        delegate void OnProcessStart(UInt32 processId);
        OnProcessStart ProcessStartDelegate = null;
        void ProcessStarted(UInt32 processId)
        {
            SetMaximumResolution();
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(SYNCHRONIZE, 0, processId);
                if(processHandle != IntPtr.Zero)
                    WaitForSingleObject(processHandle, -1);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}
            }
            finally
            {
                if(processHandle != IntPtr.Zero)
                    CloseHandle(processHandle); 
            }
            SetDefaultResolution();
        }
        List<String> ProcessesNames = null;
        void ReadProcessList()
        {
            String iniFilePath = Assembly.GetExecutingAssembly().Location + ".ini";
            if(File.Exists(iniFilePath))
            {
                this.ProcessesNames = new List<String>();
                String[] iniFileLines = File.ReadAllLines(iniFilePath);
                foreach(var line in iniFileLines)
                {
                    String[] names = line.Split(new char[] {',', ' ', ';'} , StringSplitOptions.RemoveEmptyEntries);
                    foreach(var name in names)
                    {
                        String lwr_name = name.ToLower();
                        if(!lwr_name.EndsWith(".exe"))
                            lwr_name += ".exe";
                        if(!this.ProcessesNames.Contains(lwr_name))
                            this.ProcessesNames.Add(lwr_name);
                    }
                }
            }
        }
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint ActualResolution);
        uint DefaultResolution = 0;
        uint MininumResolution = 0;
        uint MaximumResolution = 0;
        long processCounter = 0;
        void SetMaximumResolution()
        {
            long counter = Interlocked.Increment(ref this.processCounter);
            if(counter <= 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.MaximumResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
        void SetDefaultResolution()
        {
            long counter = Interlocked.Decrement(ref this.processCounter);
            if(counter < 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
    }
    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {
        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = 
                               new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;
            serviceInstaller.DisplayName = "Set Timer Resolution Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "STR";
            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }
}
"@
Set-Content -Path "$env:SystemDrive\Windows\SetTimerResolutionService.cs" -Value $MultilineComment -Force
# compile and create service
Start-Process -Wait "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ArgumentList "-out:C:\Windows\SetTimerResolutionService.exe C:\Windows\SetTimerResolutionService.cs" -WindowStyle Hidden
# delete file
Remove-Item "$env:SystemDrive\Windows\SetTimerResolutionService.cs" -ErrorAction SilentlyContinue | Out-Null
# install and start service
New-Service -Name "Set Timer Resolution Service" -BinaryPathName "$env:SystemDrive\Windows\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -StartupType Auto -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -Status Running -ErrorAction SilentlyContinue | Out-Null

# Bloatware
# uninstall microsoft update health tools w11
cmd /c "MsiExec.exe /X{C6FD611E-7EFE-488C-A0E0-974C09EF6473} /qn >nul 2>&1"
# uninstall microsoft update health tools w10
cmd /c "MsiExec.exe /X{1FC1A6C2-576E-489A-9B4A-92D21F542136} /qn >nul 2>&1"
# clean microsoft update health tools w10
cmd /c "reg delete `"HKLM\SYSTEM\ControlSet001\Services\uhssvc`" /f >nul 2>&1"
Unregister-ScheduledTask -TaskName PLUGScheduler -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
# uninstall update for windows 10 for x64-based systems
cmd /c "MsiExec.exe /X{B9A7A138-BFD5-4C73-A269-F78CCA28150E} /qn >nul 2>&1"
cmd /c "MsiExec.exe /X{85C69797-7336-4E83-8D97-32A7C8465A3B} /qn >nul 2>&1"

# Autoruns
Clear-Host
<#
# remove startup apps
cmd /c "reg delete `"HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification`" /f >nul 2>&1"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification" /f | Out-Null
cmd /c "reg delete `"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`" /f >nul 2>&1"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f | Out-Null
cmd /c "reg delete `"HKCU\Software\Microsoft\Windows\CurrentVersion\Run`" /f >nul 2>&1"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f | Out-Null
cmd /c "reg delete `"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`" /f >nul 2>&1"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f | Out-Null
cmd /c "reg delete `"HKLM\Software\Microsoft\Windows\CurrentVersion\Run`" /f >nul 2>&1"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /f | Out-Null
cmd /c "reg delete `"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`" /f >nul 2>&1"
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f | Out-Null
cmd /c "reg delete `"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`" /f >nul 2>&1"
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /f | Out-Null
Remove-Item -Recurse -Force "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Recurse -Force "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
#>
# remove logon edge
cmd /c "reg delete `"HKLM\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}`" /f >nul 2>&1"
# disable edge services
reg add "HKLM\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
reg add "HKLM\SYSTEM\ControlSet001\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
reg add "HKLM\SYSTEM\ControlSet001\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# remove edge tasks
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateBrowserReplacementTask'} | Unregister-ScheduledTask -Confirm:$false
# remove logon chrome
cmd /c "reg delete `"HKLM\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}`" /f >nul 2>&1"
# disable chrome services
$services = Get-Service | Where-Object { $_.Name -match 'Google' }
foreach ($service in $services) {
Set-Service -Name $service.Name -StartupType Disabled
Stop-Service -Name $service.Name -Force
}
# remove chrome tasks
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdaterTaskSystem'} | Unregister-ScheduledTask -Confirm:$false

# Network Adapter
Clear-Host
Write-Host "Network Adapter: Only Allow IPv4 . . ."
$progresspreference = 'silentlycontinue'
# disable all adapter settings keep ipv4
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat -ErrorAction SilentlyContinue
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer -ErrorAction SilentlyContinue
# rerun so settings stick
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat -ErrorAction SilentlyContinue
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer -ErrorAction SilentlyContinue

# Mpo
Clear-Host
# enable multiplane overlay regedit
cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\Windows\Dwm`" /v `"OverlayTestMode`" /f >nul 2>&1"
# enable optimizations for windowed games regedit
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;" /f | Out-Null

# Security
Clear-Host
# disable exploit protection, leaving control flow guard cfg on for vanguard anticheat
cmd /c "reg add `"HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel`" /v `"MitigationOptions`" /t REG_BINARY /d `"222222000001000000000000000000000000000000000000`" /f >nul 2>&1"
Timeout /T 2 | Out-Null
# create reg file
$MultilineComment = @"
Windows Registry Editor Version 5.00

; firewall notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection]
"NoActionNotificationDisabled"=dword:00000001
"SummaryNotificationDisabled"=dword:00000001
"FilesBlockedNotificationDisabled"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender Security Center\Account protection]
"DisableNotifications"=dword:00000001
"DisableDynamiclockNotifications"=dword:00000001
"DisableWindowsHelloNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Epoch]
"Epoch"=dword:000004cf

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"DisableNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"DisableNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"DisableNotifications"=dword:00000001

; core isolation 
; memory integrity 
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"ChangedInBootCycle"=-
"Enabled"=dword:00000000
"WasEnabledBy"=-

; kernel-mode hardware-enforced stack protection
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks]
"ChangedInBootCycle"=-
"Enabled"=dword:00000000
"WasEnabledBy"=-

; DISABLE DEFENDER SERVICES
; windows security service
; [HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService]
; "Start"=dword:00000003

; microsoft vulnerable driver blocklist
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\CI\Config]
"VulnerableDriverBlocklistEnable"=dword:00000000

; DISABLE OTHER
; windows defender firewall
[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"EnableFirewall"=dword:00000000

; uac
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000000

; spectre and meltdown
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management]
"FeatureSettingsOverrideMask"=dword:00000003
"FeatureSettingsOverride"=dword:00000003
"@
Set-Content -Path "$env:TEMP\SecurityOff.reg" -Value $MultilineComment -Force
Clear-Host
# import reg file
Regedit.exe /S "$env:TEMP\SecurityOff.reg"
Timeout /T 5 | Out-Null
# import reg file RunAsTI
$SecurityOff = @'
Regedit.exe /S "$env:TEMP\SecurityOff.reg"
'@
RunAsTI powershell "-nologo -windowstyle hidden -command $SecurityOff"
Timeout /T 5 | Out-Null




# BONUS


# ----------------------------------------------------------
# ---------------------Sets a wallpaper---------------------
# ----------------------------------------------------------
Write-Host "	Setting desktop background"

# Define paths
$picturesFolder = [Environment]::GetFolderPath("MyPictures")
$persistentWallpaperPath = Join-Path $picturesFolder "CustomWallpaper.jpg"

# Download wallpaper to Pictures folder
$url = "https://github.com/ManueITest/Accel/raw/main/jpg/wallpaper.jpg"
Get-FileFromWeb $url $persistentWallpaperPath

# Set wallpaper using SystemParametersInfo
try {
    Add-Type @"
    using System.Runtime.InteropServices;
    public class Wallpaper {
        public const int SPI_SETDESKWALLPAPER = 0x0014;
        public const int SPIF_UPDATEINIFILE = 0x01;
        public const int SPIF_SENDWININICHANGE = 0x02;
        [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
"@

    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10"
    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value "0"

    [Wallpaper]::SystemParametersInfo(0x0014, 0, $persistentWallpaperPath, 1 -bor 2) | Out-Null
} catch {}
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------Install & activate custom cursor--------------
# ----------------------------------------------------------
# Function to download a ZIP file from the web, extract it to TEMP, and remove the ZIP
function Get-FileFromWB {
    param([string]$Url)
    $temp = $env:TEMP
    $zip = Join-Path $temp ([System.IO.Path]::GetFileName($Url))

    # Download the ZIP file to the temp directory
    try { Invoke-WebRequest $Url -OutFile $zip -EA Stop } catch { exit 1 }

    # Extract the ZIP contents to the temp directory
    try { Expand-Archive $zip -DestinationPath $temp -Force -EA Stop } catch { exit 1 }

    # Remove the ZIP file after extraction
    try { Remove-Item $zip -Force -EA Stop } catch {}
}

# Download and extract the cursor ZIP package
Get-FileFromWB "https://github.com/ManueITest/Accel/raw/refs/heads/main/zip/Cursor.zip"

# Define the expected path to the INF installer file
$InfPath = Join-Path $env:TEMP "install.inf"

# Exit if the INF file is not present after extraction
if (-not (Test-Path $InfPath)) { exit 1 }

try {
    # Silently install the cursor pack using the INF file and rundll32
    $p = Start-Process -PassThru -WindowStyle Hidden -FilePath "rundll32.exe" -ArgumentList "setupapi.dll,InstallHinfSection", "DefaultInstall", "132", $InfPath
} catch { exit 1 }

try {
    # Define a .NET class to refresh system cursors using the SystemParametersInfo API
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Cursor {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);
    public static void RefreshCursors() {
        SystemParametersInfo(0x0057, 0, IntPtr.Zero, 0);
    }
}
'@ | Out-Null

    # Call the method to refresh the system cursors
    [Cursor]::RefreshCursors()
    Start-Sleep -Milliseconds 300
} catch {}

# Attempt to gracefully close any rundll32 processes related to mouse/cursor installation,
# then forcibly terminate if needed, and repeat this process up to 3 times for reliability
1..3 | ForEach-Object {
    try {
        Get-Process rundll32 -EA Stop |
        Where-Object { $_.MainWindowTitle -match "Mouse|Cursors|Pointer" } |
        ForEach-Object {
            $_.CloseMainWindow() | Out-Null
            Start-Sleep -Milliseconds 200
            if (-not $_.HasExited) { Stop-Process $_ -Force -EA Stop }
        }
    } catch {}
    try {
        if ($p -and -not $p.HasExited) {
            $p.CloseMainWindow() | Out-Null
            if (-not $p.WaitForExit(500)) { $p | Stop-Process -Force -EA Stop }
        }
    } catch {}
    try {
        # Ensure all other rundll32 processes (except this script) are stopped
        Get-Process rundll32 -EA Stop | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -EA Stop
    } catch {}
    Start-Sleep -Milliseconds 300
}

# Cleanup temporary files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------Add "System Properties" shortcut to Start menu------
# ----------------------------------------------------------
$t="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System Properties.lnk";$s=(New-Object -ComObject WScript.Shell).CreateShortcut($t);$s.TargetPath="$env:SystemRoot\System32\SystemPropertiesAdvanced.exe";$s.IconLocation="$env:SystemRoot\System32\SystemPropertiesAdvanced.exe";$s.Save()
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------Import community Power Plans-----------------
# ----------------------------------------------------------
Write-Host "--- Importing community power plans"
$z="$env:TEMP\PowerPlans.zip";$e=Join-Path $env:TEMP 'pow';Get-FileFromWeb "https://github.com/ManueITest/Accel/raw/refs/heads/main/zip/PowerPlans.zip" $z; Expand-Archive $z $e -Force; Get-ChildItem $e -Filter *.pow | % { powercfg -import $_.FullName *>$null }
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------Install Chocolatey and WinGet----------------
# ----------------------------------------------------------
# Set execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process -Force
# Ensure TLS 1.2 is enabled for secure downloads
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
# Download and run the Chocolatey install script
iex (irm https://community.chocolatey.org/install.ps1)
# ----------------------------------------------------------



# "3rd party app name" that will be installed | "Windows app name" that would be removed/replaced

# ----------------------------------------------------------
# --------------Everything | Windows Search-----------------
# ----------------------------------------------------------
# install Everything with choco , winget as fallback
$e="$env:ProgramFiles\Everything\Everything.exe";if(!(Test-Path $e)){if(Get-Command choco -ea 0){choco install everything -y}else{if(Get-Command winget -ea 0){winget install --id Voidtools.Everything --accept-package-agreements --accept-source-agreements -h}}}
# Pin Everything.exe to the Taskbar Using PS-TBPin https://github.com/DanysysTeam/PS-TBPin
powershell -ExecutionPolicy Bypass -command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DanysysTeam/PS-TBPin/main/TBPin.ps1')); Add-TaskbarPin 'C:\Program Files\Everything\Everything.exe' }"
# Rename Start Menu shortcut and remove desktop shortcut
$f1="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Everything.lnk";if(Test-Path $f1){Rename-Item $f1 'Search.lnk' -Force};$f2="$env:PUBLIC\Desktop\Everything.lnk";if(Test-Path $f2){Remove-Item $f2 -Force}
# Disable and stop Windows Search service
Set-Service -Name WSearch -StartupType Disabled; Stop-Service -Name WSearch -Force
# Disable built-in Windows Search feature
Dism /Online /NoRestart /Disable-Feature /FeatureName:SearchEngine-Client-Package
# Kill Search app
$batchCode = @"
@echo off

title Windows Search toggle script made by imribiy#0001
cls

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:disable
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
sc stop wsearch
taskkill /f /im explorer.exe
taskkill /f /im searchapp.exe
cd C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy
takeown /f "searchapp.exe"
icacls "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\searchapp.exe" /grant Administrators:F
ren searchapp.exe searchapp.old
start explorer.exe
cls
exit
"@			
# Write batch to TEMP
$batPath = "$env:TEMP\SearchDisable.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
# Run the batch via cmd
Start-Process "cmd.exe" -ArgumentList "/c `"$batPath`""
# Delay a moment to let batch relaunch if elevated, then clean up
Start-Sleep -Seconds 2
if (Test-Path $batPath) { Remove-Item $batPath -Force -ErrorAction SilentlyContinue }
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------Brave Browser | Microsoft Edge---------------
# ----------------------------------------------------------
# stop edge running
"MicrosoftEdgeUpdate","OneDrive","WidgetService","Widgets","msedge","msedgewebview2" | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
# Microsoft Edge Uninstallers
# Both - Removes both Edge, and WebView.
# Edge - Removes Edge and Appx version of Edge only.
# Edge-Appx - Remove Appx version of Edge only. Leave Webview / Chrome version alone.
Get-FileFromWeb 'https://github.com/ShadowWhisperer/Remove-MS-Edge/raw/refs/heads/main/Batch/Edge.bat' "$env:TEMP\Edge.bat"; Start-Process cmd.exe -ArgumentList '/c', "$env:TEMP\Edge.bat" -Wait; Remove-Item "$env:TEMP\Edge.bat" -Force
Start-Sleep -Seconds 3
# install Brave
# define possible Brave executable paths         	
$b=@("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe","$env:LocalAppData\BraveSoftware\Brave-Browser\Application\brave.exe")				
# If Brave is not found in any standard location, install it using Chocolatey or Winget			    
if(!($b|?{Test-Path $_})){if(gcm choco -ea 0){choco install brave -y}elseif(gcm winget -ea 0){winget install --id Brave.Brave --accept-package-agreements --accept-source-agreements}}			
Start-Sleep -Seconds 3	
# Delete Brave Bloatware
# Disable Brave Services
$batchCode = @"
@echo off

:: FoxOS Post Install
echo Deleting Brave Bloatware


taskkill /f /im "BraveUpdate.exe" >nul 2>&1
taskkill /f /im "brave_installer-x64.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandler.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandler64.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandlerArm64.exe" >nul 2>&1
taskkill /f /im "BraveUpdateBroker.exe" >nul 2>&1
taskkill /f /im "BraveUpdateCore.exe" >nul 2>&1
taskkill /f /im "BraveUpdateOnDemand.exe" >nul 2>&1
taskkill /f /im "BraveUpdateSetup.exe" >nul 2>&1
taskkill /f /im "BraveUpdateComRegisterShell64" >nul 2>&1
taskkill /f /im "BraveUpdateComRegisterShellArm64" >nul 2>&1
sc delete brave >nul 2>&1
sc delete bravem >nul 2>&1
sc delete BraveElevationService >nul 2>&1
rmdir /s /q "C:\Program Files (x86)\BraveSoftware\Update" >nul 2>&1

schtasks /delete /f /tn BraveSoftwareUpdateTaskMachineCore{2320C90E-9617-4C25-88E0-CC10B8F3B6BB} >nul 2>&1
schtasks /delete /f /tn BraveSoftwareUpdateTaskMachineUA{FD1FD78D-BD51-4A16-9F47-EE6518C2D038} >nul 2>&1
reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{56CA197F-543C-40DC-953C-B9C6196C92A5}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{0948A341-8E1E-479F-A667-6169E4D5CB2A}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0948A341-8E1E-479F-A667-6169E4D5CB2A}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{56CA197F-543C-40DC-953C-B9C6196C92A5}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineCore" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineUA" /f >nul 2>&1	

:: Made by Quaked
:: TikTok: _Quaked_
:: Discord: https://discord.gg/B8EmFVkdFU

cls
color D
echo (Quaked) Disabling Browsers Services...
sc config BraveElevationService start=disabled >nul 2>&1
sc config brave start=disabled >nul 2>&1
sc config bravem start=disabled >nul 2>&1
"@
$batPath = "$env:TEMP\BraveDebloat.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue	
Start-Sleep -Seconds 2	
# Debloat Brave using Chromium policies. Auto-generated using https://github.com/yashgorana/chrome-debloat
$MultilineComment = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]
"TorDisabled"=dword:00000001
"BraveRewardsDisabled"=dword:00000001
"BraveWalletDisabled"=dword:00000001
"BraveVPNDisabled"=dword:00000001
"BraveAIChatEnabled"=dword:00000000
"BraveSyncUrl"=""
"DefaultGeolocationSetting"=dword:00000002
"DefaultNotificationsSetting"=dword:00000002
"DefaultLocalFontsSetting"=dword:00000002
"DefaultSensorsSetting"=dword:00000002
"DefaultSerialGuardSetting"=dword:00000002
"CloudReportingEnabled"=dword:00000000
"DriveDisabled"=dword:00000001
"PasswordManagerEnabled"=dword:00000000
"PasswordSharingEnabled"=dword:00000000
"PasswordLeakDetectionEnabled"=dword:00000000
"QuickAnswersEnabled"=dword:00000000
"SafeBrowsingExtendedReportingEnabled"=dword:00000000
"SafeBrowsingSurveysEnabled"=dword:00000000
"SafeBrowsingDeepScanningEnabled"=dword:00000000
"DeviceActivityHeartbeatEnabled"=dword:00000000
"DeviceMetricsReportingEnabled"=dword:00000000
"HeartbeatEnabled"=dword:00000000
"LogUploadEnabled"=dword:00000000
"ReportAppInventory"=""
"ReportDeviceActivityTimes"=dword:00000000
"ReportDeviceAppInfo"=dword:00000000
"ReportDeviceSystemInfo"=dword:00000000
"ReportDeviceUsers"=dword:00000000
"ReportWebsiteTelemetry"=""
"AlternateErrorPagesEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"MetricsReportingEnabled"=dword:00000000
"ParcelTrackingEnabled"=dword:00000000
"RelatedWebsiteSetsEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"ExtensionManifestV2Availability"=dword:00000002

; Install uBlock Origin	
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist]
"1"="cjpalhdlnbpafiamejdnhcphjbkeiagm"		

; SlimBrave
; https://github.com/ltx0101/SlimBrave/tree/main
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]
"UrlKeyedAnonymizedDataCollectionEnabled"=dword:00000000
"FeedbackSurveysEnabled"=dword:00000000
"SafeBrowsingProtectionLevel"=dword:00000000
"AutofillAddressEnabled"=dword:00000000
"WebRtcIPHandling"="disable_non_proxied_udp"
"QuicAllowed"=dword:00000000
"BlockThirdPartyCookies"=dword:00000001
"EnableDoNotTrack"=dword:00000001
"ForceGoogleSafeSearch"=dword:00000001
"IPFSEnabled"=dword:00000000
"DnsOverHttpsMode"="off"
"BraveShieldsDisabledForUrls"="[""https://*"",""http://*""]"
"MediaRecommendationsEnabled"=dword:00000000
"AlwaysOpenPdfExternally"=dword:00000001
"TranslateEnabled"=dword:00000000
"SpellcheckEnabled"=dword:00000000
"PromotionsEnabled"=dword:00000000
"SearchSuggestEnabled"=dword:00000000
"PrintingEnabled"=dword:00000000
"DeveloperToolsDisabled"=dword:00000001

; brave-debullshitinator
; https://github.com/MulesGaming/brave-debloatinator
[HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave]
"NewTabPageLocation"="https://search.brave.com"
"@
Set-Content -Path "$env:TEMP\BraveTweaks.reg" -Value $MultilineComment -Force				
# edit reg file				
$path = "$env:TEMP\BraveTweaks.reg"				
(Get-Content $path) -replace "\?","$" | Out-File $path				
# import reg file				
Regedit.exe /S "$env:TEMP\BraveTweaks.reg"
# ----------------------------------------------------------	


# ----------------------------------------------------------
# --------------PowerRun | Trusted Installer----------------
# ----------------------------------------------------------
Get-FileFromWeb -URL "https://www.sordum.org/files/downloads.php?power-run" -File "$env:TEMP\PowerRun.zip"; Expand-Archive -Path "$env:TEMP\PowerRun.zip" -DestinationPath "$env:TEMP\PowerRun_Extracted" -Force; Move-Item "$env:TEMP\PowerRun_Extracted\PowerRun\PowerRun_x64.exe" "$env:SystemRoot\System32\PowerRun.exe" -Force; Remove-Item "$env:TEMP\PowerRun.zip","$env:TEMP\PowerRun_Extracted" -Recurse -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------Process Explorer (Task Manager)---------------
# ----------------------------------------------------------
$u="https://download.sysinternals.com/files/ProcessExplorer.zip";$p="$env:TEMP\ProcessExplorer.zip";$d="$env:ProgramFiles\ProcessExplorer";$e="$d\procexp64.exe";iwr $u -OutFile $p -UseBasicParsing; if(!(Test-Path $d)){New-Item $d -ItemType Directory -Force|Out-Null}; Expand-Archive $p $d -Force; Remove-Item $p -Force
# Run Process Explorer only in one instance
New-Item "HKCU:\SOFTWARE\Sysinternals\Process Explorer","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -Force|Out-Null; Set-ItemProperty "HKCU:\SOFTWARE\Sysinternals\Process Explorer" OneInstance 1; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" Debugger "`"$e`" /e"
Start-Sleep -Seconds 2 
# Process Explorer Settings  
$MultilineComment = @"				
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer]
"ShowDllView"=dword:00000000
"HandleSortColumn"=dword:00000000
"HandleSortDirection"=dword:00000001
"DllSortColumn"=dword:00000000
"DllSortDirection"=dword:00000001
"ProcessSortColumn"=dword:ffffffff
"ProcessSortDirection"=dword:00000001
"HighlightServices"=dword:00000001
"HighlightOwnProcesses"=dword:00000001
"HighlightRelocatedDlls"=dword:00000000
"HighlightJobs"=dword:00000000
"HighlightNewProc"=dword:00000001
"HighlightDelProc"=dword:00000001
"HighlightImmersive"=dword:00000001
"HighlightProtected"=dword:00000000
"HighlightPacked"=dword:00000001
"HighlightNetProcess"=dword:00000000
"HighlightSuspend"=dword:00000001
"HighlightDuration"=dword:000003e8
"ShowCpuFractions"=dword:00000001
"FindWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,96,00,00,00,96,00,00,00,00,00,00,00,\
00,00,00,00
"ShowAllUsers"=dword:00000001
"ShowProcessTree"=dword:00000001
"SymbolWarningShown"=dword:00000000
"HideWhenMinimized"=dword:00000000
"AlwaysOntop"=dword:00000000
"OneInstance"=dword:00000000
"NumColumnSets"=dword:00000000
"Windowplacement"=hex(3):2C,00,00,00,02,00,00,00,03,00,00,00,00,00,00,00,00,\
00,00,00,FF,FF,FF,FF,FF,FF,FF,FF,37,02,00,00,8C,01,00,00,57,05,00,00,E4,03,\
00,00
"RefreshRate"=dword:000003e8
"PrcessColumnCount"=dword:0000000d
"DllColumnCount"=dword:00000004
"HandleColumnCount"=dword:00000002
"DefaultProcPropPage"=dword:00000000
"DefaultSysInfoPage"=dword:00000000
"DefaultDllPropPage"=dword:00000000
"ProcessImageColumnWidth"=dword:000000c8
"SymbolPath"=""
"ColorPacked"=dword:00ff0080
"ColorImmersive"=dword:00eaea00
"ColorOwn"=dword:00ffd0d0
"ColorServices"=dword:00d0d0ff
"ColorRelocatedDlls"=dword:00a0ffff
"ColorGraphBk"=dword:00f0f0f0
"ColorJobs"=dword:00006cd0
"ColorDelProc"=dword:004646ff
"ColorNewProc"=dword:0046ff46
"ColorNet"=dword:00a0ffff
"ColorProtected"=dword:008000ff
"ShowHeatmaps"=dword:00000001
"ColorSuspend"=dword:00808080
"StatusBarColumns"=dword:00002015
"ShowAllCpus"=dword:00000000
"ShowAllGpus"=dword:00000000
"Opacity"=dword:00000064
"GpuNodeUsageMask"=dword:00000001
"GpuNodeUsageMask1"=dword:00000000
"VerifySignatures"=dword:00000000
"VirusTotalCheck"=dword:00000000
"VirusTotalSubmitUnknown"=dword:00000000
"ToolbarBands"=hex(3):06,01,00,00,00,00,00,00,00,00,00,00,4B,00,00,00,01,00,\
00,00,00,00,00,00,4B,00,00,00,02,00,00,00,00,00,00,00,4B,00,00,00,03,00,00,\
00,00,00,00,00,4B,00,00,00,04,00,00,00,00,00,00,00,4B,00,00,00,05,00,00,00,\
00,00,00,00,4B,00,00,00,06,00,00,00,00,00,00,00,4B,00,00,00,07,00,00,00,00,\
00,00,00,00,00,00,00,08,00,00,00,00,00,00,00
"UseGoogle"=dword:00000000
"ShowNewProcesses"=dword:00000000
"TrayCPUHistory"=dword:00000000
"ShowIoTray"=dword:00000000
"ShowNetTray"=dword:00000000
"ShowDiskTray"=dword:00000000
"ShowPhysTray"=dword:00000000
"ShowCommitTray"=dword:00000000
"ShowGpuTray"=dword:00000000
"FormatIoBytes"=dword:00000001
"StackWindowPlacement"=hex(3):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00
"ETWstandardUserWarning"=dword:00000000
"ShowUnnamedHandles"=dword:00000000
"SavedDivider"=hex(3):00,00,00,00,00,00,E0,3F
"UnicodeFont"=hex(3):08,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,90,01,\
00,00,00,00,00,00,00,00,00,00,4D,00,53,00,20,00,53,00,68,00,65,00,6C,00,6C,\
00,20,00,44,00,6C,00,67,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"Divider"=hex(3):00,00,00,00,00,00,F0,3F
"DllPropWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,\
00,00,00,00,00
"PropWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,00,\
00,00,00,00
"DbgHelpPath"="C:\\Windows\\SYSTEM32\\dbghelp.dll"
"SysinfoWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,\
00,00,00,00,00
"ConfirmKill"=dword:00000001
"ShowLowerpane"=dword:00000000

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumnMap]
"3"=dword:00000457
"2"=dword:00000409
"0"=dword:0000001a
"1"=dword:0000002a

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumns]
"2"=dword:0000008c
"0"=dword:0000006e
"1"=dword:000000b4
"3"=dword:0000012c

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumnMap]
"1"=dword:00000016
"0"=dword:00000015

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumns]
"0"=dword:00000064
"1"=dword:000001c2

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumnMap]
"10"=dword:0000049b
"8"=dword:00000005
"12"=dword:00000409
"13"=dword:00000672
"7"=dword:00000004
"5"=dword:00000427
"11"=dword:00000026
"9"=dword:0000053c
"0"=dword:00000003
"1"=dword:0000041f
"2"=dword:00000672
"6"=dword:00000429
"3"=dword:000004b0
"4"=dword:00000424

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumns]
"9"=dword:0000002a
"10"=dword:00000035
"11"=dword:00000096
"12"=dword:0000008c
"8"=dword:0000002b
"7"=dword:00000028
"5"=dword:00000050
"4"=dword:00000050
"3"=dword:00000056
"2"=dword:00000022
"1"=dword:00000028
"6"=dword:00000022
"0"=dword:000000c8   
"@

Set-Content -Path "$env:TEMP\ProcessExplorerSettings.reg" -Value $MultilineComment -Force				
# edit reg file				
$path = "$env:TEMP\ProcessExplorerSettings.reg"				
(Get-Content $path) -replace "\?","$" | Out-File $path				
# import reg file				
Regedit.exe /S "$env:TEMP\ProcessExplorerSettings.reg"	
# ----------------------------------------------------------				


# ----------------------------------------------------------
# ---------------Notepad++ | Windows Notepad----------------
# ----------------------------------------------------------	
Get-AppxPackage -AllUsers *Microsoft.WindowsNotepad* | Remove-AppxPackage -AllUsers
# Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like *WindowsNotepad* | Remove-AppxProvisionedPackage -Online

# "Microsoft.Windows.Notepad.System~~~~0.0.1.0","Microsoft.Windows.Notepad~~~~0.0.1.0" | % { Remove-WindowsCapability -Online -Name $_ >$null 2>&1 }

$npp="$env:ProgramFiles\Notepad++\notepad++.exe";if(!(Test-Path $npp)){if(Get-Command choco -ea 0){choco install notepadplusplus -y}else{if(Get-Command winget -ea 0){winget install --id Notepad++.Notepad++ --accept-source-agreements --accept-package-agreements --silent}}}
if(Test-Path $npp){cmd /c "ftype txtfile=`"$npp`" `"%1`""; cmd /c "assoc .txt=txtfile"; $reg="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice"; if(Test-Path $reg){Remove-Item $reg -Recurse -Force}}              
				
$MultilineComment = @"				
Windows Registry Editor Version 5.00				
				
; Created by: Shawn Brink
; http://www.tenforums.com
; Tutorial: http://www.tenforums.com/tutorials/8703-default-file-type-associations-restore-windows-10-a.html
; enhanced by WillingMost7


[-HKEY_CLASSES_ROOT\.txt]

[HKEY_CLASSES_ROOT\.txt]
@="txtfile"
"Content Type"="text/plain"
"PerceivedType"="text"

[HKEY_CLASSES_ROOT\.txt\PersistentHandler]
@="{5e941d80-bf96-11cd-b579-08002b30bfeb}"

[HKEY_CLASSES_ROOT\.txt\ShellNew]
"ItemName"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,\
  6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\
  00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,2c,00,\
  2d,00,34,00,37,00,30,00,00,00
"NullFile"=""

[-HKEY_CLASSES_ROOT\SystemFileAssociations\.txt]

[HKEY_CLASSES_ROOT\SystemFileAssociations\.txt]
"PerceivedType"="document"

[-HKEY_CLASSES_ROOT\txtfile]

[HKEY_CLASSES_ROOT\txtfile]
@="Text Document"
"EditFlags"=dword:00210000
"FriendlyTypeName"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,\
  00,6f,00,6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,\
  32,00,5c,00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,\
  00,2c,00,2d,00,34,00,36,00,39,00,00,00

[HKEY_CLASSES_ROOT\txtfile\DefaultIcon]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,00,6d,00,\
  61,00,67,00,65,00,72,00,65,00,73,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,31,\
  00,30,00,32,00,00,00

[HKEY_CLASSES_ROOT\txtfile\shell\open\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\txtfile\shell\print]

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithList]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids]
"txtfile"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice]
"Hash"="hyXk/CpboWw="
"ProgId"="txtfile"

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.txt]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.txt\UserChoice]
"Hash"="FvJcqeZpmOE="
"ProgId"="txtfile"

[HKEY_CLASSES_ROOT\regfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\regfile\shell\print]

[HKEY_CLASSES_ROOT\batfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\batfile\shell\print]

[HKEY_CLASSES_ROOT\VBSFile\Shell\Edit\Command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\VBSFile\Shell\Print]

[HKEY_CLASSES_ROOT\cmdfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\cmdfile\shell\print]

[-HKEY_CLASSES_ROOT\xbox-tcui]
[-HKEY_CLASSES_ROOT\xboxmusic]					
"@
Set-Content -Path "$env:TEMP\Notepad.reg" -Value $MultilineComment -Force				
# edit reg file				
$path = "$env:TEMP\Notepad.reg"				
(Get-Content $path) -replace "\?","$" | Out-File $path				
# import reg file				
Regedit.exe /S "$env:TEMP\Notepad.reg"										
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------simplewall (Windows FireWall)----------------
# ----------------------------------------------------------
$s="$env:ProgramFiles\simplewall\simplewall.exe";if(!(Test-Path $s)){if(Get-Command choco -ea 0){choco install simplewall -y}else{if(Get-Command winget -ea 0){winget install --id SimpleWall.SimpleWall --accept-source-agreements --accept-package-agreements --silent}}}
$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\simplewall.lnk"); $Shortcut.TargetPath = "C:\Program Files\simplewall\simplewall.exe"; $Shortcut.WorkingDirectory = "C:\Program Files\simplewall"; $Shortcut.Save()
Start-Sleep -Seconds 2
$batchCode = @"
@echo off
netsh advfirewall set allprofiles state off
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
exit
"@
$batPath = "$env:TEMP\FirewallOFF.bat"			
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII			
Start-Process -FilePath $batPath -Wait					
Remove-Item $batPath -Force -ErrorAction SilentlyContinue
# ----------------------------------------------------------


# ----------------------------------------------------------
# ---------VLC media player (Windows Media Player)----------
# ----------------------------------------------------------
$vlc="$env:ProgramFiles\VideoLAN\VLC\vlc.exe";if(!(Test-Path $vlc)){if(Get-Command choco -ea 0){choco install vlc -y}else{if(Get-Command winget -ea 0){winget install --id VideoLAN.VLC --accept-package-agreements --accept-source-agreements}}}
$f="$env:PUBLIC\Desktop\VLC media player.lnk";if(Test-Path $f){Remove-Item $f -Force}
# ----------------------------------------------------------			


# ----------------------------------------------------------
# -------------------7-Zip (Explorer)-----------------------
# ----------------------------------------------------------
$exe="$env:ProgramFiles\7-Zip\7zFM.exe";if(!(Test-Path $exe)){if(Get-Command choco -ea 0){choco install 7zip -y}else{if(Get-Command winget -ea 0){winget install --id 7zip.7zip --accept-package-agreements --accept-source-agreements}}}
if(Test-Path $exe){'7z','xz','bzip2','gzip','tar','zip','wim','apfs','ar','arj','cab','chm','cpio','cramfs','dmg','ext','fat','gpt','hfs','ihex','iso','lzh','lzma','mbr','msi','nsis','ntfs','qcow2','rar','rpm','squashfs','udf','uefi','vdi','vhd','vhdx','vmdk','xar','z'|%{cmd /c "assoc .$_=7zFM.exe" >$null}; cmd /c 'ftype 7zFM.exe="C:\Program Files\7-Zip\7zFM.exe" "%1" "%*"' >$null}
# ----------------------------------------------------------


# ----------------------------------------------------------
# --Install SpotX Ad-free desktop Spotify with parameters---
# ----------------------------------------------------------
# https://github.com/SpotX-Official/SpotX/discussions/60
iex "& { $(iwr -useb 'https://spotx-official.github.io/run.ps1') } -m -sp-over -new_theme -canvashome_off -adsections_off -podcasts_off -block_update_on -DisableStartup -cl 500 -no_shortcut"
Start-Sleep -Seconds 2
$batchCode = @"
@echo off
title SPOTIFY DEBLOATER BY CATGAMEROP
echo SPOTIFY DEBLOATER BY CATGAMEROP

cd /d "%APPDATA%\Spotify" >NUL 2>&1
copy "%APPDATA%\Spotify\locales\en-US.pak" "%APPDATA%\Spotify" >NUL 2>&1
rmdir "%APPDATA%\Spotify\locales" /s /q >NUL 2>&1
mkdir "%APPDATA%\Spotify\locales" >NUL 2>&1
move "%APPDATA%\Spotify\en-US.pak" "%APPDATA%\Spotify\locales" >NUL 2>&1
"@			
$batPath = "$env:TEMP\Spotify Debloat by CatGamerOP.bat"			
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII			
Start-Process -FilePath $batPath -Wait					
Remove-Item $batPath -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------------WebCord | Discord----------------------
# ----------------------------------------------------------
Write-Host "--- Installing WebCord (Discord client)"
Get-FileFromWeb -URL "https://github.com/SpacingBat3/WebCord/releases/latest/download/webcord-squirrel-x64.exe" -File "$env:TEMP\webcord-squirrel-x64.exe";Start-Process -Wait "$env:TEMP\webcord-squirrel-x64.exe";$iconDir="$env:APPDATA\local\webcord";if(!(Test-Path $iconDir)){ni $iconDir -ItemType Directory -Force|Out-Null};Get-FileFromWeb -URL "https://github.com/ManueITest/Accel/raw/refs/heads/main/ico/Discord.ico" -File "$iconDir\Discord.ico";$webcordExe=(gci "$env:LOCALAPPDATA\Programs\WebCord\app-*","$env:LOCALAPPDATA\webcord" -Filter "WebCord.exe" -Recurse -ea 0|select -First 1).FullName;$sc=(New-Object -ComObject WScript.Shell).CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Discord.lnk");$sc.TargetPath=$webcordExe;$sc.WorkingDirectory=[System.IO.Path]::GetDirectoryName($webcordExe);$sc.IconLocation="$iconDir\Discord.ico";$sc.Save()
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------StartIsBack/StartAllBack | Windows Start----------
# ----------------------------------------------------------
$build = try { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild } catch { 0 }
# StartIsBack
if ($build -le 19045) {
	$exe="$env:TEMP\StartIsBackPlusPlus_setup.exe"; Get-FileFromWeb -URL "https://startisback.sfo3.cdn.digitaloceanspaces.com/StartIsBackPlusPlus_setup.exe" -File $exe; Start-Process -FilePath $exe -ArgumentList "/elevated /silent" -Wait; Remove-Item $exe -Force
	# Start Windows Explorer
	Start-Process explorer

# create reg file
$MultilineComment = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\StartIsBack]
"CurrentVersion"="2.9.20"
"WinBuild"=dword:00004a65
"WinLangID"=dword:00000409
"ModernIconsColorized"=dword:00000000
"WelcomeShown"=dword:00000002
"Start_LargeMFUIcons"=dword:00000001
"StartMetroAppsMFU"=dword:00000001
"StartScreenShortcut"=dword:00000000
"Start_LargeAllAppsIcons"=dword:00000000
"StartMetroAppsFolder"=dword:00000001
"Start_SortFoldersFirst"=dword:00000000
"Start_NotifyNewApps"=dword:00000000
"Start_AutoCascade"=dword:00000000
"Start_AskCortana"=dword:00000000
"Start_RightPaneIcons"=dword:00000002
"Start_ShowUser"=dword:00000001
"Start_ShowMyDocs"=dword:00000001
"Start_ShowMyPics"=dword:00000001
"Start_ShowMyMusic"=dword:00000001
"Start_ShowVideos"=dword:00000000
"Start_ShowDownloads"=dword:00000001
"Start_ShowSkyDrive"=dword:00000000
"StartMenuFavorites"=dword:00000000
"Start_ShowRecentDocs"=dword:00000000
"Start_ShowNetPlaces"=dword:00000000
"Start_ShowNetConn"=dword:00000000
"Start_ShowMyComputer"=dword:00000001
"Start_ShowControlPanel"=dword:00000001
"Start_ShowPCSettings"=dword:00000001
"Start_AdminToolsRoot"=dword:00000000
"Start_ShowPrinters"=dword:00000000
"Start_ShowSetProgramAccessAndDefaults"=dword:00000000
"Start_ShowCommandPrompt"=dword:00000000
"Start_ShowRun"=dword:00000001
"Start_MinMFU"=dword:00000009
"Start_JumpListItems"=dword:0000000a
"StartMenuColor"=dword:ffffffff
"StartMenuBlur"=dword:00000001
"StartMenuAlpha"=dword:0000006f
"TaskbarAlpha"=dword:0000006f
"TaskbarBlur"=dword:00000001
"TaskbarColor"=dword:ffffffff
"AutoUpdates"=dword:00000000
"Disabled"=dword:00000000
"StartIsApps"=dword:00000000
"NoXAMLPrelaunch"=dword:00000001
"TerminateOnClose"=dword:00000001
"AllProgramsFlyout"=dword:00000000
"CombineWinX"=dword:00000001
"HideUserFrame"=dword:00000001
"TaskbarLargerIcons"=dword:00000000
"TaskbarSpacierIcons"=dword:fffffffe
"TaskbarJumpList"=dword:00000001
"HideOrb"=dword:00000000
"HideSecondaryOrb"=dword:00000000
"StartMenuMonitor"=dword:00000001
"ImmersiveMenus"=dword:ffffffff
"WinkeyFunction"=dword:00000000
"MetroHotkeyFunction"=dword:00000000
"MetroHotKey"=dword:0000000a
"OrbBitmap"="Windows 10"
"TaskbarStyle"="C:\\Program Files (x86)\\StartIsBack\\Styles\\Windows 10.msstyles"
"AlterStyle"="C:\\Program Files (x86)\\StartIsBack\\Styles\\Plain10.msstyles"
"AppsFolderIcon"=hex(2):73,00,68,00,65,00,6c,00,6c,00,33,00,32,00,2e,00,64,00,\
  6c,00,6c,00,2c,00,33,00,00,00
"SettingsVersion"=dword:00000005

[HKEY_CURRENT_USER\SOFTWARE\StartIsBack\Cache]
"IdealHeight.6"=dword:00000000
"IdealHeight.9"=dword:00020009
"IdealWidth.9"="Control Panel"

[HKEY_CURRENT_USER\SOFTWARE\StartIsBack\ShutdownChoices]
@=dword:00000002
"Switch user"=dword:00000100
"Sign out"=dword:00000001
"Lock"=dword:00000200
"Sleep"=dword:00000010
"Shut down"=dword:00000002
"Restart"=dword:00000004
"@
Set-Content -Path "$env:TEMP\StartIsBack.reg" -Value $MultilineComment -Force
# edit reg file
$path = "$env:TEMP\StartIsBack.reg"
(Get-Content $path) -replace "\?","$" | Out-File $path
# import reg file
Regedit.exe /S "$env:TEMP\StartIsBack.reg"
}

# StartAllBack
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
    choco install startallback -y --force                               
	# downlaod ROG orb                
	$URL  = "https://github.com/ManueITest/Accel/raw/main/Orbs/StartAllBack/rog.png"				
	$Dest = "C:\Program Files\StartAllBack\Orbs\rog.png"				
	Timeout /T 2 | Out-Null
	
	if (!(Test-Path -Path (Split-Path $Dest))) {
		New-Item -Path (Split-Path $Dest) -ItemType Directory -Force | Out-Null				
	}

	Get-FileFromWeb $URL $Dest
	Timeout /T 2 | Out-Null
	
# create reg file
$MultilineComment = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\StartIsBack]
"AutoUpdates"=dword:00000000
"WinBuild"=dword:000065f4
"WinLangID"=dword:00000409
"SettingsVersion"=dword:00000006
"WelcomeShown"=dword:00000003
"UpdateCheck"=hex:91,cc,1c,a1,f2,d2,db,01
"FrameStyle"=dword:00000000
"OrbBitmap"="C:\Program Files\StartAllBack\Orbs\rog.png"
"AlterStyle"=""
"TaskbarStyle"=""
"SysTrayStyle"=dword:00000000
"BottomDetails"=dword:00000000
"Start_LargeAllAppsIcons"=dword:00000000
"AllProgramsFlyout"=dword:00000000
"StartMetroAppsFolder"=dword:00000001
"Start_SortOverride"=dword:0000000a
"Start_NotifyNewApps"=dword:00000001
"Start_AutoCascade"=dword:00000001
"Start_LargeSearchIcons"=dword:00000000
"Start_AskCortana"=dword:00000000
"HideUserFrame"=dword:00000001
"Start_RightPaneIcons"=dword:00000002
"Start_ShowUser"=dword:00000001
"Start_ShowMyDocs"=dword:00000001
"Start_ShowMyPics"=dword:00000001
"Start_ShowMyMusic"=dword:00000001
"Start_ShowVideos"=dword:00000000
"Start_ShowDownloads"=dword:00000001
"Start_ShowSkyDrive"=dword:00000000
"StartMenuFavorites"=dword:00000000
"Start_ShowRecentDocs"=dword:00000000
"Start_ShowNetPlaces"=dword:00000000
"Start_ShowNetConn"=dword:00000000
"Start_ShowMyComputer"=dword:00000001
"Start_ShowControlPanel"=dword:00000001
"Start_ShowPCSettings"=dword:00000001
"Start_AdminToolsRoot"=dword:00000000
"Start_ShowPrinters"=dword:00000000
"Start_ShowSetProgramAccessAndDefaults"=dword:00000000
"Start_ShowTerminal"=dword:00000000
"Start_ShowCommandPrompt"=dword:00000000
"Start_ShowRun"=dword:00000001
"TaskbarLargerIcons"=dword:00000000
"TaskbarSpacierIcons"=dword:fffffffe
"TaskbarOneSegment"=dword:00000000
"TaskbarCenterIcons"=dword:00000000
"FatTaskbar"=dword:00000002
"TaskbarTranslucentEffect"=dword:00000000
"SysTrayClockFont"=hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,\
  00,00,00,00,00,00,00,00,00,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,\
  00,20,00,56,00,61,00,72,00,69,00,61,00,62,00,6c,00,65,00,20,00,53,00,6d,00,\
  61,00,6c,00,6c,00,00,00,00,64,00,00,00,00,00,00,1e,00,00,00,00,00,00,00
"SysTrayClockFormat"=dword:00000003
"StartMenuBlur"=dword:00000001
"TaskbarBlur"=dword:00000001
"StartMenuAlpha"=dword:00000065
"TaskbarAlpha"=dword:00000065
"AppsFolderIcon"=hex(2):73,00,68,00,65,00,6c,00,6c,00,33,00,32,00,2e,00,64,00,\
  6c,00,6c,00,2c,00,33,00,00,00
"Start_MinMFU"=dword:00000009
"SysTrayInputSwitch"=dword:00000000
"SysTrayVolume"=dword:00000001
"SysTrayNetwork"=dword:00000001

[HKEY_CURRENT_USER\Software\StartIsBack\Cache]
"OrbWidth.96"=dword:00000028
"OrbHeight.96"=dword:00000030
"IdealHeight.6"=dword:00000000
"IdealHeight.9"=dword:00020009
"IdealWidth.9"="Control Panel"

[HKEY_CURRENT_USER\Software\StartIsBack\DarkMagic]

[HKEY_CURRENT_USER\Software\StartIsBack\Taskbaz]
"Toolbars"=hex:0c,00,00,00,08,00,00,00,01,00,00,00,00,00,00,00,aa,4f,28,68,48,\
  6a,d0,11,8c,78,00,c0,4f,d9,18,b4,00,00,00,00,40,0d,00,00,00,00,00,00,30,00,\
  00,00,00,00,00,00,00,00,00,00,30,00,00,00,00,00,00,00,01,00,00,00
"Settings"=hex:30,00,00,00,fe,ff,ff,ff,02,00,00,00,03,00,00,00,38,00,00,00,30,\
  00,00,00,00,00,00,00,08,04,00,00,80,07,00,00,38,04,00,00,60,00,00,00,01,00,\
  00,00

[HKEY_CURRENT_USER\Software\StartIsBack\Recolor]
"@
Set-Content -Path "$env:TEMP\StartAllBack.reg" -Value $MultilineComment -Force
# edit reg file
$path = "$env:TEMP\StartAllBack.reg"
(Get-Content $path) -replace "\?","$" | Out-File $path
# import reg file
Regedit.exe /S "$env:TEMP\StartAllBack.reg"
}

else { $null }
# ----------------------------------------------------------

# ADVANCED

<#
# Remove Windows 11 'Get Started' and Windows 10/11 'Windows Backup' Apps
if (-not (Get-InstalledModule MySQLite -ErrorAction Ignore)) {Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null; Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null; Install-Module MySQLite -Repository PSGallery -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}; Import-Module MySQLite -Force -ErrorAction SilentlyContinue | Out-Null

function Unlock-Package {param([string]$p) takeown /f "C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd" /a | Out-Null; takeown /f "C:\ProgramData\Microsoft\Windows\AppRepository" /a | Out-Null; icacls "C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd" /grant "Administrators:F" | Out-Null; icacls "C:\ProgramData\Microsoft\Windows\AppRepository" /grant "Administrators:(OI)(CI)F" | Out-Null; Stop-Service StateRepository -Force; Copy-Item "C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd" "C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd.bak" -Force; Copy-Item "C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd" "C:\Windows\Temp\" -Force; Invoke-MySQLiteQuery -Path "C:\Windows\Temp\StateRepository-Machine.srd" -Query "DROP TRIGGER IF EXISTS TRG_AFTERUPDATE_Package_SRJournal"; Invoke-MySQLiteQuery -Path "C:\Windows\Temp\StateRepository-Machine.srd" -Query "UPDATE Package SET IsInbox=0 WHERE PackageFullName LIKE '%$p%'"; Copy-Item "C:\Windows\Temp\StateRepository-Machine.srd" "C:\ProgramData\Microsoft\Windows\AppRepository\" -Force; Start-Service StateRepository}

function Remove-App-From-Package {param([string]$a,[string]$p) $pkg=Get-AppxPackage -Name "*$p*"; $xmlPath=$pkg.InstallLocation+"\AppxManifest.xml"; $xml=[xml](Get-Content $xmlPath); $n=$xml.Package.Applications.Application|? Id -eq $a; if ($n){$n.ParentNode.RemoveChild($n)|Out-Null}; $xml.Save("C:\Windows\Temp\appxmanifest.xml"); takeown /f $pkg.InstallLocation /a | Out-Null; takeown /f $xmlPath /a | Out-Null; icacls $pkg.InstallLocation /grant "Administrators:(OI)(CI)F" | Out-Null; icacls $xmlPath /grant "Administrators:F" | Out-Null; Copy-Item "C:\Windows\Temp\appxmanifest.xml" $xmlPath -Force}

function Restart-Package {param([string]$p) Unlock-Package $p; $pkg=Get-AppxPackage -Name "*$p*"; $xmlPath=$pkg.InstallLocation+"\AppxManifest.xml"; $pkg|Remove-AppxPackage -ErrorAction SilentlyContinue; Add-AppxPackage -DisableDevelopmentMode -Register $xmlPath -ErrorAction SilentlyContinue; Start-Sleep 1}

Remove-App-From-Package "WebExperienceHost" "MicrosoftWindows.Client.CBS"; Remove-App-From-Package "WindowsBackup" "MicrosoftWindows.Client.CBS"; Restart-Package "MicrosoftWindows.Client.CBS"; Start-Sleep 1; Timeout /T 1 | Out-Null
# ----------------------------------------------------------



# ----------------------------------------------------------
# --------------------Network Tweaks------------------------
# ----------------------------------------------------------
Write-Host "	Applying Network Tweaks"
try {
    $adapters = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.GUID } | Select-Object -ExpandProperty GUID

    foreach ($guid in $adapters) {
        $regPath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"

        New-ItemProperty -Path $regPath -Name "TcpAckFrequency" -PropertyType DWord -Value 1 -Force | Out-Null -ErrorAction SilentlyContinue
        New-ItemProperty -Path $regPath -Name "TcpDelAckTicks" -PropertyType DWord -Value 0 -Force | Out-Null -ErrorAction SilentlyContinue
        New-ItemProperty -Path $regPath -Name "TCPNoDelay" -PropertyType DWord -Value 1 -Force | Out-Null -ErrorAction SilentlyContinue
    }

    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterBinding -Name $_.Name -ComponentID ms_msclient -Enabled $false | Out-Null -ErrorAction SilentlyContinue
        Set-NetAdapterBinding -Name $_.Name -ComponentID ms_server -Enabled $false | Out-Null -ErrorAction SilentlyContinue
    }
}
catch {}
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------------------BCDEdit Tweaks------------------------
# ----------------------------------------------------------
# Remove the 'useplatformclock' boot configuration value
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/deletevalue useplatformclock" -WindowStyle Hidden -Wait
# Note: 'useplatformtick yes' can improve performance but may cause instability
# Set 'useplatformtick' to 'no'
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set useplatformtick no" -WindowStyle Hidden -Wait
# Set 'disabledynamictick' to 'yes'
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set disabledynamictick yes" -WindowStyle Hidden -Wait # try value "no"
# Hide the boot logo for a cleaner boot experience
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set quietboot Yes" -WindowStyle Hidden -Wait
# Disable the boot animation (bootux)
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set bootux Disabled" -WindowStyle Hidden -Wait
# Disable boot logging (no bootlog.txt created)
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set bootlog no" -WindowStyle Hidden -Wait
# Set the boot menu timeout to 10 seconds
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/timeout 10" -WindowStyle Hidden -Wait
# Disable event logging during boot
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/event off" -WindowStyle Hidden -Wait
# Disable boot debugging (for normal users, not needed)
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/bootdebug off" -WindowStyle Hidden -Wait
# Disable kernel debugging
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set debug No" -WindowStyle Hidden -Wait
# Disable Emergency Management Services (EMS)
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set ems No" -WindowStyle Hidden -Wait
# Disable EMS during boot
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set bootems No" -WindowStyle Hidden -Wait
# Disable Hyper-V (virtualization platform, required for WSL2/VMware/VirtualBox acceleration)
# Only use this if you do NOT need virtualization features
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set hypervisorlaunchtype Off" -WindowStyle Hidden -Wait
# Set the TSC synchronization policy to 'enhanced' for improved timing synchronization
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set tscsyncpolicy enhanced" -WindowStyle Hidden -Wait
# Disable legacy APIC mode by setting 'uselegacyapicmode' to 'No'
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set uselegacyapicmode No" -WindowStyle Hidden -Wait
# Remove the 'useplatformtick' setting from the boot configuration if it exists
# Start-Process -FilePath "bcdedit.exe" -ArgumentList "/deletevalue useplatformtick" -WindowStyle Hidden -Wait
# ----------------------------------------------------------


# ----------------------------------------------------------
# -------------Disable power saving features----------------
# ----------------------------------------------------------
# https://docs.atlasos.net/getting-started/post-installation/atlas-folder/general-configuration/#system-restore

param (
    [switch]$Silent
)

# Detect if running on a laptop (PCSystemType 2 = Laptop)
$isLaptop = (Get-CimInstance -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType -eq 2

if ($isLaptop) {
    if (!$Silent) {
        Write-Host @"
WARNING: You are on a laptop, disabling power saving will cause faster battery drainage and increased heat output.
If you use your laptop on battery, certain power saving features will enable, but not all.
Generally, it's NOT recommended to run aggressive power saving tweaks on laptops.`n
"@ -ForegroundColor Yellow
        Start-Sleep 2
    }
    # Only disable USB selective suspend (not display, CPU, NVMe, etc.)
    powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
	# Disable power throttling
	$powerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
	if (!(Test-Path $powerKey)) { New-Item $powerKey | Out-Null }
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -PropertyType DWORD -Force | Out-Null
	# Enable Hibernation
	powercfg /h on *> $null

    if ($Silent) { return }
    return
} else {

## Secondary NVMe Idle Timeout - 0 miliseconds
powercfg /setacvalueindex scheme_current 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 0
## Primary NVMe Idle Timeout - 0 miliseconds
powercfg /setacvalueindex scheme_current 0012ee47-9041-4b5d-9b77-535fba8b1442 d639518a-e56d-4345-8af2-b9f32fb26109 0
## NVME NOPPME - Off
powercfg /setacvalueindex scheme_current 0012ee47-9041-4b5d-9b77-535fba8b1442 fc7372b6-ab2d-43ee-8797-15e9841f2cca 0
## Allow Throttle States - Off
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0
## Dim display after - 0 seconds
powercfg /setacvalueindex scheme_current 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
## Processor performance time check interval - 200 miliseconds
## Reduces DPCs, can be set all the way to 5000ms for statically clocked systems
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 200

Write-Host "	Disabling network adapter power-saving"
$properties = Get-NetAdapter -Physical | Get-NetAdapterAdvancedProperty
foreach ($setting in @(
    # Stands for Ultra Low Power
    "ULPMode",

    # Energy Efficient Ethernet
    "EEE",
    "EEELinkAdvertisement",
    "AdvancedEEE",
    "EnableGreenEthernet",
    "EeePhyEnable",

    # Wi-Fi capability that saves power consumption
    "uAPSDSupport",

    # Self-explanatory
    "EnablePowerManagement",
    "EnableSavePowerNow",
    "bLowPowerEnable",
    "PowerSaveMode",
    "PowerSavingMode",
    "SavePowerNowEnabled",
    "AutoPowerSaveModeEnabled",
    "NicAutoPowerSaver",
    "SelectiveSuspend"
)) {
    $properties | Where-Object { $_.RegistryKeyword -eq "*$setting" -or $_.RegistryKeyword -eq $setting } | Set-NetAdapterAdvancedProperty -RegistryValue 0
}

# https://discord.com/channels/1298592513816530994/1359513721738629140/1359524213047824517
# disables power saving features for all devices (that support power saving) in Device Manager.
# get all USB ROOT devices
Write-Host "	Disabling device power-saving"
$devicesUSB = Get-PnpDevice | Where-Object { $_.InstanceId -like "*USB\ROOT*" }
# disable each device
foreach ($device in $devicesUSB) {
    try {
        Set-CimInstance -Namespace root\wmi `
            -Query "SELECT * FROM MSPower_DeviceEnable WHERE InstanceName LIKE '%$($device.PNPDeviceID)%'" `
            -Property @{Enable = $false} `
            -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

Write-Host "	Disabling miscellaneous power-saving"
# Disable D3 support on SATA/NVMEs while using Modern Standby
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Storage" -Name "StorageD3InModernStandby" -Value 0 -PropertyType DWORD -Force | Out-Null
# Disable IdlePowerMode for stornvme.sys (storage devices) - the device will never enter a low-power state
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" -Name "IdlePowerMode" -Value 0 -PropertyType DWORD -Force | Out-Null
# Disable power throttling
$powerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
if (!(Test-Path $powerKey)) { New-Item $powerKey | Out-Null }
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -PropertyType DWORD -Force | Out-Null

    if ($Silent) { return }
}
# ----------------------------------------------------------
#>



# Cleanup
Clear-Host
# clear %temp% folder
Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
# clear temp folder
Remove-Item -Path "$env:SystemDrive\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
# run disk cleanup
cleanmgr.exe /d C: /VERYLOWDISK
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase -ErrorAction SilentlyContinue | Out-Null
# close the overlay window and clean up
$form.Invoke({ $form.Close() })
# reboot
shutdown.exe /r /t 5 /f /c "System maintenance in progress"
#######################
