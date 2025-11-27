:: Made by Quaked
:: TikTok: _Quaked_
:: Discord: https://discord.gg/8NqDSMzYun

@echo off
title Service Destroyer V1.2
color 9

:: Check for Admin Privileges.
fltmc >nul 2>&1
if not %errorlevel% == 0 (
    Powershell -NoProfile -Command "Write-Host 'Service Destroyer is required to be run as *Administrator.*' -ForegroundColor White -BackgroundColor Red" 
    Powershell -NoProfile -Command "Write-Host 'Please Click *Yes* to the following prompt!' -ForegroundColor White -BackgroundColor Red" 
    timeout 3 > nul
    Powershell -NoProfile Start -Verb RunAs '%0'
    exit /b 0
)

:: Creating Backup Folder.
mkdir "C:\Service Destroyer\Reg Backup" >nul 2>&1

:: Creating Services Reg Backup.
reg export "HKLM\System\CurrentControlSet\Services" "C:\Service Destroyer\Reg Backup\ServicesBackup.reg" /y >nul 2>&1
if errorlevel 1 (
    Powershell -NoProfile -Command "Write-Host 'Service Destroyer failed to create a *ServicesBackup.reg*' -ForegroundColor White -BackgroundColor Red" 
    Powershell -NoProfile -Command "Write-Host 'You won''t be able to easily revert *Services* back, unless you create a restore point.' -ForegroundColor White -BackgroundColor Red"
    Powershell -NoProfile -Command "Write-Host 'Do you want to continue and rely on a restore point?' -ForegroundColor White -BackgroundColor Red" 
    echo.  
    call :BackupFailed
    goto :SDSS 
) else ( 
    echo Service Destroyer Reg Backup created successfully. >nul 2>&1
    goto :SDSS 
)

:: Backup Failed Handing.
:BackupFailed
chcp 65001 >nul 2>&1
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" (
    cls
    exit /b
) else if /i "%choice%"=="N" (
    cls
    color A
    echo ╔═══════════════════════════════╗
    echo ║ ✅ Exiting Service Destroyer. ║
    echo ╚═══════════════════════════════╝
    echo • Smart decision, now closing Service Destroyer in 5 seconds!
    timeout 5 > nul
    exit
) else (
    cls
    chcp 437 >nul
    Powershell -NoProfile -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 2 > nul
    cls
    goto :BackupFailed
)

:: Service Destroyer Start Screen.
:SDSS
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
echo.                                   ███████╗███████╗██████╗ ██╗   ██╗██╗ ██████╗███████╗
echo.                                   ██╔════╝██╔════╝██╔══██╗██║   ██║██║██╔════╝██╔════╝
echo.                                   ███████╗█████╗  ██████╔╝██║   ██║██║██║     █████╗  
echo.                                   ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║██║     ██╔══╝  
echo.                                   ███████║███████╗██║  ██║ ╚████╔╝ ██║╚██████╗███████╗
echo.                                   ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝                             
echo.                                                                   
echo.                        ██████╗ ███████╗███████╗████████╗██████╗  ██████╗ ██╗   ██╗███████╗██████╗ 
echo.                        ██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
echo.                        ██║  ██║█████╗  ███████╗   ██║   ██████╔╝██║   ██║ ╚████╔╝ █████╗  ██████╔╝
echo.                        ██║  ██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║   ██║  ╚██╔╝  ██╔══╝  ██╔══██╗
echo.                        ██████╔╝███████╗███████║   ██║   ██║  ██║╚██████╔╝   ██║   ███████╗██║  ██║
echo.                        ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
echo. 
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║              Version 1.2 - By Quaked               ║
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.
echo. 
echo. ╔═════════╗                                                                        
echo. ║ Loading ║                                              
echo. ╚═════════╝
timeout 2 > nul

:: Restore Point. (Allows the user to revert changes)
:Restore_Point
cls
color D
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.                                 ██▀███  ▓█████   ██████ ████████▓ ▒█████   ██▀███  ▓█████ 
echo.                                ▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ 
echo.                                ▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒▒███   
echo.                                ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ 
echo.                                ░██▓ ▒██▒░▒████▒▒██████▒▒  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒░▒████▒
echo.                                ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░
echo.                                  ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░    ░      ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░
echo.                                  ░░   ░    ░   ░  ░  ░    ░      ░ ░ ░ ▒    ░░   ░    ░   
echo.                                   ░        ░  ░      ░               ░ ░     ░        ░  ░
echo. 
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║   Create a restore point to undo system changes.   ║
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.
echo.
echo.                                                                     
chcp 437 >nul
Powershell -NoProfile -Command "Write-Host '[Highly Recommended]' -ForegroundColor Green"
chcp 65001 >nul 2>&1
echo → Do you want to make a restore point?
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" (
    cls
    goto :Check_Windows_Drive
) else if /i "%choice%"=="N" (
    cls
    goto :No_Restore_Point
) else (
    cls
    chcp 437 >nul
    Powershell -NoProfile -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 2 > nul
    goto :Restore_Point
)

:: Check for Main Windows Drive.
:Check_Windows_Drive
setlocal enabledelayedexpansion
color A
chcp 65001 >nul 2>&1
echo ╔══════════════════════════════════╗
echo ║ 🔄 Detecting Main Windows Drive. ║
echo ╚══════════════════════════════════╝
chcp 437 >nul
for /f %%S in ('Powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable('SystemDrive')"') do (
    set "SystemDrive=%%S"
)
chcp 65001 >nul 2>&1
echo • Main Windows Drive: 💾 !SystemDrive!
echo. 
echo → Applying System Restore Registry Tweaks.
echo ✅ The operation completed successfully.
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f >nul 2>&1 
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
echo.
echo → Enabling System Restore Services.
echo ✅ [SC] ChangeServiceConfig SUCCESS.
sc config VSS start=demand >nul 2>&1
sc config swprv start=demand >nul 2>&1
echo.
echo → Enabling System Protection.
chcp 437 >nul
Powershell -NoProfile -Command "try { $ErrorActionPreference='Stop'; Enable-ComputerRestore -Drive '!SystemDrive!\' ; exit 0 } catch { exit 1 }" >nul 2>&1
set "SP_Error=%ERRORLEVEL%"
chcp 65001 >nul
if %SP_Error% NEQ 0 ( 
    cls
    color C
    echo ❌ Could not enable System Protection on 💾 !SystemDrive!
    timeout 2 > nul 
    goto :Restore_Failure
) else (
    echo ✅ System Protection successfully enabled on 💾 !SystemDrive!
    timeout 2 > nul 
)
endlocal

:: System Restore Point Creation.
echo.
echo → Creating System Restore Point.
chcp 437 >nul
Powershell -NoProfile -Command "try { $ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; Checkpoint-Computer -Description 'Service Destroyer V1.2 Restore Point'; exit 0 } catch { exit 1 }" >nul 2>&1
set "RP_Error=%ERRORLEVEL%"
chcp 65001 >nul 2>&1
if %RP_Error% neq 0 (
    cls
    color C
    echo ❌ Failed to create System Restore Point.
    timeout 2 > nul
    goto :Restore_Failure
) else (
    chcp 65001 >nul 2>&1
    echo ✅ System Restore Point created successfully.
    timeout 2 > nul
    goto :Disabling_Services
)

:: System Protection/Restore Point Failure.
:Restore_Failure
cls
color C
chcp 65001 >nul 2>&1
echo ╔═════════════════════════════════════════════════════╗
echo ║ ⚠️  Your System Protection or Restore Point FAILED. ║
echo ╚═════════════════════════════════════════════════════╝
echo ❌ You won't be able to revert system changes without one!
echo.
echo → Do you still wish to continue? (LAST WARNING)
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" (
    cls
    echo ╔═══════════════════╗
    echo ║ ❌ Not Restoring. ║
    echo ╚═══════════════════╝
    echo • Questionable decision, now continuing with Service Destroyer.
    timeout 2 > nul
    goto :Disabling_Services
) else if /i "%choice%"=="N" (
    cls
    color A
    echo ╔═══════════════════════════════╗
    echo ║ ✅ Exiting Service Destroyer. ║
    echo ╚═══════════════════════════════╝
    echo • Smart decision, now closing Service Destroyer in 5 seconds!
    timeout 5 > nul
    exit
) else (
    cls
    chcp 437 >nul
    Powershell -NoProfile -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 2 > nul
    cls
    goto :Restore_Failure
)

:: No Restore Point Selected.
:No_Restore_Point
cls
color C
chcp 65001 >nul 2>&1
echo ╔═══════════════════════════════════════╗
echo ║ ⚠️ Not Creating System Restore Point. ║
echo ╚═══════════════════════════════════════╝
echo ❌ You won't be able to revert system changes without one!
echo.
echo → Do you still wish to continue? (LAST WARNING)
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" (
    cls
    echo ╔═══════════════════╗
    echo ║ ❌ Not Restoring. ║
    echo ╚═══════════════════╝
    echo • Questionable decision, now continuing with Service Destroyer.
    timeout 2 > nul
    goto :Disabling_Services
) else if /i "%choice%"=="N" (
    cls
    color A
    echo ╔═══════════════════════════════╗
    echo ║ ✅ Exiting Service Destroyer. ║
    echo ╚═══════════════════════════════╝
    echo • Smart decision, now closing Service Destroyer in 2 seconds!
    timeout 2 > nul
    exit
) else (
    cls
    chcp 437 >nul
    Powershell -NoProfile -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 2 > nul
    cls
    goto :No_Restore_Point
)

:: Disabling Services.
:Disabling_Services
cls
color 9
chcp 65001 >nul 2>&1
echo ╔════════════════════════╗
echo ║ ✅ Disabling Services. ║
echo ╚════════════════════════╝
timeout 1 > nul

:: Windows Services.
sc config AarSvc start=disabled
sc config ADPSvc start=disabled >nul 2>&1  
sc config AJRouter start=disabled >nul 2>&1
sc config ALG start=disabled
sc config Appinfo start=disabled
sc config AppMgmt start=disabled >nul 2>&1
sc config AppReadiness start=disabled
sc config AssignedAccessManagerSvc start=disabled >nul 2>&1
sc config autotimesvc start=disabled
sc config AxInstSV start=disabled
sc config BDESVC start=disabled
sc config BITS start=disabled   
sc config BTAGService start=disabled
sc config BthAvctpSvc start=disabled
sc config bthserv start=disabled 
sc config CDPSvc start=disabled
sc config CertPropSvc start=disabled
sc config cloudidsvc start=demand >nul 2>&1 
sc config COMSysApp start=disabled
sc config CscService start=disabled >nul 2>&1
sc config dcsvc start=disabled
sc config defragsvc start=demand 
sc config DeviceAssociationService start=disabled
sc config DeviceInstall start=disabled
sc config DevQueryBroker start=disabled
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
sc config DiagTrack start=disabled
sc config diagsvc start=disabled
sc config DispBrokerDesktopSvc start=disabled
sc config DisplayEnhancementService start=disabled
sc config DmEnrollmentSvc start=disabled
sc config dmwappushservice start=disabled  
sc config dot3svc start=disabled
sc config DPS start=disabled  
sc config DsmSvc start=disabled
sc config DsSvc start=disabled 
sc config DusmSvc start=disabled  
sc config Eaphost start=disabled
sc config edgeupdate start=disabled
sc config edgeupdatem start=disabled
sc config EFS start=disabled
sc config EventLog start=disabled
sc config EventSystem start=disabled
sc config fdPHost start=disabled 
sc config FDResPub start=disabled 
sc config fhsvc start=disabled 
sc config FontCache start=disabled 
sc config FrameServer start=disabled
sc config FrameServerMonitor start=disabled 
sc config GameInputSvc start=disabled >nul 2>&1
sc config GraphicsPerfSvc start=disabled
sc config hpatchmon start=disabled >nul 2>&1
sc config HvHost start=disabled
sc config icssvc start=disabled 
sc config IKEEXT start=disabled 
sc config InstallService start=disabled  
sc config InventorySvc start=disabled
sc config IpxlatCfgSvc start=disabled
sc config KtmRm start=disabled
sc config LanmanServer start=disabled
sc config LanmanWorkstation start=disabled
sc config lfsvc start=disabled
sc config LocalKdc start=disabled
sc config LicenseManager start=disabled 
sc config lltdsvc start=disabled 
sc config lmhosts start=disabled 
sc config LxpSvc start=disabled  
sc config MapsBroker start=disabled  
sc config McpManagementService start=disabled >nul 2>&1 
sc config MicrosoftEdgeElevationService start=disabled  
sc config MSDTC start=disabled
sc config MSiSCSI start=disabled
sc config NaturalAuthentication start=disabled
sc config NcaSvc start=disabled
sc config NcbService start=disabled
sc config NcdAutoSetup start=disabled
sc config Netlogon start=disabled
sc config Netman start=disabled
sc config NetSetupSvc start=disabled
sc config NetTcpPortSharing start=disabled 
sc config NlaSvc start=disabled  
sc config p2pimsvc start=disabled >nul 2>&1
sc config p2psvc start=disabled >nul 2>&1
sc config PcaSvc start=disabled 
sc config PeerDistSvc start=disabled >nul 2>&1    
sc config perceptionsimulation start=disabled 
sc config PerfHost start=disabled
sc config PhoneSvc start=disabled
sc config pla start=disabled 
sc config PNRPAutoReg start=disabled >nul 2>&1
sc config PNRPsvc start=disabled >nul 2>&1
sc config PolicyAgent start=disabled
sc config PrintDeviceConfigurationService start=disabled >nul 2>&1
sc config PrintNotify start=disabled 
sc config PrintScanBrokerService start=disabled >nul 2>&1 
sc config PushToInstall start=disabled
sc config QWAVE start=disabled
sc config RasAuto start=disabled
sc config RasMan start=disabled
sc config refsdedupsvc start=disabled >nul 2>&1 
sc config RemoteAccess start=disabled 
sc config RemoteRegistry start=disabled 
sc config RetailDemo start=disabled 
sc config RmSvc start=disabled    
sc config RpcLocator start=disabled   
sc config SamSs start=disabled
sc config SCardSvr start=disabled
sc config ScDeviceEnum start=disabled     
sc config SCPolicySvc start=disabled
sc config SDRSVC start=disabled
sc config seclogon start=disabled  
sc config SENS start=disabled
sc config Sense start=disabled >nul 2>&1
sc config SensorDataService start=disabled
sc config SensorService start=disabled
sc config SensrSvc start=disabled
sc config SEMgrSvc start=disabled
sc config SessionEnv start=disabled
sc config SharedAccess start=disabled  
sc config SharedRealitySvc start=disabled >nul 2>&1
sc config ShellHWDetection start=disabled 
sc config shpamsvc start=disabled
sc config SmsRouter start=disabled
sc config smphost start=disabled
sc config SNMPTrap start=disabled
sc config Spooler start=disabled
sc config SSDPSRV start=disabled
sc config ssh-agent start=disabled
sc config SstpSvc start=disabled 
sc config stisvc start=disabled
sc config StorSvc start=disabled 
sc config svsvc start=disabled
sc config SysMain start=disabled
sc config TapiSrv start=disabled
sc config TermService start=disabled
sc config Themes start=disabled
sc config TieringEngineService start=disabled 
sc config TokenBroker start=disabled
sc config TrkWks start=disabled 
sc config TroubleshootingSvc start=disabled
sc config tzautoupdate start=disabled
sc config UevAgentService start=disabled >nul 2>&1   
sc config uhssvc start=disabled >nul 2>&1  
sc config UmRdpService start=disabled 
sc config upnphost start=disabled
sc config VacSvc start=demand >nul 2>&1
sc config VaultSvc start=disabled
sc config vds start=disabled
sc config vmicguestinterface start=disabled 
sc config vmicheartbeat start=disabled
sc config vmickvpexchange start=disabled 
sc config vmicrdv start=disabled
sc config vmicshutdown start=disabled
sc config vmictimesync start=disabled
sc config vmicvmsession start=disabled
sc config vmicvss start=disabled 
sc config W32Time start=disabled  
sc config WalletService start=disabled
sc config WarpJITSvc start=disabled
sc config wbengine start=disabled
sc config WbioSrvc start=disabled
sc config Wcmsvc start=disabled
sc config wcncsvc start=disabled  
sc config WdiServiceHost start=disabled
sc config WdiSystemHost start=disabled
sc config WebClient start=disabled
sc config webthreatdefsvc start=disabled
sc config Wecsvc start=disabled 
sc config WEPHOSTSVC start=disabled
sc config wercplsupport start=disabled
sc config WerSvc start=disabled
sc config WFDSConMgrSvc start=disabled 
sc config whesvc start=disabled >nul 2>&1
sc config WiaRpc start=disabled 
sc config WinRM start=disabled
sc config wisvc start=disabled 
sc config WlanSvc start=disabled
sc config wlidsvc start=disabled
sc config wlpasvc start=disabled
sc config WManSvc start=disabled  
sc config wmiApSrv start=disabled
sc config WMPNetworkSvc start=disabled
sc config workfolderssvc start=disabled
sc config WpcMonSvc start=disabled
sc config WPDBusEnum start=disabled
sc config WpnService start=disabled
sc config WSAIFabricSvc start=disabled >nul 2>&1
sc config WSearch start=disabled
sc config WwanSvc start=disabled  
sc config XblAuthManager start=disabled
sc config XblGameSave start=disabled
sc config XboxGipSvc start=disabled
sc config XboxNetApiSvc start=disabled

:: Windows Services Regs.
reg add "HKLM\System\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\embeddedmode" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\P9RdrService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\PenService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f

:: Deleting Services.
reg delete "HKLM\System\CurrentControlSet\Services\CryptSvc" /f
reg delete "HKLM\System\CurrentControlSet\Services\wuauserv" /f
reg delete "HKLM\System\CurrentControlSet\Services\WaaSMedicSvc" /f
reg delete "HKLM\System\CurrentControlSet\Services\UsoSvc" /f

:: If exist Service checks. (Avoids adding services to the reg if they don't exist on other win versions)
reg query "HKLM\System\CurrentControlSet\Services\CloudBackupRestoreSvc" >nul 2>&1
if %errorlevel%==0 (
    reg add "HKLM\System\CurrentControlSet\Services\CloudBackupRestoreSvc" /v "Start" /t REG_DWORD /d "4" /f
)
reg query "HKLM\System\CurrentControlSet\Services\NPSMSvc" >nul 2>&1
if %errorlevel%==0 (
    reg add "HKLM\System\CurrentControlSet\Services\NPSMSvc" /v "Start" /t REG_DWORD /d "4" /f
)

:: Spliting svchost.exe processes, based on RAM capacity in KB. 
chcp 437 >nul 
for /f %%R in ('Powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB) * 1024 * 1024"') do set "Ram_Amount_KB=%%R"
reg add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d %Ram_Amount_KB% /f
chcp 65001 >nul 2>&1

:: UAC (When Application Information Service is disabled, apps can't request admin permissions how disabling UAC fixes this) 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 >nul 2>&1

echo ✔  Services disabled successfully.
timeout 2 > nul

:: Service Destroyer End Screen.
cls
color D
chcp 65001 >nul 2>&1
echo ╔════════════════════════════╗
echo ║ ✅ Service Destroyer Done! ║
echo ╚════════════════════════════╝
echo ✔  Now Restarting in 5 seconds
timeout 5 > nul
shutdown /r /t 0 