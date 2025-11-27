@echo off
:: https://privacy.sexy — v0.13.8 — Wed, 26 Nov 2025 00:09:42 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: -----------Disable Edge diagnostic data sending-----------
:: ----------------------------------------------------------
echo --- Disable Edge diagnostic data sending
:: Configure "DiagnosticData" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!DiagnosticData"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DiagnosticData' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable outdated Edge metrics data sending--------
:: ----------------------------------------------------------
echo --- Disable outdated Edge metrics data sending
:: Configure "MetricsReportingEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!MetricsReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'MetricsReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable outdated Edge site information sending------
:: ----------------------------------------------------------
echo --- Disable outdated Edge site information sending
:: Configure "SendSiteInfoToImproveServices" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SendSiteInfoToImproveServices"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SendSiteInfoToImproveServices' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Edge Feedback-------------------
:: ----------------------------------------------------------
echo --- Disable Edge Feedback
:: Configure "UserFeedbackAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!UserFeedbackAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'UserFeedbackAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge spotlight recommendations----------
:: ----------------------------------------------------------
echo --- Disable Edge spotlight recommendations
:: Configure "SpotlightExperiencesAndRecommendationsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SpotlightExperiencesAndRecommendationsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SpotlightExperiencesAndRecommendationsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Edge feature ads-----------------
:: ----------------------------------------------------------
echo --- Disable Edge feature ads
:: Configure "ShowRecommendationsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowRecommendationsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowRecommendationsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Edge Bing ads-------------------
:: ----------------------------------------------------------
echo --- Disable Edge Bing ads
:: Configure "BingAdsSuppression" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!BingAdsSuppression"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BingAdsSuppression' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge promotional pages--------------
:: ----------------------------------------------------------
echo --- Disable Edge promotional pages
:: Configure "PromotionalTabsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!PromotionalTabsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'PromotionalTabsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Edge browsing history collection for ads-----
:: ----------------------------------------------------------
echo --- Disable Edge browsing history collection for ads
:: Configure "PersonalizationReportingEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!PersonalizationReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'PersonalizationReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Edge Insider ads-----------------
:: ----------------------------------------------------------
echo --- Disable Edge Insider ads
:: Configure "MicrosoftEdgeInsiderPromotionEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!MicrosoftEdgeInsiderPromotionEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'MicrosoftEdgeInsiderPromotionEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Adobe Acrobat subscription ads--------
:: ----------------------------------------------------------
echo --- Disable Edge Adobe Acrobat subscription ads
:: Configure "ShowAcrobatSubscriptionButton" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowAcrobatSubscriptionButton"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowAcrobatSubscriptionButton' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Edge top sites and sponsored links on new tab page
echo --- Disable Edge top sites and sponsored links on new tab page
:: Configure "NewTabPageHideDefaultTopSites" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageHideDefaultTopSites"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageHideDefaultTopSites' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Enable Edge tracking prevention--------------
:: ----------------------------------------------------------
echo --- Enable Edge tracking prevention
:: Configure "TrackingPrevention" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!TrackingPrevention"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '3'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'TrackingPrevention' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Block Edge third party cookies--------------
:: ----------------------------------------------------------
echo --- Block Edge third party cookies
:: Configure "BlockThirdPartyCookies" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!BlockThirdPartyCookies"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BlockThirdPartyCookies' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Enable Do Not Track requests---------------
:: ----------------------------------------------------------
echo --- Enable Do Not Track requests
:: Configure "ConfigureDoNotTrack" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ConfigureDoNotTrack"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ConfigureDoNotTrack' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Edge Follow feature----------------
:: ----------------------------------------------------------
echo --- Disable Edge Follow feature
:: Configure "EdgeFollowEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeFollowEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeFollowEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Edge Shopping Assistant--------------
:: ----------------------------------------------------------
echo --- Disable Edge Shopping Assistant
:: Configure "EdgeShoppingAssistantEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeShoppingAssistantEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeShoppingAssistantEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Edge Search bar on desktop------------
:: ----------------------------------------------------------
echo --- Disable Edge Search bar on desktop
:: Configure "WebWidgetAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!WebWidgetAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'WebWidgetAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "WebWidgetIsEnabledOnStartup" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!WebWidgetIsEnabledOnStartup"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'WebWidgetIsEnabledOnStartup' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "SearchbarAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchbarAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchbarAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "SearchbarIsEnabledOnStartup" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchbarIsEnabledOnStartup"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchbarIsEnabledOnStartup' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge Microsoft Rewards--------------
:: ----------------------------------------------------------
echo --- Disable Edge Microsoft Rewards
:: Configure "ShowMicrosoftRewards" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowMicrosoftRewards"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowMicrosoftRewards' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Bing suggestions in address bar-------
:: ----------------------------------------------------------
echo --- Disable Edge Bing suggestions in address bar
:: Configure "AddressBarMicrosoftSearchInBingProviderEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AddressBarMicrosoftSearchInBingProviderEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AddressBarMicrosoftSearchInBingProviderEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge "Find on Page" data collection--------
:: ----------------------------------------------------------
echo --- Disable Edge "Find on Page" data collection
:: Configure "RelatedMatchesCloudServiceEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!RelatedMatchesCloudServiceEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'RelatedMatchesCloudServiceEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge sign-in prompt on new tab page--------
:: ----------------------------------------------------------
echo --- Disable Edge sign-in prompt on new tab page
:: Configure "SignInCtaOnNtpEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SignInCtaOnNtpEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SignInCtaOnNtpEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Edge search and site suggestions---------
:: ----------------------------------------------------------
echo --- Disable Edge search and site suggestions
:: Configure "SearchSuggestEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchSuggestEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchSuggestEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable outdated Edge automatic image enhancement-----
:: ----------------------------------------------------------
echo --- Disable outdated Edge automatic image enhancement
:: Configure "EdgeEnhanceImagesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeEnhanceImagesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeEnhanceImagesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge quick links on the new tab page-------
:: ----------------------------------------------------------
echo --- Disable Edge quick links on the new tab page
:: Configure "NewTabPageQuickLinksEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageQuickLinksEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageQuickLinksEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable Edge remote background images on new tab page---
:: ----------------------------------------------------------
echo --- Disable Edge remote background images on new tab page
:: Configure "NewTabPageAllowedBackgroundTypes" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageAllowedBackgroundTypes"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageAllowedBackgroundTypes' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Edge Collections feature-------------
:: ----------------------------------------------------------
echo --- Disable Edge Collections feature
:: Configure "EdgeCollectionsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeCollectionsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeCollectionsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable outdated Edge games menu-------------
:: ----------------------------------------------------------
echo --- Disable outdated Edge games menu
:: Configure "AllowGamesMenu" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AllowGamesMenu"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AllowGamesMenu' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Edge failed page data collection and suggestions-
:: ----------------------------------------------------------
echo --- Disable Edge failed page data collection and suggestions
:: Configure "AlternateErrorPagesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AlternateErrorPagesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AlternateErrorPagesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Edge in-app support----------------
:: ----------------------------------------------------------
echo --- Disable Edge in-app support
:: Configure "InAppSupportEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!InAppSupportEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'InAppSupportEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Edge payment data storage and ads---------
:: ----------------------------------------------------------
echo --- Disable Edge payment data storage and ads
:: Configure "AutofillCreditCardEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AutofillCreditCardEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AutofillCreditCardEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Edge address data storage-------------
:: ----------------------------------------------------------
echo --- Disable Edge address data storage
:: Configure "AutofillAddressEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AutofillAddressEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AutofillAddressEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable Edge experimentation and remote configuration---
:: ----------------------------------------------------------
echo --- Disable Edge experimentation and remote configuration
:: Configure "ExperimentationAndConfigurationServiceControl" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ExperimentationAndConfigurationServiceControl"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ExperimentationAndConfigurationServiceControl' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge automatic startup--------------
:: ----------------------------------------------------------
echo --- Disable Edge automatic startup
:: Configure "StartupBoostEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!StartupBoostEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'StartupBoostEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Edge external connectivity checks---------
:: ----------------------------------------------------------
echo --- Disable Edge external connectivity checks
:: Configure "ResolveNavigationErrorsUseWebService" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ResolveNavigationErrorsUseWebService"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ResolveNavigationErrorsUseWebService' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Edge Family Safety settings------------
:: ----------------------------------------------------------
echo --- Disable Edge Family Safety settings
:: Configure "FamilySafetySettingsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!FamilySafetySettingsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'FamilySafetySettingsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Edge site information gathering from Bing-----
:: ----------------------------------------------------------
echo --- Disable Edge site information gathering from Bing
:: Configure "SiteSafetyServicesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SiteSafetyServicesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SiteSafetyServicesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge Copilot and Hubs Sidebar-----------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot and Hubs Sidebar
:: Configure "HubsSidebarEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!HubsSidebarEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "StandaloneHubsSidebarEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!StandaloneHubsSidebarEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'StandaloneHubsSidebarEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable Edge Copilot browsing data collection-------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot browsing data collection
:: Configure "DiscoverPageContextEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!DiscoverPageContextEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DiscoverPageContextEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "CopilotPageContext" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!CopilotPageContext"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "CopilotCDPPageContext" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!CopilotCDPPageContext"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Copilot access on new tab page--------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot access on new tab page
:: Configure "NewTabPageBingChatEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageBingChatEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageBingChatEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable outdated Edge Discover button-----------
:: ----------------------------------------------------------
echo --- Disable outdated Edge Discover button
:: Configure "EdgeDiscoverEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeDiscoverEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeDiscoverEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable Edge automatic update scheduled tasks-------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update scheduled tasks
:: Disable scheduled task(s): `\MicrosoftEdgeUpdateTaskMachineCore{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='MicrosoftEdgeUpdateTaskMachineCore{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\MicrosoftEdgeUpdateTaskMachineUA{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='MicrosoftEdgeUpdateTaskMachineUA{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Edge automatic update checks-----------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update checks
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!AutoUpdateCheckPeriodMinutes"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'AutoUpdateCheckPeriodMinutes' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Maximize Edge update suppression duration---------
:: ----------------------------------------------------------
echo --- Maximize Edge update suppression duration
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedDurationMin"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '1440'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedDurationMin' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedStartHour"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedStartHour' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedStartMin"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedStartMin' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge automatic update services----------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update services
:: Disable service(s): `edgeupdate`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'edgeupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: Disable service(s): `edgeupdatem`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'edgeupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0