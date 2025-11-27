$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

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

# Install Firefox
Write-Host "Installing: Firefox . . ."
	
Get-FileFromWeb -URL "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US" -File "$env:Temp\Firefox Setup.exe"
Start-Process "$env:TEMP\Firefox Setup.exe" -ArgumentList "/S" -Wait

# Firefox Policies
Write-Output "Configuring Firefox Policies..."
$MultilineComment = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox]
; Allow file selection dialogs.
"AllowFileSelectionDialogs"=dword:00000000
; Enable or disable automatic application update.
"AppAutoUpdate"=dword:00000000
; Enable autofill for addresses.
"AutofillAddressEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundAppUpdate"=dword:00000000
"BlockAboutAddons"=dword:00000000
"BlockAboutConfig"=dword:00000000
"BlockAboutProfiles"=dword:00000000
"BlockAboutSupport"=dword:00000000
"CaptivePortal"=dword:00000000
"DisableAccounts"=dword:00000001
"DisableAppUpdate"=dword:00000000
"DisableBuiltinPDFViewer"=dword:00000001
"DisableDefaultBrowserAgent"=dword:00000001
"DisableDeveloperTools"=dword:00000001
"DisableEncryptedClientHello"=dword:00000001
"DisableFeedbackCommands"=dword:00000001
"DisableFirefoxAccounts"=dword:00000001
"DisableFirefoxScreenshots"=dword:00000001
"DisableFirefoxStudies"=dword:00000001
; Prevent access to the Forget button.
"DisableForgetButton"=dword:00000001
; Dont remember search and form history.
; "DisableFormHistory"=dword:00000000
"DisableMasterPasswordCreation"=dword:00000001
"DisablePasswordReveal"=dword:00000001
"DisablePrivateBrowsing"=dword:00000000
"DisableProfileImport"=dword:00000000
"DisableProfileRefresh"=dword:00000000
"DisableSafeMode"=dword:00000001
"DisableSetDesktopBackground"=dword:00000001
"DisableSystemAddonUpdate"=dword:00000001
"DisableTelemetry"=dword:00000001
; Prevent the user from blocking third-party modules that get injected into the Firefox process.
"DisableThirdPartyModuleBlocking"=dword:00000001
"DisplayBookmarksToolbar"="newtab"
"DisablePocket"=dword:00000001
; Display the Menu Bar by default.
"DisplayMenuBar"="never"
"DontCheckDefaultBrowser"=dword:00000001
; Set and lock the download directory.
; "DownloadDirectory"="%USERPROFILE%\\Downloads"
"ExtensionUpdate"=dword:00000001
"GoToIntranetSiteForSingleWordEntryInAddressBar"=dword:00000000
"HardwareAcceleration"=dword:00000000
"HttpsOnlyMode"="enabled"
"LegacyProfiles"=dword:00000000
; Allow manual updates only and do not notify the user about updates.
"ManualAppUpdateOnly"=dword:00000001
"MicrosoftEntraSSO"=dword:00000000
"NetworkPrediction"=dword:00000000
"NewTabPage"=dword:00000000
"NoDefaultBookmarks"=dword:00000001
; Enforce the setting to allow Firefox to offer to remember saved logins and passwords. Both true and false values are accepted.
"OfferToSaveLoginsDefault"=dword:00000000
"OverridePostUpdatePage"=""
"PasswordManagerEnabled"=dword:00000000
"PostQuantumKeyAgreementEnabled"=dword:00000000
; Require or prevent using a Primary Password.
"PrimaryPassword"=dword:00000000
; disable printing	
"PrintingEnabled"=dword:00000000
"PrivateBrowsingModeAvailability"=dword:00000000
"PromptForDownloadLocation"=dword:00000001
"SearchBar"="unified"
"SearchSuggestEnabled"=dword:00000000
"ShowHomeButton"=dword:00000000
"SkipTermsOfUse"=dword:00000001
; "StartDownloadsInTempDirectory"=dword:00000000
; Enable or disable webpage translation.
"TranslateEnabled"=dword:00000001
; Set the minimum SSL version.
"SSLVersionMin"="tls1.2"
"UseSystemPrintDialog"=dword:00000000
"VisualSearchEnabled"=dword:00000000
"WindowsSSO"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Cookies]
"Behavior"="reject-foreign"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\DisableSecurityBypass]
"InvalidCertificate"=dword:00000000
"SafeBrowsing"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS]
"Enabled"=dword:00000000
"ProviderURL"=""
"Locked"=dword:00000000

; [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection]
; "Category"="strict"
; "Locked"=dword:00000000

; Enable or disable Encrypted Media Extensions and optionally lock it.
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions]
"Enabled"=dword:00000000

; Extensions

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings\uBlock0@raymondhill.net]
"installation_mode"="force_installed"
"install_url"="https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
"Locked"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install]
"1"="https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
"Locked"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Uninstall]
"1"="amazondotcom@search.mozilla.org"
"2"="ebay@search.mozilla.org"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome]
"Search"=dword:00000000
"TopSites"=dword:00000000
"SponsoredTopSites"=dword:00000000
"Highlights"=dword:00000000
"Pocket"=dword:00000000
"Stories"=dword:00000000
"SponsoredPocket"=dword:00000000
"SponsoredStories"=dword:00000000
"Snippets"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\FirefoxSuggest]
"WebSuggestions"=dword:00000000
"SponsoredSuggestions"=dword:00000000
"ImproveSuggest"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\GenerativeAI]
"Enabled"=dword:00000001
"Chatbot"=dword:00000001
"LinkPreviews"=dword:00000000
"TabGroups"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Homepage]
"StartPage"="homepage"
"URL"="https://search.brave.com/"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission\Allow\1]
@="https://addons.mozilla.org"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission]
"Default"=dword:00000001

; Permissions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Camera]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Microphone]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Location]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Notifications]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\VirtualReality]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\ScreenShare]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay]
"Default"="allow-audio-video"

; Enable or disable Picture-in-Picture.
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\PictureInPicture]
"Enabled"=dword:00000001

; Allow certain websites to display popups and be redirected by third-party frames
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking]
"Default"=dword:00000001

; Clear navigation data on shutdown
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown]
"Cache"=dword:00000001
"Cookies"=dword:00000000
"FormData"=dword:00000001
"History"=dword:00000001
"Sessions"=dword:00000001
"SiteSettings"=dword:00000001
"Locked"=dword:00000000

; Configure search engine settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines]
"PreventInstalls"=dword:00000000
"Default"="Brave"

; Brave
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines\Add\1]
"Name"="Brave"
"URLTemplate"="https://search.brave.com/search?q={searchTerms}"
"Method"="GET"
"IconURL"="https://www.vectorlogo.zone/logos/brave/brave-icon.svg"
"Alias"="brave"
"Description"="Brave's privacy-focused search engine"
"SuggestURLTemplate"="https://search.brave.com/suggestions?q={searchTerms}"
"PostData"=""

; SearXNG
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines\Add\2]
"Name"="SearXNG"
"Description"="A privacy-respecting, hackable metasearch engine"
"Alias"=""
"Method"="POST"
"URLTemplate"="https://searx.stream/?q={searchTerms}"
"PostData"="q={searchTerms}&time_range=&language=en-US&category_general=on"
"IconURL"="https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/searxng.svg"

; Remove
[HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\SearchEngines\Remove]
"1"="Google"
"2"="Bing"
"3"="Amazon.com"
"4"="eBay"
"5"="Twitter"
"6"="Wikipedia (en)"
"7"="Qwant"
"8"="Ecosia"
"9"="DuckDuckGo"

; Dont show certain messages to the user
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging]
"ExtensionRecommendations"=dword:00000000
"FeatureRecommendations"=dword:00000000
"UrlbarInterventions"=dword:00000000
"SkipOnboarding"=dword:00000000
"MoreFromMozilla"=dword:00000000
"FirefoxLabs"=dword:00000000
"@

Set-Content -Path "$env:TEMP\FirefoxPolicies.reg" -Value $MultilineComment -Force	
# import reg file	
Regedit.exe /S "$env:TEMP\FirefoxPolicies.reg"	
	
Write-Output "Configuring User Profile..."	
# Create user.json in Firefox default-release profile	
$firefoxExe = "C:\Program Files\Mozilla Firefox\firefox.exe"	
$profilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"	

# Ensure Firefox profile exists	
Start-Process $firefoxExe -ArgumentList "--headless" -PassThru | Out-Null	
Start-Sleep -Seconds 3	
Stop-Process -Name "firefox" -Force -ErrorAction SilentlyContinue	

# Detect default-release profile	
$profileDir = Get-ChildItem -Path $profilesPath -Directory -ErrorAction SilentlyContinue |	
	Where-Object { $_.Name -match '\.default-release$' } |    
	Sort-Object LastWriteTime -Descending |    
	Select-Object -First 1    

if (-not $profileDir) {	
	Write-Host "Could not find Firefox profile directory." -ForegroundColor Red    
}	

$profilePath = $profileDir.FullName	
Write-Host "Found Firefox profile: $profilePath" -ForegroundColor Green	

# Define JSON configuration	
$jsonContent = @"	
//
/* You may copy+paste this file and use it as it is.
 *
 * If you make changes to your about:config while the program is running, the
 * changes will be overwritten by the user.js when the application restarts.
 *
 * To make lasting changes to preferences, you will have to edit the user.js.
 */

/****************************************************************************
 * Betterfox                                                                *
 * "Ad meliora"                                                             *
 * version: 144                                                             *
 * url: https://github.com/yokoffing/Betterfox                              *
****************************************************************************/

/****************************************************************************
 * SECTION: FASTFOX                                                         *
****************************************************************************/
/** GENERAL ***/
user_pref("gfx.content.skia-font-cache-size", 32);

/** GFX ***/
user_pref("gfx.canvas.accelerated.cache-items", 32768);
user_pref("gfx.canvas.accelerated.cache-size", 4096);
user_pref("webgl.max-size", 16384);

/** DISK CACHE ***/
user_pref("browser.cache.disk.enable", false);

/** MEMORY CACHE ***/
user_pref("browser.cache.memory.capacity", 131072);
user_pref("browser.cache.memory.max_entry_size", 20480);
user_pref("browser.sessionhistory.max_total_viewers", 4);
user_pref("browser.sessionstore.max_tabs_undo", 10);

/** MEDIA CACHE ***/
user_pref("media.memory_cache_max_size", 262144);
user_pref("media.memory_caches_combined_limit_kb", 1048576);
user_pref("media.cache_readahead_limit", 600);
user_pref("media.cache_resume_threshold", 300);

/** IMAGE CACHE ***/
user_pref("image.cache.size", 10485760);
user_pref("image.mem.decode_bytes_at_a_time", 65536);

/** NETWORK ***/
user_pref("network.http.max-connections", 1800);
user_pref("network.http.max-persistent-connections-per-server", 10);
user_pref("network.http.max-urgent-start-excessive-connections-per-host", 5);
user_pref("network.http.request.max-start-delay", 5);
user_pref("network.http.pacing.requests.enabled", false);
user_pref("network.dnsCacheEntries", 10000);
user_pref("network.dnsCacheExpiration", 3600);
user_pref("network.ssl_tokens_cache_capacity", 10240);

/** SPECULATIVE LOADING ***/
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.places.speculativeConnect.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);

/****************************************************************************
 * SECTION: SECUREFOX                                                       *
****************************************************************************/
/** TRACKING PROTECTION ***/
user_pref("browser.contentblocking.category", "strict"); // EnableTrackingProtection
user_pref("privacy.trackingprotection.allow_list.baseline.enabled", true);
user_pref("browser.download.start_downloads_in_tmp_dir", true);
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.uitour.enabled", false);
user_pref("privacy.globalprivacycontrol.enabled", true);


/** OCSP & CERTS / HPKP ***/
user_pref("security.OCSP.enabled", 0);
user_pref("security.csp.reporting.enabled", false);

/** SSL / TLS ***/
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);
user_pref("security.tls.enable_0rtt_data", false);

/** DISK AVOIDANCE ***/
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("browser.sessionstore.interval", 60000);

/** SHUTDOWN & SANITIZING ***/
user_pref("privacy.history.custom", true);
user_pref("browser.privatebrowsing.resetPBM.enabled", true);

/** SEARCH / URL BAR ***/
user_pref("browser.urlbar.trimHttps", true);
user_pref("browser.urlbar.untrimOnUserInteraction.featureGate", true);
user_pref("browser.search.separatePrivateDefault.ui.enabled", true);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.groupLabels.enabled", false);
user_pref("browser.formfill.enable", false);
user_pref("network.IDN_show_punycode", true);

/** PASSWORDS ***/
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.privateBrowsingCapture.enabled", false);
user_pref("network.auth.subresource-http-auth-allow", 1);
user_pref("editor.truncate_user_pastes", false);

/** MIXED CONTENT + CROSS-SITE ***/
user_pref("security.mixed_content.block_display_content", true);
user_pref("pdfjs.enableScripting", false);

/** EXTENSIONS ***/
user_pref("extensions.enabledScopes", 5);

/** HEADERS / REFERERS ***/
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

/** CONTAINERS ***/
user_pref("privacy.userContext.ui.enabled", true);

/** SAFE BROWSING ***/
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

/** MOZILLA ***/
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.geo", 2);
user_pref("geo.provider.network.url", "https://beacondb.net/v1/geolocate");
user_pref("browser.search.update", false);
user_pref("permissions.manager.defaultsUrl", "");
user_pref("extensions.getAddons.cache.enabled", false);

/** TELEMETRY ***/
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("default-browser-agent.enabled", false);
user_pref("services.settings.server", false); // service endpoint to consult for remote-disablement
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("datareporting.usage.uploadEnabled", false);

/** EXPERIMENTS ***/
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

/** CRASH REPORTS ***/
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

/****************************************************************************
 * SECTION: PESKYFOX                                                        *
****************************************************************************/
/** MOZILLA UI ***/
user_pref("browser.privatebrowsing.vpnpromourl", "");
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.preferences.moreFromMozilla", false);
user_pref("browser.aboutConfig.showWarning", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.profiles.enabled", true);

/** THEME ADJUSTMENTS ***/
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("browser.compactmode.show", true);
user_pref("browser.privateWindowSeparation.enabled", false); // WINDOWS

/** AI ***/
user_pref("browser.ml.enable", false);
// user_pref("browser.ml.chat.enabled", false); // chatbots
// user_pref("browser.ml.chat.menu", false); // chatbots
user_pref("browser.tabs.groups.smart.enabled", false);
user_pref("browser.ml.linkPreview.enabled", false);

/** FULLSCREEN NOTICE ***/
user_pref("full-screen-api.transition-duration.enter", "0 0");
user_pref("full-screen-api.transition-duration.leave", "0 0");
user_pref("full-screen-api.warning.timeout", 0);

/** URL BAR ***/
user_pref("browser.urlbar.trending.featureGate", false);

/** NEW TAB PAGE ***/
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredCheckboxes", false);

/** DOWNLOADS ***/
user_pref("browser.download.manager.addToRecentDocs", false);

/** PDF ***/
user_pref("browser.download.open_pdf_attachments_inline", true);

/** TAB BEHAVIOR ***/
user_pref("browser.bookmarks.openInTabClosesMenu", false);
user_pref("browser.menu.showViewImageInfo", true);
user_pref("findbar.highlightAll", true);
user_pref("layout.word_select.eat_space_to_next_word", false);

/****************************************************************************
 * START: MY OVERRIDES                                                      *
****************************************************************************/
// visit https://github.com/yokoffing/Betterfox/wiki/Common-Overrides
// visit https://github.com/yokoffing/Betterfox/wiki/Optional-Hardening
// Enter your personal overrides below this line:

// PREF: revert back to Standard ETP
user_pref("browser.contentblocking.category", "standard");

// PREF: make Strict ETP less aggressive
// user_pref("browser.contentblocking.features.strict", "tp,tpPrivate,cookieBehavior5,cookieBehaviorPBM5,cm,fp,stp,emailTP,emailTPPrivate,-lvl2,rp,rpTop,ocsp,qps,qpsPBM,fpp,fppPrivate,3pcd,btp");

// PREF: improve font rendering by using DirectWrite everywhere like Chrome [WINDOWS]
user_pref("gfx.font_rendering.cleartype_params.rendering_mode", 5);
user_pref("gfx.font_rendering.cleartype_params.cleartype_level", 100);
user_pref("gfx.font_rendering.directwrite.use_gdi_table_loading", false);
//user_pref("gfx.font_rendering.cleartype_params.enhanced_contrast", 50); // 50-100 [OPTIONAL]

// PREF: disable Firefox Sync
user_pref("identity.fxaccounts.enabled", false);

// PREF: disable the Firefox View tour from popping up
user_pref("browser.firefox-view.feature-tour", "{\"screen\":\"\",\"complete\":true}");

// PREF: disable login manager
user_pref("signon.rememberSignons", false); // Control whether or not Firefox offers to save passwords

// PREF: disable address and credit card manager
user_pref("extensions.formautofill.addresses.enabled", false); // disables autofill for addresses
user_pref("extensions.formautofill.creditCards.enabled", false); // disables autofill for payment methods

// PREF: do not allow embedded tweets, Instagram, Reddit, and Tiktok posts
user_pref("urlclassifier.trackingSkipURLs", "");
user_pref("urlclassifier.features.socialtracking.skipURLs", "");

// PREF: enable HTTPS-Only Mode
// Warn me before loading sites that don't support HTTPS
// in both Normal and Private Browsing windows.
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_error_page_user_suggestions", true);

// PREF: disable captive portal detection
// [WARNING] Do NOT use for mobile devices!
user_pref("captivedetect.canonicalURL", ""); 
user_pref("network.captive-portal-service.enabled", false); 
user_pref("network.connectivity-service.enabled", false); 

// PREF: hide site shortcut thumbnails on New Tab page
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);

// PREF: hide weather on New Tab page
user_pref("browser.newtabpage.activity-stream.showWeather", false);

// PREF: hide dropdown suggestions when clicking on the address bar
user_pref("browser.urlbar.suggest.topsites", false);

// PREF: ask where to save every file
user_pref("browser.download.useDownloadDir", true);

// PREF: ask whether to open or save new file types
user_pref("browser.download.always_ask_before_handling_new_types", true);

// PREF: enforce certificate pinning
// [ERROR] MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE
// 1 = allow user MiTM (such as your antivirus) (default)
// 2 = strict
user_pref("security.cert_pinning.enforcement_level", 2);

// PREF: delete cookies, cache, and site data on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true); // Browsing & download history
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false); // Cookies and site data
user_pref("privacy.clearOnShutdown_v2.cache", true); // Temporary cached files and pages
user_pref("privacy.clearOnShutdown_v2.formdata", true); // Saved form info

// Disable WebRTC
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.enabled", false);

// Disable Google Safe Browsing
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);

user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("privacy.resistFingerprinting.letterboxing", false);



/****************************************************************************
 * SECTION: SMOOTHFOX                                                       *
****************************************************************************/
// visit https://github.com/yokoffing/Betterfox/blob/main/Smoothfox.js
// Enter your scrolling overrides below this line:

// credit: https://github.com/black7375/Firefox-UI-Fix
// only sharpen scrolling
user_pref("apz.overscroll.enabled", true); // DEFAULT NON-LINUX
user_pref("general.smoothScroll", true); // DEFAULT
user_pref("mousewheel.min_line_scroll_amount", 10); // adjust this number to your liking; default=5
user_pref("general.smoothScroll.mouseWheel.durationMinMS", 80); // default=50
user_pref("general.smoothScroll.currentVelocityWeighting", "0.15"); // default=.25
user_pref("general.smoothScroll.stopDecelerationWeighting", "0.6"); // default=.4

// recommended for 60hz+ displays
user_pref("apz.overscroll.enabled", true); // DEFAULT NON-LINUX
user_pref("general.smoothScroll", true); // DEFAULT
user_pref("mousewheel.default.delta_multiplier_y", 275); // 250-400; adjust this number to your liking


/****************************************************************************
 * END: BETTERFOX                                                           *
****************************************************************************/
"@

# Write user.js to profile folder	
$userJsPath = Join-Path $profilePath "user.js"	
Set-Content -Path $userJsPath -Value $jsonContent -Encoding UTF8 -Force	

# Debloat Firefox	
Write-Host "Debloating Firefox..." -ForegroundColor Green	
	
# Uninstall Mozilla Maintenance Service	
Write-Output "Uninstalling Mozilla Maintenance Service..."	
if (Test-Path "C:\Program Files (x86)\Mozilla Maintenance Service\Uninstall.exe") {	
	Start-Process -FilePath "C:\Program Files (x86)\Mozilla Maintenance Service\Uninstall.exe" -ArgumentList "/S" -Wait -NoNewWindow	
}	
	
# Remove-Item "C:\Program Files\Mozilla Firefox\crashhelper.exe" -Force	
Remove-Item "C:\Program Files\Mozilla Firefox\crashreporter.exe" -Force	
# Remove-Item "C:\Program Files\Mozilla Firefox\crashreporter.ini" -Force	
Remove-Item "C:\Program Files\Mozilla Firefox\default-browser-agent.exe" -Force	
Remove-Item "C:\Program Files\Mozilla Firefox\maintenanceservice.exe" -Force	
Remove-Item "C:\Program Files\Mozilla Firefox\maintenanceservice_installer.exe" -Force	
# Remove-Item "C:\Program Files\Mozilla Firefox\minidump-analyzer.exe" -Force	
Remove-Item "C:\Program Files\Mozilla Firefox\pingsender.exe" -Force	
# Remove-Item "C:\Program Files\Mozilla Firefox\updater.exe" -Force	
Get-ChildItem -Path "C:\Program Files\Mozilla Firefox" -Filter "crash*.*" -File | Remove-Item -Force	
Get-ChildItem -Path "C:\Program Files\Mozilla Firefox" -Filter "install.log" -File | Remove-Item -Force	
Get-ChildItem -Path "C:\Program Files\Mozilla Firefox" -Filter "minidump*.*" -File | Remove-Item -Force	

# Disable Firefox Default Browser Agent
Write-Output "Disabling Firefox Default Browser Agent..."
$batchCode = @'
@echo off
:: https://privacy.sexy — v0.13.8 — Fri, 12 Sep 2025 00:16:49 GMT
:: Ensure PowerShell is available

:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: --------Disable Firefox background browser checks---------
:: ----------------------------------------------------------
echo --- Disable Firefox background browser checks
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent 308046B0AF4A39CB'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent D2CEEC440E2074BD'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
'@

$batPath = "$env:TEMP\ConfigureFirefox.bat"	
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII	
Start-Process -FilePath $batPath -NoNewWindow -Wait	

# Disable Mozilla Firefox Services	
Write-Output "Disabling Mozilla Firefox Services..."	
Get-Service | Where-Object { $_.Name -match 'Firefox|Mozilla' } | ForEach-Object {	
	Stop-Service $_.Name -Force -ErrorAction SilentlyContinue	
	Set-Service $_.Name -StartupType Disabled -ErrorAction SilentlyContinue	
}	

# Disable Mozilla Firefox Tasks	
Write-Output "Disabling Mozilla Firefox Tasks..."	
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Firefox*" -or $_.TaskName -like "*Mozilla*" } | ForEach-Object {	
	Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Out-Null	
}	

# Remove Firefox Private Browsing	
Write-Output "Removing Firefox Private Browsing..."	
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" -Force -ErrorAction SilentlyContinue	
Remove-Item "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" -Force -ErrorAction SilentlyContinue	
