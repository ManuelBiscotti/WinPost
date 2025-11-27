:: Created by: Shawn Brink
:: Created on: December 29, 2022
:: Updated on: Februrary 14, 2024
:: Tutoria: https://www.elevenforum.com/t/find-and-save-windows-spotlight-images-in-windows-11.11556/

@echo off
pushd %cd%

md "%UserProfile%\Desktop\WindowsSpotlightImages" 2>nul

setlocal enabledelayedexpansion

cd "%LocalAppData%\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\Assets\"
for /r %%f in (*) do (
  set dest="%UserProfile%\Desktop\WindowsSpotlightImages\%%~nxf.jpg"
  for %%A in ("%%f") do (
    if %%~zA GEQ 51200 (
      if not exist !dest! copy "%%f" !dest!
    )
  )
)

cd "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\DesktopSpotlight\Assets\Images\"
for /r %%f in (*.jpg) do (
  set dest="%UserProfile%\Desktop\WindowsSpotlightImages\%%~nxf"
  if not exist !dest! copy "%%f" !dest!
)

cd "%LocalAppData%\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalCache\Microsoft\IrisService\"
for /r %%f in (*) do (
  if "%%~xf"==".jpg" (
    set dest="%UserProfile%\Desktop\WindowsSpotlightImages\%%~nxf"
    if not exist !dest! copy "%%f" !dest!
  )
)

popd