@echo off
chcp 65001 >nul
cd /d "%~dp0"
title VibeScan - first-time setup (one time only)
echo ============================================
echo   VibeScan - first-time setup
echo   Runs only on the very first launch, or
echo   after you delete apps\web\.next
echo ============================================
echo.
if not exist "node_modules" (
  echo [setup] Installing dependencies, please wait...
  call npm install
  echo [setup] Downloading the Chromium browser for the scanner...
  call npx playwright install chromium
  echo.
)
if not exist "apps\web\.next\BUILD_ID" (
  echo [build] Building the web app ^(~20-30 seconds^)...
  call npm run build --workspace @vibescan/web
  echo.
)
echo Setup finished. This window closes automatically...
timeout /t 2 /nobreak >nul
