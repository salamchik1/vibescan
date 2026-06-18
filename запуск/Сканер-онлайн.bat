@echo off
chcp 65001 >nul
cd /d "%~dp0"
title VibeScan online
echo Starting VibeScan online agent...
echo Keep this window open. Closing it = scanner goes offline.
echo.
node tools/scanner-online.mjs
echo.
echo Agent stopped (exit code %errorlevel%).
pause
