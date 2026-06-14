@echo off
chcp 65001 >nul
cd /d "%~dp0"
title VibeScan online (scanner + tunnel)

echo ============================================================
echo  Запускаю локальный сканер...
echo ============================================================
start "VibeScan Scanner" cmd /c "npm run start:scanner"

echo Жду, пока сканер поднимется (8 сек)...
timeout /t 8 >nul

echo.
echo ============================================================
echo  Сейчас появится ПУБЛИЧНЫЙ адрес (https://...tunnelmole.net)
echo.
echo  1) Скопируй адрес из строки "https://....tunnelmole.net"
echo  2) В Vercel - Settings - Environment Variables:
echo        SCANNER_URL = этот адрес
echo  3) Vercel - Deployments - ... - Redeploy
echo.
echo  ВАЖНО: не закрывай это окно - пока оно открыто, сайт работает.
echo ============================================================
echo.

npx -y tunnelmole 8787

echo.
echo Туннель остановлен. Сайт-сканер больше недоступен, пока не запустишь снова.
pause
