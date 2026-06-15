@echo off
chcp 65001 >nul
cd /d "%~dp0.."
title VibeScan online (scanner + tunnel)

echo ============================================================
echo  Запускаю VibeScan online: сканер + публичный туннель
echo  (Cloudflare). Адрес публикуется в Supabase автоматически —
echo  ничего в Vercel вручную вписывать НЕ нужно.
echo.
echo  ВАЖНО: не закрывай это окно — пока оно открыто, сайт работает.
echo ============================================================
echo.

node tools/scanner-online.mjs

echo.
echo Агент остановлен (код %errorlevel%). Сайт-сканер недоступен, пока не запустишь снова.
pause
