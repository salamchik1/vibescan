' VibeScan - остановить ВСЁ разом (тихо, без окна).
' Глушит: веб (:3000), сканер (:8787), онлайн-агент (tools/scanner-online.mjs)
' и его туннель (localtunnel/tunnelmole/cloudflared). После этого публикация
' домена в Supabase прекращается, и сайт честно показывает "offline".
Option Explicit
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""$ids = Get-NetTCPConnection -LocalPort 3000,8787 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; foreach($id in $ids){ try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }; Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' -and $_.CommandLine -match 'scanner-online|localtunnel|tunnelmole' } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }; Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue""", 0, True
