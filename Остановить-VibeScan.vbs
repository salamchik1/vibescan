' VibeScan - stop all background servers (silent, no window).
' Double-click to shut down the scanner (port 8787) and web (port 3000).
Option Explicit
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""$ids = Get-NetTCPConnection -LocalPort 3000,8787 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; foreach($id in $ids){ try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }""", 0, True
