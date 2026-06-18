' VibeScan online - тихий запуск агента (без окна).
' Поднимает локальный сканер + туннель и публикует адрес в Supabase.
' Используй этот файл для АВТОЗАПУСКА при включении ПК:
'   1) Win+R -> вставь  shell:startup  -> Enter
'   2) перетащи СЮДА ярлык этого файла (ПКМ по файлу -> Создать ярлык).
' Теперь при каждом входе в Windows агент стартует сам, без окон.
Option Explicit

Dim sh, fso, root
Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root

' Run the agent hidden (window style 0), do not wait.
sh.Run "cmd /c node tools\scanner-online.mjs", 0, False
WScript.Quit
