' VibeScan - тихий запуск (без командных окон).
' Двойной клик: поднимает ЛОКАЛЬНЫЙ сервер (сайт :3000 + сканер :8787) И
' онлайн-агент (публичный туннель + публикация домена в Supabase, чтобы сайт на
' Vercel мог достучаться до этого ПК), затем открывает сайт. Можно кликать ещё
' раз - то, что уже запущено, не трогается (без дубликатов), просто заново
' открывается браузер. Остановить всё разом: "Остановить-VibeScan.vbs".
Option Explicit

Dim sh, fso, root, url, i, needSetup
' Что открыть в браузере: публичный сайт на Vercel (не локальный localhost:3000).
' Локальные серверы ниже всё равно поднимаются - они нужны, чтобы публичный сайт
' мог сканировать через туннель (Vercel -> localtunnel -> этот ПК).
url = "https://vibescan-web.vercel.app"

Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root

' Первый запуск (или после удаления apps\web\.next): установка + сборка.
' Это единственный случай, когда показывается окно (прогресс, само закроется).
needSetup = False
If Not fso.FolderExists(root & "\node_modules") Then needSetup = True
If Not fso.FileExists(root & "\apps\web\.next\BUILD_ID") Then needSetup = True
If needSetup Then
    sh.Run "cmd /c """ & root & "\_vibescan-setup.bat""", 1, True
End If

' Локальные серверы СКРЫТО - только если веб ещё не поднят.
If Not WebUp() Then
    sh.Run "cmd /c npm run start:scanner", 0, False
    sh.Run "cmd /c npm run start --workspace @vibescan/web", 0, False
End If

' Онлайн-агент СКРЫТО - только если он ещё не запущен. Он открывает публичный
' туннель и публикует домен в Supabase; сканер выше он переиспользует.
If Not AgentRunning() Then
    sh.Run "cmd /c npm run online", 0, False
End If

' Ждём, пока веб ответит, затем открываем браузер.
For i = 1 To 60
    WScript.Sleep 1000
    If WebUp() Then Exit For
Next
sh.Run "explorer.exe " & url, 1, False
WScript.Quit

' True, если что-то отвечает на http://localhost:3000
Function WebUp()
    On Error Resume Next
    Dim http
    Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    http.SetTimeouts 800, 800, 1500, 1500
    http.Open "GET", "http://localhost:3000/", False
    http.Send
    WebUp = (Err.Number = 0) And (http.Status >= 200) And (http.Status < 600)
    On Error GoTo 0
End Function

' True, если онлайн-агент (tools/scanner-online.mjs) уже работает.
Function AgentRunning()
    On Error Resume Next
    Dim wmi, procs, p
    AgentRunning = False
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Set procs = wmi.ExecQuery("SELECT CommandLine FROM Win32_Process WHERE Name = 'node.exe'")
    For Each p In procs
        If Not IsNull(p.CommandLine) Then
            If InStr(LCase(p.CommandLine), "scanner-online") > 0 Then
                AgentRunning = True
                Exit For
            End If
        End If
    Next
    On Error GoTo 0
End Function
