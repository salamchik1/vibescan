' VibeScan - silent launcher (no command windows).
' Double-click this file: it starts the servers in the background
' and opens the site. Click it again any time - if VibeScan is
' already running it just re-opens the browser (no duplicates).
Option Explicit

Dim sh, fso, root, url, i, needSetup
url = "http://localhost:3000"

Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root

' Already running? Just open the browser and exit.
If WebUp() Then
    sh.Run "explorer.exe " & url, 1, False
    WScript.Quit
End If

' First run, or after deleting apps\web\.next: install deps + build.
' This is the only time a window appears (shows progress, auto-closes).
needSetup = False
If Not fso.FolderExists(root & "\node_modules") Then needSetup = True
If Not fso.FileExists(root & "\apps\web\.next\BUILD_ID") Then needSetup = True
If needSetup Then
    sh.Run "cmd /c """ & root & "\_vibescan-setup.bat""", 1, True
End If

' Start both servers HIDDEN - they keep running in the background.
sh.Run "cmd /c npm run start:scanner", 0, False
sh.Run "cmd /c npm run start --workspace @vibescan/web", 0, False

' Wait until the web app answers, then open the browser.
For i = 1 To 60
    WScript.Sleep 1000
    If WebUp() Then Exit For
Next
sh.Run "explorer.exe " & url, 1, False
WScript.Quit

' Returns True if something answers on http://localhost:3000
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
