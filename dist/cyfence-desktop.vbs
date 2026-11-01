' ClassiGuard CyFence Silent Desktop Launcher
' Suppresses the console window so CyFence opens as a 100% clean native desktop app
Set WshShell = CreateObject("WScript.Shell")
Dim currentDir
currentDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = currentDir
WshShell.Run Chr(34) & currentDir & "\cyfence.exe" & Chr(34), 0, False
