# ClassiGuard CyFence: Automated Windows Desktop Installer
# Installs application files, creates Desktop & Start Menu shortcuts, and configures zero-console silent launch

$ErrorActionPreference = 'Stop'

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  🛡️  ClassiGuard CyFence: Windows Desktop Installer" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Installing enterprise offensive & defensive security suite..." -ForegroundColor White

$sourceDir = $PSScriptRoot
if (-not $sourceDir) { $sourceDir = Get-Location }

$exeSource = Join-Path $sourceDir "dist\cyfence.exe"
if (-not (Test-Path $exeSource)) {
    $exeSource = Join-Path $sourceDir "cyfence.exe"
}

if (-not (Test-Path $exeSource)) {
    Write-Host "`n❌ Error: cyfence.exe not found in dist\ or current directory." -ForegroundColor Red
    Write-Host "Please build or download cyfence.exe before running installer." -ForegroundColor Yellow
    Exit 1
}

$vbsSource = Join-Path $sourceDir "dist\cyfence-desktop.vbs"
if (-not (Test-Path $vbsSource)) {
    $vbsSource = Join-Path $sourceDir "cyfence-desktop.vbs"
}

# Define target per-user installation path
$installDir = Join-Path $env:LOCALAPPDATA "Programs\ClassiGuard-CyFence"
Write-Host "`n[1/4] Creating installation directory: $installDir" -ForegroundColor White
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Write-Host "[2/4] Copying binary and desktop launcher assets..." -ForegroundColor White
Copy-Item $exeSource (Join-Path $installDir "cyfence.exe") -Force

if (Test-Path $vbsSource) {
    Copy-Item $vbsSource (Join-Path $installDir "cyfence-desktop.vbs") -Force
} else {
    # Generate silent desktop runner VBScript directly
    $vbsContent = @"
' ClassiGuard CyFence Silent Desktop Launcher
Set WshShell = CreateObject("WScript.Shell")
Dim currentDir
currentDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = currentDir
WshShell.Run Chr(34) & currentDir & "\cyfence.exe" & Chr(34), 0, False
"@
    Set-Content (Join-Path $installDir "cyfence-desktop.vbs") $vbsContent -Encoding ASCII
}

# Copy documentation
$readme = Join-Path $sourceDir "README.md"
if (Test-Path $readme) {
    Copy-Item $readme (Join-Path $installDir "README.md") -Force
}

Write-Host "[3/4] Creating Desktop and Start Menu application shortcuts..." -ForegroundColor White
$wsh = New-Object -ComObject WScript.Shell

# Desktop Shortcut
$desktopPath = [Environment]::GetFolderPath('Desktop')
$desktopShortcutPath = Join-Path $desktopPath "ClassiGuard CyFence.lnk"
$sc = $wsh.CreateShortcut($desktopShortcutPath)
$sc.TargetPath = "wscript.exe"
$sc.Arguments = "`"$installDir\cyfence-desktop.vbs`""
$sc.WorkingDirectory = $installDir
$sc.IconLocation = "$installDir\cyfence.exe,0"
$sc.Description = "ClassiGuard CyFence Enterprise Security Suite"
$sc.Save()

# Start Menu Shortcut
$startMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\ClassiGuard CyFence"
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
$startMenuShortcutPath = Join-Path $startMenuDir "ClassiGuard CyFence.lnk"
$sc2 = $wsh.CreateShortcut($startMenuShortcutPath)
$sc2.TargetPath = "wscript.exe"
$sc2.Arguments = "`"$installDir\cyfence-desktop.vbs`""
$sc2.WorkingDirectory = $installDir
$sc2.IconLocation = "$installDir\cyfence.exe,0"
$sc2.Description = "ClassiGuard CyFence Enterprise Security Suite"
$sc2.Save()

Write-Host "[4/4] Creating uninstaller and registering environment..." -ForegroundColor White
$uninstallerPath = Join-Path $installDir "uninstall.bat"
$uninstallScript = @"
@echo off
echo ================================================================================
echo   ClassiGuard CyFence Uninstaller
echo ================================================================================
echo Removing desktop and Start Menu shortcuts...
del "%USERPROFILE%\Desktop\ClassiGuard CyFence.lnk" 2>nul
rmdir /s /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\ClassiGuard CyFence" 2>nul

echo Stopping active CyFence background processes...
taskkill /F /IM cyfence.exe 2>nul

echo Removing application files...
cd /d "%LOCALAPPDATA%\Programs"
rmdir /s /q "%LOCALAPPDATA%\Programs\ClassiGuard-CyFence" 2>nul

echo.
echo ✅ ClassiGuard CyFence has been successfully uninstalled.
echo.
pause
"@
Set-Content $uninstallerPath $uninstallScript -Encoding ASCII

# Add to user PATH if not present
try {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    }
} catch {}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  🎉 ClassiGuard CyFence Installation Complete!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Application Location: $installDir" -ForegroundColor White
Write-Host "  Desktop Shortcut:     $desktopShortcutPath" -ForegroundColor White
Write-Host "  Start Menu Shortcut:  $startMenuShortcutPath" -ForegroundColor White
Write-Host "  Silent Launcher:      wscript.exe cyfence-desktop.vbs (0 command prompt pop-up!)" -ForegroundColor White
Write-Host "  Uninstaller:          $uninstallerPath" -ForegroundColor White
Write-Host "================================================================================`n" -ForegroundColor Cyan
Write-Host "You can now double-click 'ClassiGuard CyFence' on your Desktop to launch!" -ForegroundColor Green
