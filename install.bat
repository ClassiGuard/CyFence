@echo off
REM ClassiGuard CyFence 1-Click Windows Desktop Installer
setlocal EnableDelayedExpansion

echo ================================================================================
echo   ClassiGuard CyFence: Windows Desktop Installer Launcher
echo ================================================================================
echo Launching installation script...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ Installation encountered an issue.
    pause
) else (
    echo.
    echo Press any key to close installer...
    pause >nul
)
