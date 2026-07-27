@echo off
echo == SecureDOT setup ==

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Install Python 3.9+ from https://python.org and re-run this script.
    exit /b 1
)

python -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo Tkinter is missing from your Python install. Reinstall Python from
    echo https://python.org and make sure "tcl/tk and IDLE" is checked during setup.
    exit /b 1
)

if not exist "data\VirusDataBaseHash.bav" (
    echo Signature database not found at data\VirusDataBaseHash.bav
    exit /b 1
)

echo All checks passed.
echo.
echo Launch the app with:
echo   python main.py
