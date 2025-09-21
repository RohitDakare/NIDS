@echo off
echo ============================================
echo    NIDS - Real Packet Capture Mode
echo ============================================
echo.
echo This script will run NIDS with administrator privileges
echo to enable real network packet capture.
echo.
echo Requirements:
echo - Administrator privileges (required for packet capture)
echo - WinPcap or Npcap installed
echo - Active network interface
echo.
pause

echo Starting NIDS with real packet capture...
echo.

REM Activate virtual environment
call venv_new\Scripts\activate.bat

REM Run NIDS backend with admin privileges
python main_working.py

pause
