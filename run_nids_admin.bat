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

echo Starting NIDS Frontend...
cd frontend
start "NIDS Dashboard" cmd /k "npm run dev"
cd ..

echo Starting NIDS Backend with real packet capture...
echo.

REM Change to backend directory
cd backend

REM Activate virtual environment
call venv_clean\Scripts\activate

REM Run NIDS backend with admin privileges
python main_working.py

pause
