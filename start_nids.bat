@echo off
echo Starting NIDS Application...
cd backend
call venv_clean\Scripts\activate
python -m app.main
pause
