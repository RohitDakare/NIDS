@echo off
echo Starting NIDS Application...
cd backend
call venv_new\Scripts\activate
python -m app.main
pause
