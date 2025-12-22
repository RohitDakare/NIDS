@echo off
echo Starting NIDS Application...
call venv_new\Scripts\activate
python -m app.main
pause
