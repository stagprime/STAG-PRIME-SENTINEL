@echo off
cd /d "%~dp0"
echo Starting Stag Prime Sentinel BACKEND on http://127.0.0.1:8000
echo Docs: http://127.0.0.1:8000/docs
echo.
".venv\Scripts\python.exe" -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
pause
