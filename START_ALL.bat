@echo off
cd /d "%~dp0"
echo.
echo Stag Prime Sentinel — starting API + Frontend + Monitoring worker
echo Keep this window open. Ctrl+C stops owned processes.
echo.
".venv\Scripts\python.exe" Sentinel_Start_Local_All.py
echo.
pause
