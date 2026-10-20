@echo off
cd /d "%~dp0\frontend"
echo Starting Stag Prime Sentinel FRONTEND (Vite)
echo UI: http://127.0.0.1:5173
echo.
call npm run dev
pause
