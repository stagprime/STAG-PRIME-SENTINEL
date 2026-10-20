@echo off
cd /d "%~dp0"
echo Running backend pytest (this may take a minute)...
echo.
".venv\Scripts\python.exe" -m pytest backend\tests -q --tb=line
echo.
pause
