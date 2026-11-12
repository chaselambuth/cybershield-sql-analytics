@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" "scripts\open_power_bi.py"
if errorlevel 1 pause
