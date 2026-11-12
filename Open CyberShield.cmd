@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" "scripts\open_workspace.py"
if errorlevel 1 pause

