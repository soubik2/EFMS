@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py -3.12 -m venv venv) else (python -m venv venv)
if not exist "venv\Scripts\python.exe" (echo Could not create virtual environment. Install Python 3.12 and retry.& pause & exit /b 1)
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe setup_env.py
venv\Scripts\python.exe app.py
pause
