@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
echo WARNING: This exposes the panel to devices on your local network over plain HTTP.
echo Use only on a trusted private Wi-Fi. Do not use public Wi-Fi or configure port forwarding.
echo.
where py >nul 2>&1
if %errorlevel%==0 (
  py -3 --version >nul 2>&1
  if %errorlevel%==0 goto run_with_py
)
python --version >nul 2>&1
if %errorlevel%==0 goto run_with_python
echo Python 3.10 or newer was not found. Install Python and try again.
goto done
:run_with_py
py -3 app.py --host 0.0.0.0 --port 8765
goto done
:run_with_python
python app.py --host 0.0.0.0 --port 8765
goto done
:done
echo.
echo ALI VPN Panel closed.
pause
