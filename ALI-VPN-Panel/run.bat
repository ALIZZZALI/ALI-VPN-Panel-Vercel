@echo off
chcp 65001 >nul
cd /d "%~dp0"
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
py -3 app.py
goto done
:run_with_python
python app.py
goto done
:done
echo.
echo ALI VPN Panel closed.
pause
