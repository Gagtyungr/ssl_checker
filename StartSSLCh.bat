@echo off
echo ============================================
echo   SSL Checker - DIAGNOSTIC launcher
echo   (console stays open so errors are visible)
echo ============================================
set "DIR=%~dp0"
set "TARGET=%DIR%ssl_checker.py"

if not exist "%TARGET%" (
  echo [X] ssl_checker.py NOT FOUND in folder:
  echo     "%DIR%"
  echo     Put this .bat next to ssl_checker.py.
  pause
  exit /b 1
)
echo [.] target file OK: "%TARGET%"
echo.

rem ---- [1] local venv -------------------------------------------
if exist "%DIR%venv\Scripts\python.exe" (
  echo [1] found venv, launching with venv python ...
  "%DIR%venv\Scripts\python.exe" "%TARGET%"
  echo [1] venv python finished, exit code = %errorlevel%
  goto :END
)
echo [1] no venv\Scripts\python.exe  -  skipped
echo.

rem ---- [2] python from PATH -------------------------------------
where python >nul 2>nul
if %errorlevel%==0 (
  echo [2] launching with python from PATH ...
  python "%TARGET%"
  echo [2] python finished, exit code = %errorlevel%
  goto :END
)
echo [2] no python in PATH  -  skipped
echo.

rem ---- [3] py launcher ------------------------------------------
where py >nul 2>nul
if %errorlevel%==0 (
  echo [3] launching with py -3 ...
  py -3 "%TARGET%"
  echo [3] py finished, exit code = %errorlevel%
  goto :END
)
echo [3] no py launcher  -  skipped
echo.

echo [X] NO usable Python was found on this machine.
:END
echo.
echo ---- press any key to close this window ----
pause >nul