@echo off
chcp 65001 >nul
setlocal EnableExtensions
rem ==================================================================
rem  StartSSLCh.bat - диспетчер запуска. НЕ устанавливает ничего.
rem  Задача: запустить ssl_checker.py тем Python, в котором есть
rem  полное ssl и (если ставил) cryptography, а НЕ урезанной сборкой
rem  из Microsoft Store / Anaconda. Порядок поиска:
rem    1) venv рядом с этим файлом   <- предпочтительно (полный отчёт)
rem    2) python.org из типовых папок<- базовый режим работает
rem    3) py launcher                <- крайний случай
rem  Чего НЕ делает: не качает, не пишет в реестр/автозагрузку,
rem  не трогает Store-заглушки (пути WindowsApps не используются).
rem ==================================================================
set "DIR=%~dp0"
set "TARGET=%DIR%ssl_checker.py"
if not exist "%TARGET%" (
  echo [!] ssl_checker.py не найден рядом с StartSSLCh.bat
  pause & exit /b 1
)

rem --- 1) локальный venv (даёт и даты, и SigAlg/KeyBits) -------------
if exist "%DIR%venv\Scripts\pythonw.exe" (
  start "" /b "%DIR%venv\Scripts\pythonw.exe" "%TARGET%"
  exit /b 0
)

rem --- 2) python.org по типовым путям (перебор 3.14..3.8) ------------
for /L %%V in (14,-1,8) do (
  if exist "%LOCALAPPDATA%\Programs\Python\Python3%%V\pythonw.exe" (
    start "" /b "%LOCALAPPDATA%\Programs\Python\Python3%%V\pythonw.exe" "%TARGET%" & exit /b 0 )
  if exist "%ProgramFiles%\Python3%%V\pythonw.exe" (
    start "" /b "%ProgramFiles%\Python3%%V\pythonw.exe" "%TARGET%" & exit /b 0 )
  if exist "%ProgramFiles(x86)%\Python3%%V\pythonw.exe" (
    start "" /b "%ProgramFiles(x86)%\Python3%%V\pythonw.exe" "%TARGET%" & exit /b 0 )
)

rem --- 3) крайний случай: py launcher (может попасть на Store!) ------
where py >nul 2>nul
if %errorlevel%==0 (
  echo [i] Используем py launcher. Если отчёт неполный или падает -
  echo     это, скорее всего, урезанный Python из Microsoft Store.
  echo     Поставь обычный Python с python.org и перезапусти bat.
  start "" /b py -3 -w "%TARGET%"
  exit /b 0
)

echo [!] Подходящий Python не найден. Поставь с python.org
echo     (НЕ из Microsoft Store), галочку "py launcher" включи.
pause
exit /b 1