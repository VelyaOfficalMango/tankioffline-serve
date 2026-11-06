@echo off
rem TANKI server - local run (Windows)
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
    echo Python not found in PATH
    pause
    exit /b 1
)
rem Ключ админ-панели (admin.html). Сервер читает его ТОЛЬКО из окружения:
rem config.json игнорируется, чтобы реальный ключ не утекал через GitHub.
set "ADMIN_KEY=test"
rem UTF-8 вывод логов независимо от кодовой страницы консоли
set "PYTHONUTF8=1"
%PY% server.py
pause
