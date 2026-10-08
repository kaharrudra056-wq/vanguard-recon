@echo off
title VanguardRecon Public Server Launcher
echo ===================================================
echo     VanguardRecon - Starting Server & Public Tunnel
echo ===================================================
echo.
echo Starting FastAPI Web Server...
start "" ".\.venv\Scripts\python.exe" -m vanguard serve --host 127.0.0.1 --port 8000
timeout /t 2 >nul

echo Starting Cloudflare Public Tunnel...
echo.
.\cloudflared.exe tunnel --url http://127.0.0.1:8000
pause
