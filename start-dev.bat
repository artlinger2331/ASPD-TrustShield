@echo off
title TrustShield Launcher
echo ====================================================
echo Starting TrustShield Platform (Frontend + Backend)
echo ====================================================

if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY_BIN=%~dp0.venv\Scripts\python.exe"
) else (
    set "PY_BIN=python"
)

start "TrustShield Backend (FastAPI)" cmd /k "cd /d %~dp0 && "%PY_BIN%" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
ping 127.0.0.1 -n 3 >nul

start "TrustShield Frontend (Vite)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Both servers started in their own windows!
echo - Frontend: http://localhost:5173
echo - Backend:  http://127.0.0.1:8000
echo - API Docs: http://127.0.0.1:8000/docs
echo ====================================================
