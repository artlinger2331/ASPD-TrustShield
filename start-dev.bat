@echo off
title TrustShield Launcher
echo ====================================================
echo Starting TrustShield Platform (Frontend + Backend)
echo ====================================================

start "TrustShield Backend (FastAPI)" cmd /k "cd /d %~dp0 && python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
timeout /t 2 /nobreak >nul

start "TrustShield Frontend (Vite)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Both servers started in their own windows!
echo - Frontend: http://localhost:5173
echo - Backend:  http://127.0.0.1:8000
echo - API Docs: http://127.0.0.1:8000/docs
echo ====================================================
