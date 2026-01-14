@echo off
echo ==========================================
echo   STARTING ORGWATCH SERVER (NO DOCKER)
echo ==========================================

cd backend

echo [1/2] Installing Server Dependencies...
pip install fastapi uvicorn sqlalchemy

echo [2/2] Starting API Server...
echo Server will be live at http://127.0.0.1:8000
echo.

python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000