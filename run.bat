@echo off
REM BUGHUNTR v4.2 - Startup Script
REM This script starts the frontend server

echo.
echo =========================================
echo   BUGHUNTR v4.2 - Starting Frontend
echo =========================================
echo.

echo Starting Frontend (Vite) on port 8080/8081...
echo.
echo Frontend URL: http://localhost:8080 (or 8081 if 8080 is in use)
echo.
echo [INFO] Backend requires additional dependencies.
echo        To install and run backend manually:
echo        1. Install dependencies: cd backend && python -m pip install -r requirements.txt
echo        2. Run backend: cd backend && python app.py
echo        3. Backend will run on http://localhost:5000
echo.
echo Press Ctrl+C to stop the frontend server
echo.

REM Start frontend
npm run dev
