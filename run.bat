@echo off
echo APK Inspector - Starting Application
echo ====================================

echo Starting Backend Server...
start "APK Inspector Backend" cmd /k "cd backend && python main.py"

timeout /t 3 /nobreak > nul

echo Starting Frontend Server...
start "APK Inspector Frontend" cmd /k "cd frontend && npm start"

echo.
echo Both servers are starting...
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000
echo.
echo Press any key to exit this window (servers will continue running)
pause > nul

