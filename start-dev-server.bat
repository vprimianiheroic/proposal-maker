@echo off
cd /d "%~dp0"
echo Starting Vite dev server...
start "" cmd /k "npm run dev"
timeout /t 3 /nobreak >nul
start http://localhost:5173
echo.
echo Dev server should be starting. Check the command window that opened.
echo If the browser doesn't open automatically, navigate to http://localhost:5173
pause

