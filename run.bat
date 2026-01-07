@echo off
title Ultimate Deal Server Manager
echo Ultimate Deal Server Manager
echo =============================
:loop
echo.
echo Starting Node.js server with garbage collection enabled...
echo Started at: %time%
echo =============================
echo.
:: Start the server and save its PID
start /B "" node encserver.js > nul 2>&1
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq node.exe" /fi "windowtitle eq N/A" /fo list ^| find "PID:"') do set SERVER_PID=%%a
echo Server started with PID %SERVER_PID%
:: Wait for 10 minutes (600 seconds)
timeout /t 600 /nobreak > nul
:: Kill only this specific Node.js process
echo.
echo =============================
echo Scheduled restart initiated at: %time%
echo Stopping current server instance...
taskkill /f /pid %SERVER_PID%
echo Server stopped, restarting...
echo =============================
echo.
:: Small delay before restart
timeout /t 5 /nobreak > nul
:: Loop back to start
goto loop