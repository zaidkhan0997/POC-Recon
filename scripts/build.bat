@echo off
echo ========================================================
echo   Building POC-Recon (Pure Go Executable .exe)
echo ========================================================

cd /d "%~dp0\.."

if not exist "bin" mkdir bin

go build -ldflags="-s -w" -o bin\poc-recon.exe .\cmd\poc-recon

echo.
echo ========================================================
echo   Build Complete! Executable saved in: bin\poc-recon.exe
echo ========================================================
pause
