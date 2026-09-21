@echo off
echo ========================================================
echo   Building POC-Recon Standalone Executable (.exe)
echo ========================================================

cd /d "%~dp0\.."

if not exist ".venv" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
)

echo [*] Installing requirements and PyInstaller...
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo [*] Packaging executable with PyInstaller...
pyinstaller --clean -y poc-recon.spec

echo.
echo ========================================================
echo   Build Complete! Executable saved in: dist\poc-recon.exe
echo ========================================================
pause
