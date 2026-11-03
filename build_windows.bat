@echo off
setlocal
echo ============================================
echo APZ Manager Windows - Build
echo ============================================
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher not found.
  echo Install Python 3.11+ from python.org and enable "Add Python to PATH".
  pause
  exit /b 1
)

py -m pip install --upgrade pip
py -m pip install pyinstaller
py -m PyInstaller --noconfirm --clean --onefile --windowed --name APZ-Manager apz_manager.py

echo.
echo Build complete:
echo dist\APZ-Manager.exe
pause
