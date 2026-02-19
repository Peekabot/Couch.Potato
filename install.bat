@echo off
REM Couch Potato Controller - Easy Installer for Windows
REM Run this on your Windows computer to set up the receiver server

echo.
echo 🛋️  Couch Potato Controller - Installer
echo ========================================
echo.

REM Check Python installation
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH!
    echo    Please install Python 3.7 or higher first.
    echo    Visit: https://www.python.org/downloads/
    echo    Make sure to check "Add Python to PATH" during installation!
    pause
    exit /b 1
)

python --version
echo.

REM Check pip
echo Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ pip is not installed!
    echo    Please reinstall Python with pip included.
    pause
    exit /b 1
)

echo ✅ pip is available
echo.

REM Install dependencies
echo Installing dependencies...
echo Running: pip install -r requirements.txt
echo.

pip install -r requirements.txt

echo.
echo ✅ Installation complete!
echo.
echo 📋 Next Steps:
echo    1. Run the receiver server:
echo       python receiver_server.py
echo.
echo    2. Note the IP address shown
echo.
echo    3. On your iPhone (Pythonista):
echo       - Copy pythonista_server.py and couch_controller.html
echo       - Run pythonista_server.py
echo       - Open Safari → http://localhost:8080
echo       - Go to Settings → Enter computer IP → Connect
echo.
echo 📖 For detailed instructions, see SETUP_GUIDE.md
echo.
pause
