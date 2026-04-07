@echo off
echo ===============================================
echo   WiFi Defender - Starting Server
echo ===============================================
echo.
echo Checking if Flask is installed...
python -c "import flask" 2>nul
if errorlevel 1 (
    echo Flask not found! Installing dependencies...
    pip install -r requirements.txt
)
echo.
echo Starting WiFi Defender...
echo Open your browser to: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.
python app.py
pause
