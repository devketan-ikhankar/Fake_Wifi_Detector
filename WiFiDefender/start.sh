#!/bin/bash
echo "==============================================="
echo "  WiFi Defender - Starting Server"
echo "==============================================="
echo ""
echo "Checking if Flask is installed..."
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Flask not found! Installing dependencies..."
    pip3 install -r requirements.txt
fi
echo ""
echo "Starting WiFi Defender..."
echo "Open your browser to: http://localhost:5000"
echo ""
echo "Note: WiFi scanning requires sudo privileges"
echo "Press Ctrl+C to stop the server"
echo ""
sudo python3 app.py
