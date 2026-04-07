═══════════════════════════════════════════════════════════════════════════
   WiFi Defender - CYBERPUNK Edition with REAL Backend & Database
═══════════════════════════════════════════════════════════════════════════

⚠️  IMPORTANT: EXTRACT THE ZIP FILE FIRST!
    Do NOT run from inside the ZIP file or temp folder!

═══════════════════════════════════════════════════════════════════════════
📋 STEP-BY-STEP SETUP (Follow Exactly!)
═══════════════════════════════════════════════════════════════════════════

STEP 1: Extract the ZIP File
─────────────────────────────
Right-click WiFiDefender-CYBERPUNK.zip → "Extract All" → Choose a folder
Example: C:\WiFiDefender\  or  ~/Desktop/WiFiDefender/

Your folder should look like this:
WiFiDefender/
├── app.py
├── wifidefender.db
├── templates/
│   ├── dashboard.html (Cyberpunk UI)
│   ├── login.html
│   ├── register.html
│   └── history.html
├── START.bat
├── start.sh
└── requirements.txt


STEP 2: Install Python Dependencies
────────────────────────────────────
Open Command Prompt/Terminal in the WiFiDefender folder:

    pip install flask flask-cors

Or use:

    pip install -r requirements.txt


STEP 3: Run the Application
────────────────────────────
WINDOWS:
    Double-click START.bat
    
    OR in Command Prompt (AS ADMINISTRATOR):
    python app.py

MAC/LINUX:
    chmod +x start.sh
    sudo ./start.sh
    
    OR:
    sudo python3 app.py


STEP 4: Open Browser
────────────────────
Navigate to: http://localhost:5000


═══════════════════════════════════════════════════════════════════════════
🎮 HOW TO USE
═══════════════════════════════════════════════════════════════════════════

FIRST TIME SETUP:
1. Click "Create one" on login page
2. Enter username, email, password
3. Click "Create Account"
4. Login with your credentials

USING THE CYBERPUNK DASHBOARD:
1. After login → Cyberpunk hacker-style interface loads
2. Top-right shows: ◉ LIVE MODE (green) or ◉ DEMO MODE (amber)
3. Click big scan button: ⌖ SCAN
4. Watch the 8 detection engines run in real-time
5. See threat cards with red alerts for fake WiFi networks
6. Click "Recent Scans" to view scan history
7. Enable "Live Mode" toggle for auto-refresh every 5 seconds


═══════════════════════════════════════════════════════════════════════════
✨ FEATURES
═══════════════════════════════════════════════════════════════════════════

✅ REAL WiFi Scanning (Windows/Mac/Linux)
✅ 8 Advanced Detection Engines:
   - Evil Twin Detection
   - Deauth Attack Detection  
   - Karma Attack Detection
   - WPS Vulnerability Scanner
   - Hidden SSID Detection
   - Channel Hopping Detection
   - Beacon Flooding Detection
   - Signal Anomaly Detection

✅ Cyberpunk Hacker UI:
   - Matrix-style background grid
   - Animated radar scanner
   - Real-time threat logs
   - Channel activity visualization
   - Risk score meters
   - Modal popups with detailed analysis

✅ Database Backend:
   - SQLite database stores all scans
   - User authentication system
   - Scan history with timestamps
   - Threat detection records

✅ Recent Scans Feature:
   - Access via navbar: "Recent Scans" button
   - Shows last 10 scans with details
   - Threat count per scan
   - Click to view full details


═══════════════════════════════════════════════════════════════════════════
🔧 TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════

ERROR: "TemplateNotFound: login.html"
SOLUTION: You're running from ZIP file! Extract it first properly!

ERROR: "No module named 'flask'"
SOLUTION: Run: pip install flask flask-cors

ERROR: "No networks found"  
SOLUTION:
  - Windows: Run Command Prompt as Administrator
  - Mac/Linux: Use sudo python3 app.py
  - Check WiFi adapter is enabled

ERROR: "Address already in use"
SOLUTION: Port 5000 is busy
  - Close other Flask apps
  - Or change port in app.py line 736: app.run(port=5001)

BACKEND SHOWS "DEMO MODE":
- This means WiFi scanning failed
- Run as Administrator/sudo
- Check WiFi adapter is working
- Demo mode still shows interface with fake data


═══════════════════════════════════════════════════════════════════════════
🎯 TESTING THE SYSTEM
═══════════════════════════════════════════════════════════════════════════

1. Login to the system
2. Click scan button - you should see:
   ✓ Progress bar with stages
   ✓ 8 engines running (visual indicators)
   ✓ Real-time log messages scrolling
   ✓ Network cards appearing with threat analysis

3. Fake WiFi Detection Works When:
   ✓ Same SSID on multiple BSSIDs (Evil Twin)
   ✓ Open networks detected
   ✓ WPA downgrade attacks
   ✓ Deauth frame flooding
   ✓ Suspicious vendor/MAC addresses
   ✓ Beacon interval anomalies
   ✓ Channel hopping detected

4. Check Recent Scans:
   ✓ Click "Recent Scans" in navbar
   ✓ See history with timestamps
   ✓ Threat count per scan


═══════════════════════════════════════════════════════════════════════════
📁 FILE STRUCTURE
═══════════════════════════════════════════════════════════════════════════

app.py              - Flask backend with API endpoints
wifidefender.db     - SQLite database (auto-created)
templates/
  ├── dashboard.html    - Cyberpunk scanner interface
  ├── login.html        - Login page
  ├── register.html     - Registration page
  └── history.html      - Scan history page
START.bat           - Windows launcher
start.sh            - Mac/Linux launcher


═══════════════════════════════════════════════════════════════════════════
🔒 API ENDPOINTS
═══════════════════════════════════════════════════════════════════════════

/status              - Backend status check
/scan-real           - Perform real WiFi scan
/api/recent-scans    - Get recent scan history (requires login)
/login               - User authentication
/register            - User registration
/logout              - Logout
/dashboard           - Main cyberpunk interface
/history             - Scan history page


═══════════════════════════════════════════════════════════════════════════
💡 TIPS
═══════════════════════════════════════════════════════════════════════════

- Run as Administrator/sudo for best WiFi scanning results
- Use Chrome/Firefox for best UI experience
- Enable "Live Mode" for continuous monitoring
- Check logs in terminal for detailed scan info
- Modal popups show full network analysis - click any network card


═══════════════════════════════════════════════════════════════════════════

Enjoy your Cyberpunk WiFi Security Scanner! 🛡️⚡

═══════════════════════════════════════════════════════════════════════════
