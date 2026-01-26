# Ethical Hacking Platform - Red Team vs Blue Team

A comprehensive web application for simulating ethical hacking scenarios with separate Red Team (attack) and Blue Team (defense) interfaces.

## 🎯 Project Overview

This platform provides an educational environment for learning cybersecurity concepts through interactive simulation of both offensive (Red Team) and defensive (Blue Team) security operations.

## ✨ Features

### 🔴 Red Team Interface (Attack Simulation)

1. **Attack Arsenal Section**
   - 4 different attack types (SQL Injection, Brute Force, Port Scanner, DDoS)
   - Quick launch buttons
   - Attack status indicators
   - Success/failure statistics

2. **Attack Configuration Panel**
   - Target selection (IP, domain, service)
   - Attack parameters (intensity, duration, payloads)
   - Advanced options (custom scripts, wordlists)
   - Scheduling attacks

3. **Attack Execution View**
   - Real-time terminal output
   - Progress bars
   - Live packet/request counters
   - Abort/pause controls

4. **Results & Reporting**
   - Vulnerability summary
   - Exploited weaknesses
   - Captured data (passwords, sessions, files)
   - Export reports (PDF, JSON)
   - Replay attack feature

5. **Attack History**
   - Timeline of all attacks
   - Filter by type, target, date
   - Success rate analytics
   - Comparison between attacks

### 🔵 Blue Team Interface (Protection & Auditing)

1. **Security Overview (Main Dashboard)**
   - Security score/health meter
   - Active threats counter
   - System status indicators
   - Quick stats (attacks blocked, alerts generated)

2. **Real-Time Monitoring**
   - Live alert feed (scrolling list)
   - Network traffic visualization
   - Active connections map
   - Suspicious activity indicators

3. **Intrusion Detection System (IDS) Panel**
   - Detection rules manager
   - Enable/disable specific detectors
   - Sensitivity configuration
   - Whitelist/blacklist IPs
   - Custom rule creation

4. **Log Analysis Center**
   - Searchable log viewer
   - Filter by: severity, source IP, event type, time range
   - Pattern recognition highlights
   - Correlation engine (related events)
   - Export logs

5. **Alert Management**
   - Alert queue (unacknowledged alerts)
   - Severity classification (Critical → Low)
   - Alert details (source, target, payload, timestamp)
   - Acknowledge/dismiss/escalate actions
   - Notes and incident tracking

6. **Firewall Control Panel**
   - Blocked IPs list
   - Active rules
   - Add/remove rules
   - Traffic statistics by rule
   - Auto-blocking based on IDS

7. **Forensics & Investigation**
   - Attack timeline reconstruction
   - Packet capture viewer (PCAP analysis)
   - Attack pattern analysis
   - Attacker profiling
   - Mitigation recommendations

8. **Reports & Audit Logs**
   - Security posture reports
   - Compliance dashboards
   - Incident reports
   - Automated audit trail
   - Export for compliance

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup Steps

1. **Clone or navigate to the project directory:**
   ```bash
   cd c:\Users\hp\Desktop\Projets\Python
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the application:**
   - Open your web browser and navigate to: `http://localhost:5000`
   - You'll see the main page with options to enter Red Team or Blue Team interfaces

## 📁 Project Structure

```
Python/
├── app.py                 # Main Flask application
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── attacks/              # Attack modules
│   ├── __init__.py
│   ├── sql_injection.py  # SQL Injection attack
│   ├── brute_force.py    # Brute Force attack
│   ├── port_scanner.py   # Port Scanner attack
│   └── ddos.py           # DDoS attack
├── defense/              # Defense modules
│   ├── __init__.py
│   ├── ids.py            # Intrusion Detection System
│   ├── firewall.py       # Firewall module
│   └── log_analyzer.py   # Log analysis module
├── templates/            # HTML templates
│   ├── index.html        # Main landing page
│   ├── red_team.html     # Red Team interface
│   └── blue_team.html    # Blue Team interface
└── static/               # Static files
    ├── css/
    │   └── style.css     # Stylesheet
    └── js/
        ├── red_team.js   # Red Team JavaScript
        └── blue_team.js  # Blue Team JavaScript
```

## 🎮 Usage Guide

### Red Team Interface

1. **Select an Attack:**
   - Browse available attacks in the Attack Arsenal section
   - Click on an attack card to select it

2. **Configure Attack:**
   - Enter target (IP address or domain)
   - Configure attack parameters (intensity, duration, etc.)
   - Customize payloads or wordlists if needed

3. **Launch Attack:**
   - Click "Launch Attack" button
   - Monitor real-time progress in the Execution View
   - View results in the Results & Reporting section

4. **Review History:**
   - Check Attack History for past attacks
   - Filter by attack type or date
   - Export reports as JSON

### Blue Team Interface

1. **Monitor Security:**
   - Check Security Overview dashboard for system health
   - Monitor real-time alerts in the Alert Feed
   - Watch network traffic visualization

2. **Manage IDS:**
   - Configure detection rules
   - Adjust sensitivity settings
   - Enable/disable specific detectors

3. **Analyze Logs:**
   - Search and filter system logs
   - Identify patterns and correlations
   - Export log data

4. **Handle Alerts:**
   - Review alert queue
   - Acknowledge or escalate alerts
   - Block suspicious IPs automatically

5. **Configure Firewall:**
   - Add/remove firewall rules
   - Block malicious IP addresses
   - Monitor blocked traffic

## 🔧 Attack Modules

### 1. SQL Injection (`sql_injection.py`)
- Simulates SQL injection attacks
- Tests multiple payloads
- Detects vulnerabilities
- Extracts database information

### 2. Brute Force (`brute_force.py`)
- Attempts password cracking
- Uses wordlist-based attacks
- Tracks failed attempts
- Detects account lockouts

### 3. Port Scanner (`port_scanner.py`)
- Scans target ports
- Identifies open services
- Detects filtered ports
- Maps network services

### 4. DDoS (`ddos.py`)
- Simulates denial of service attacks
- Configurable intensity levels
- Multiple attack types (HTTP flood, TCP SYN, UDP)
- Monitors target response times

## 🛡️ Defense Modules

### 1. Intrusion Detection System (`ids.py`)
- Pattern-based detection
- Custom rule creation
- Real-time alert generation
- Severity classification

### 2. Firewall (`firewall.py`)
- IP blocking
- Rule-based filtering
- Protocol and port control
- Traffic statistics

### 3. Log Analyzer (`log_analyzer.py`)
- Log parsing and analysis
- Event correlation
- Pattern recognition
- Search and filtering

## 🔌 API Endpoints

### Red Team Endpoints
- `GET /api/red/attacks` - Get available attacks
- `POST /api/red/launch` - Launch an attack
- `GET /api/red/status/<attack_id>` - Get attack status
- `GET /api/red/history` - Get attack history
- `POST /api/red/abort/<attack_id>` - Abort an attack

### Blue Team Endpoints
- `GET /api/blue/dashboard` - Get dashboard data
- `GET /api/blue/alerts` - Get security alerts
- `POST /api/blue/alerts/<alert_id>/acknowledge` - Acknowledge alert
- `GET /api/blue/logs` - Get system logs
- `GET /api/blue/ids/rules` - Get IDS rules
- `POST /api/blue/ids/rules` - Add IDS rule
- `DELETE /api/blue/ids/rules/<rule_id>` - Delete IDS rule
- `GET /api/blue/firewall/rules` - Get firewall rules
- `POST /api/blue/firewall/rules` - Add firewall rule
- `POST /api/blue/firewall/block` - Block IP address

## 🌐 WebSocket Events

### Red Team Events
- `attack_update` - Real-time attack progress
- `attack_complete` - Attack completion notification
- `attack_detected` - Blue Team detection notification
- `attack_error` - Attack error notification

### Blue Team Events
- `security_alert` - New security alert
- `log_update` - New log entry

## ⚠️ Important Notes

- **Educational Purpose Only:** This platform is designed for learning and should only be used in authorized environments with proper permissions.

- **No Real Attacks:** All attacks are simulated and do not cause actual harm to systems.

- **Controlled Environment:** Use only in isolated lab environments or with explicit authorization.

## 🎓 Learning Objectives

This project demonstrates:
- Web application security vulnerabilities
- Attack simulation and penetration testing
- Intrusion detection and prevention
- Security operations center (SOC) workflows
- Real-time monitoring and alerting
- Log analysis and forensics
- Firewall configuration and management

## 📊 Project Requirements Met

✅ **Red Team Side:**
- Python code/notebook for attack simulation (15 points)
- Web application with GUI for attack management (2 bonus points)
- 4 different attack modules

✅ **Blue Team Side:**
- Web application with GUI for SOC operations (2-3 bonus points)
- IDS system for attack analysis
- Log analysis capabilities
- Security alert generation

## 🚀 Future Enhancements

- Additional attack types
- Machine learning-based detection
- Advanced forensics tools
- Multi-user support
- Database persistence
- Report generation (PDF)
- PCAP file analysis
- Network topology visualization

## 👨‍💻 Development

Built with:
- **Backend:** Flask, Flask-SocketIO
- **Frontend:** HTML5, CSS3, JavaScript
- **Real-time:** WebSocket (Socket.IO)
- **Charts:** Chart.js

## 📝 License

This project is for educational purposes only.

## 🤝 Contributing

This is an academic project. For improvements or suggestions, please contact the project maintainer.

---

**Note:** Always ensure you have proper authorization before using any security testing tools, even in educational contexts.
