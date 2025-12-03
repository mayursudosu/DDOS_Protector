# DDOS Protector - Demo Guide

**Quick demonstration guide for showing how the system works without full deployment**

---

## 🚀 Quick Demo (5 Minutes)

### Step 1: Start the Dashboard

```bash
cd ~/ddos/DDOS_Protector/dashboard
pip install flask werkzeug pyyaml
python3 app.py
```

Open browser: **http://localhost:8080**

---

### Step 2: Create Demo Database with Sample Data

In a new terminal:

```bash
cd ~/ddos/DDOS_Protector
python3 << 'EOF'
import sqlite3
from datetime import datetime, timedelta
import random

# Create demo database
db = sqlite3.connect('/tmp/demo.db')

db.executescript('''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ip TEXT, ts DATETIME, reason TEXT, severity TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, ts DATETIME, source TEXT, notes TEXT);
''')

# Add admin user with hashed password
from werkzeug.security import generate_password_hash
db.execute("INSERT OR REPLACE INTO users VALUES (1, 'rms', ?)", (generate_password_hash('LinuxOS'),))

# Add 50 sample events
ips = ["185.220.101.42", "45.155.205.233", "192.168.1.100", "10.0.0.50"]
events = [
    ("rate_limit", "INFO", "429 response"),
    ("rate_limit", "WARN", "Multiple rate limits exceeded"),
    ("ssh_failed", "INFO", "Failed SSH login"),
    ("ssh_bruteforce", "ALERT", "Brute force detected - AUTO BLOCKED"),
    ("high_rate", "WARN", "100+ requests in 60s"),
]

now = datetime.now()
for i in range(50):
    ip = random.choice(ips)
    reason, sev, detail = random.choice(events)
    ts = now - timedelta(hours=random.uniform(0, 24))
    db.execute("INSERT INTO events (ip, ts, reason, severity, details) VALUES (?,?,?,?,?)",
               (ip, ts.strftime('%Y-%m-%d %H:%M:%S'), reason, sev, detail))

# Add blocked IPs
db.execute("INSERT OR REPLACE INTO blocked_ips VALUES ('185.220.101.42', datetime('now'), 'parser', 'Auto-blocked: SSH brute force')")
db.execute("INSERT OR REPLACE INTO blocked_ips VALUES ('45.155.205.233', datetime('now'), 'dashboard', 'Manual block')")

db.commit()
print("✅ Demo database created at /tmp/demo.db")
print("✅ 50 sample events added")
print("✅ 2 blocked IPs added")
EOF
```

---

### Step 3: Run Dashboard with Demo Data

Stop the previous dashboard (Ctrl+C), then:

```bash
cd ~/ddos/DDOS_Protector/dashboard
python3 << 'EOF'
import app
app.DB_PATH = "/tmp/demo.db"
app.BLOCKLIST_PATH = "/tmp/demo_blocklist.txt"
open("/tmp/demo_blocklist.txt", "a").close()

# Auto-login for demo
from flask import session
@app.app.before_request
def auto_login():
    session['user_id'] = 1
    session['username'] = 'rms'

print("🎯 Dashboard running with demo data")
print("🌐 Open: http://localhost:8080/admin")
app.app.run(host='127.0.0.1', port=8080, debug=False)
EOF
```

---

## 📊 What to Show

### 1. Dashboard Overview
- **Stats Cards**: Events today, alerts, blocked IPs
- **Dark theme** UI designed for security operations

### 2. Events Tab
- Real-time log of all security events
- Color-coded severity (INFO/WARN/ALERT)
- IP addresses, timestamps, reasons

### 3. Blocked IPs Tab
- List of currently blocked IPs
- Source (auto-blocked by parser vs manual)
- Unblock button for each IP

### 4. Alerts Tab
- Only WARN and ALERT severity events
- Quick view of threats requiring attention

### 5. Block IP Form
- Manual IP blocking capability
- Enter IP + reason → instantly blocked

---

## 🏗️ Architecture Explanation

Show the `docs/PROJECT_OVERVIEW.md` and explain:

```
Request Flow:
─────────────────────────────────────────────────────────
   Internet
      │
      ▼
┌──────────────┐
│   Anubis     │ ← Layer 0: Browser-level bot check (optional)
└──────────────┘
      │
      ▼
┌──────────────┐
│  iptables    │ ← Layer 1: Kernel-level IP blocking (<1μs)
│   + ipset    │   Blocked IPs are DROPped here
└──────────────┘
      │
      ▼
┌──────────────┐
│    NGINX     │ ← Layer 2: Rate limiting (10 req/sec)
│              │   Excess requests → 429 error
└──────────────┘
      │
      ▼
┌──────────────┐
│  Log Parser  │ ← Layer 3: Analyzes logs in real-time
│  (parser.py) │   Detects patterns, auto-blocks threats
└──────────────┘
      │
      ▼
┌──────────────┐
│  Dashboard   │ ← Layer 4: Human monitoring & control
│   (Flask)    │   View events, manage blocks
└──────────────┘
─────────────────────────────────────────────────────────
```

---

## 💡 Key Points to Mention

### Why This Approach?

| Layer | Speed | Purpose |
|-------|-------|---------|
| iptables | <1μs | Block known bad IPs at kernel level |
| NGINX | ~1ms | Rate limit to prevent flood |
| Parser | async | Detect patterns, learn new threats |
| Dashboard | human | Oversight and manual intervention |

### Technologies Used

- **Python 3** - Log parsing, dashboard
- **Flask** - Web framework
- **SQLite** - Event logging database
- **NGINX** - Rate limiting
- **iptables + ipset** - IP blocking
- **systemd** - Service management

### Security Principles

1. **Defense in Depth** - Multiple layers of protection
2. **Fail-Safe** - Ports closed by default
3. **Least Privilege** - Services run as non-root
4. **Audit Logging** - All events recorded

---

## 🎯 Demo Script (What to Say)

> "This is DDOS Protector, a multi-layered security system for Ubuntu servers.
>
> When traffic comes in, it first hits **iptables** which blocks known bad IPs 
> in microseconds - that's kernel-level speed.
>
> Traffic that passes goes to **NGINX** which enforces rate limiting - 
> max 10 requests per second per IP.
>
> The **Log Parser** runs in the background, analyzing logs in real-time.
> It detects patterns like brute-force attacks and automatically blocks IPs.
>
> All events are logged to an SQLite database, which powers this **Dashboard**.
>
> Here you can see:
> - Recent security events
> - Currently blocked IPs
> - High-severity alerts
>
> You can also manually block IPs through this interface.
>
> The system is designed to be **scalable** - we have a plugin system 
> for adding new detection methods, notification systems, or 
> integrating with external services like Cloudflare."

---

## 🧹 Cleanup After Demo

```bash
rm /tmp/demo.db /tmp/demo_blocklist.txt
```

---

## 📁 Files to Show

| File | What to Explain |
|------|-----------------|
| `README.md` | Project overview with architecture diagram |
| `docs/PROJECT_OVERVIEW.md` | Detailed file-by-file breakdown |
| `core/parser.py` | The brain - log analysis daemon |
| `dashboard/app.py` | Flask web application |
| `core/plugin_system.py` | Extensible plugin architecture |

---

*Good luck with your presentation! 🎓*
