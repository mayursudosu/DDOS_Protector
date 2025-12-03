# DDOS Protector - Project Overview

## 📋 Executive Summary

**DDOS Protector** is a multi-layered HTTP security system designed to protect web servers from Distributed Denial of Service (DDoS) attacks, brute-force attempts, and malicious traffic. It implements a defense-in-depth strategy using industry-standard Linux security tools.

| Attribute | Details |
|-----------|---------|
| **Target Platform** | Ubuntu Server 22.04+ (amd64, arm64, armv7l) |
| **Primary Language** | Python 3, Bash |
| **Database** | SQLite |
| **Web Framework** | Flask |
| **Web Server** | NGINX |
| **Firewall** | iptables + ipset |

---

## 🏗️ System Architecture

The system implements a **5-layer defense model**:

```
Layer 0: Anubis        → Browser-level bot detection (optional)
Layer 1: iptables      → Kernel-level IP blocking (microseconds)
Layer 2: NGINX         → Application-level rate limiting
Layer 3: Log Parser    → Real-time threat detection
Layer 4: Dashboard     → Human monitoring and control
```

### Why This Order Matters

1. **Anubis (Layer 0)** - Stops bots before they even make a request
2. **iptables (Layer 1)** - Fastest possible blocking (kernel-level, <1μs)
3. **NGINX (Layer 2)** - Rate limits legitimate-looking traffic
4. **Parser (Layer 3)** - Analyzes patterns and detects threats
5. **Dashboard (Layer 4)** - Human oversight and manual intervention

---

## 📁 Repository Structure

```
DDOS_Protector/
├── 📜 Root Scripts (Installation & Management)
│   ├── setup_ubuntu.sh      # Initial server hardening
│   ├── install.sh           # Main installer
│   ├── uninstall.sh         # Clean removal
│   └── test.sh              # Diagnostic tests
│
├── 📋 Configuration
│   ├── config.yaml.example  # Configuration template
│   └── LICENSE              # MIT License
│
├── 📚 Documentation
│   └── docs/
│       ├── INSTALL_GUIDE.md     # Beginner-friendly guide
│       ├── DEPLOY_QUICK.md      # Quick deployment steps
│       └── PROJECT_OVERVIEW.md  # This file
│
├── 🔧 Core Engine
│   └── core/
│       ├── parser.py        # Log analysis daemon
│       ├── apply_blocklist.sh # ipset sync script
│       ├── log_format.conf  # Custom NGINX log format
│       └── future_hooks.md  # Planned features
│
├── 🌐 NGINX Configuration
│   └── nginx/
│       └── scr_protector.conf # Rate limiting snippet
│
├── 📊 Dashboard Application
│   └── dashboard/
│       ├── app.py           # Flask application
│       ├── requirements.txt # Python dependencies
│       ├── templates/       # HTML templates
│       │   ├── admin.html   # Main dashboard
│       │   └── login.html   # Login page
│       └── static/          # CSS & JavaScript
│           ├── main.css     # Dark theme styles
│           └── main.js      # Client-side logic
│
├── 🛡️ Challenge Page
│   └── .scr-protector/
│       └── challenge.html   # Rate-limit challenge
│
└── ⚙️ Systemd Services
    └── systemd/
        ├── scr-protector-dashboard.service
        ├── scr-protector-parser.service
        ├── scr-protector-blocker.service
        └── scr-protector-blocker.timer
```

---

## 📜 File-by-File Breakdown

### 🔧 Root Scripts

#### `setup_ubuntu.sh`
**Purpose:** Initial server hardening and package installation

| Function | Description |
|----------|-------------|
| Package Install | NGINX, Python3, ipset, iptables, fail2ban, UFW |
| Firewall Setup | Default deny incoming, allow SSH |
| User Creation | Creates `scr-protector` system user |
| Security Hardening | Disables root SSH, configures fail2ban |

**When to Run:** Once, on fresh Ubuntu Server installation

---

#### `install.sh`
**Purpose:** Main installation script for DDOS Protector

| Function | Description |
|----------|-------------|
| File Deployment | Copies all files to `/opt/scr-protector/` |
| NGINX Config | Installs rate limiting snippet |
| ipset Setup | Creates `scr_blockset` hash:ip set |
| Database Init | Creates SQLite database with tables |
| Admin User | Creates dashboard admin account |
| Service Setup | Enables systemd services |

**Key Features:**
- Idempotent (safe to run multiple times)
- Automatic backup of existing configs
- Validates NGINX config before reload

---

#### `uninstall.sh`
**Purpose:** Clean removal of DDOS Protector

| Function | Description |
|----------|-------------|
| Service Stop | Stops and disables all services |
| File Removal | Removes `/opt/scr-protector/` |
| NGINX Cleanup | Removes rate limiting config |
| ipset Cleanup | Destroys blocklist set |

**Safety:** Prompts for confirmation before each step

---

#### `test.sh`
**Purpose:** Diagnostic tests to verify installation

| Test | What it Checks |
|------|----------------|
| Services | All systemd services running |
| NGINX | Configuration valid |
| ipset | Blocklist set exists |
| Database | SQLite database accessible |
| Permissions | File ownership correct |

---

### 🔧 Core Engine

#### `core/parser.py`
**Purpose:** Real-time log analysis daemon (the brain of the system)

```python
# Key Classes
SlidingWindowCounter  # Tracks events per IP over time window
Database              # SQLite interface for events and blocks
BlocklistManager      # Manages blocklist.txt and triggers ipset sync
ParserDaemon          # Main daemon loop
```

| Feature | Implementation |
|---------|----------------|
| Log Tailing | `FileTailer` class with rotation detection |
| Rate Tracking | Sliding window algorithm per IP |
| Threat Detection | Pattern matching for HTTP/SSH abuse |
| Auto-Blocking | Threshold-based automatic IP blocking |
| Event Logging | All events stored in SQLite |

**Monitored Logs:**
- `/var/log/nginx/access.log` - HTTP requests
- `/var/log/auth.log` - SSH attempts

---

#### `core/apply_blocklist.sh`
**Purpose:** Syncs blocklist.txt to ipset for kernel-level blocking

| Step | Description |
|------|-------------|
| 1 | Read `blocklist.txt` |
| 2 | Create temporary ipset |
| 3 | Add valid IPs to temp set |
| 4 | Atomic swap with main set |
| 5 | Verify iptables rule exists |
| 6 | Persist to `/etc/ipset.conf` |

**Why Atomic Swap?** Prevents packet loss during updates

---

### 🌐 NGINX Configuration

#### `nginx/scr_protector.conf`
**Purpose:** NGINX rate limiting configuration snippet

```nginx
# Key Directives
limit_req_zone $binary_remote_addr zone=scr_limit:10m rate=10r/s;
limit_req zone=scr_limit burst=20 nodelay;
error_page 429 = /__scr_challenge;
```

| Directive | Purpose |
|-----------|---------|
| `limit_req_zone` | Creates shared memory zone for rate tracking |
| `limit_req` | Applies rate limit to requests |
| `error_page 429` | Redirects rate-limited clients to challenge |

---

### 📊 Dashboard Application

#### `dashboard/app.py`
**Purpose:** Flask web application for admin interface

| Route | Function |
|-------|----------|
| `/login` | Authentication page |
| `/admin` | Main dashboard |
| `/api/stats` | JSON statistics |
| `/api/blocked` | List blocked IPs |
| `/api/block` | Block an IP |
| `/api/unblock` | Unblock an IP |
| `/api/events` | Event log |
| `/api/alerts` | Alerts only |

**Security Features:**
- Password hashing (werkzeug)
- Session-based authentication
- Binds to localhost only (127.0.0.1)
- CSRF protection

---

#### `dashboard/templates/admin.html`
**Purpose:** Main dashboard HTML template

| Section | Content |
|---------|---------|
| Stats Cards | Events today, alerts, blocked IPs |
| Events Tab | Full event log table |
| Blocked Tab | Currently blocked IPs with unblock |
| Alerts Tab | WARN and ALERT severity events |
| Block Form | Manual IP blocking |

---

### 🛡️ Challenge Page

#### `.scr-protector/challenge.html`
**Purpose:** JavaScript challenge for rate-limited clients

| Step | Action |
|------|--------|
| 1 | Display "Verifying browser" message |
| 2 | Wait 2.5 seconds (prevents rapid requests) |
| 3 | Set `__scr_pass` cookie |
| 4 | Redirect back to original page |

**Purpose:** Proves the client can execute JavaScript (not a simple script)

---

### ⚙️ Systemd Services

| Service | Purpose | Restart |
|---------|---------|---------|
| `scr-protector-dashboard.service` | Flask dashboard | on-failure |
| `scr-protector-parser.service` | Log parser daemon | on-failure |
| `scr-protector-blocker.service` | Blocklist sync | manual |
| `scr-protector-blocker.timer` | Runs blocker every 30s | - |

---

## 🔐 Security Model

### Defense in Depth

```
Attack → Anubis → iptables → NGINX → Parser → Response
                     ↑                    │
                     └────── Feedback ────┘
```

### Key Security Principles

1. **Fail-Safe Defaults** - All ports closed by default
2. **Least Privilege** - Services run as non-root user
3. **Defense in Depth** - Multiple layers of protection
4. **Audit Logging** - All events recorded to database
5. **Secure by Default** - Dashboard only accessible via SSH tunnel

---

## 📈 Scalability Points

### Current Extension Points

| Component | How to Extend |
|-----------|---------------|
| Detection | Add new patterns to `parser.py` |
| Blocking | Add new sources to `blocklist.txt` |
| Dashboard | Add new routes to `app.py` |
| NGINX | Add new rate limit zones |

### Planned Modules (see `core/future_hooks.md`)

- Port scan detection
- Geographic IP filtering
- Reputation scoring
- Webhook notifications
- Prometheus metrics

---

## 🎓 Key Concepts Demonstrated

| Concept | Implementation |
|---------|----------------|
| **Rate Limiting** | Token bucket algorithm in NGINX |
| **IP Blocking** | ipset hash tables for O(1) lookup |
| **Log Analysis** | Real-time file tailing with rotation handling |
| **Sliding Window** | Time-based event counting per IP |
| **REST API** | Flask JSON endpoints |
| **Systemd Integration** | Service management and timers |
| **Database Design** | SQLite with proper indexing |
| **Security Hardening** | UFW, fail2ban, principle of least privilege |

---

## 📊 Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| ipset lookup | O(1) | Hash table |
| Max blocked IPs | 65,536 | Configurable |
| Rate limit zone | 10MB | ~160,000 IPs |
| Parser overhead | <1% CPU | Async design |
| Database size | ~10MB/month | With regular traffic |

---

## 🚀 Quick Start for Reviewers

```bash
# 1. Clone repository
git clone https://github.com/mayursudosu/DDOS_Protector.git
cd DDOS_Protector

# 2. View demo dashboard (no installation needed)
cd dashboard
pip install flask werkzeug pyyaml
python3 app.py
# Open http://localhost:8080

# 3. For full installation (on Ubuntu Server)
sudo ./setup_ubuntu.sh
sudo ./install.sh
sudo ./test.sh
```

---

## 📝 Summary

DDOS Protector demonstrates:

1. **Systems Programming** - Bash scripting, systemd integration
2. **Network Security** - iptables, rate limiting, DDoS mitigation
3. **Web Development** - Flask, REST APIs, responsive dashboard
4. **Database Design** - SQLite schema, indexing, queries
5. **DevOps** - Service management, configuration, deployment
6. **Security Best Practices** - Defense in depth, least privilege

The modular architecture allows for easy extension with new detection methods, blocking mechanisms, or monitoring capabilities.

---

*Document prepared for academic presentation*
*DDOS Protector - Server-first HTTP Security Layer*
