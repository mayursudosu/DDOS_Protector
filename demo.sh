#!/bin/bash
# =============================================================================
# DDOS Protector - Demo Script
# =============================================================================
# This script sets up a demo environment to showcase the dashboard
# without requiring full installation on Ubuntu Server.
#
# Usage: ./demo.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DB="/tmp/ddos_protector_demo.db"
DEMO_BLOCKLIST="/tmp/ddos_protector_demo_blocklist.txt"

echo -e "${CYAN}"
echo "============================================================"
echo "   DDOS Protector - Demo Mode"
echo "============================================================"
echo -e "${NC}"

# -----------------------------------------------------------------------------
# Step 1: Check dependencies
# -----------------------------------------------------------------------------
echo -e "${BLUE}[1/4]${NC} Checking dependencies..."

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: Python3 not found. Please install it first.${NC}"
    exit 1
fi

# Check for Flask
if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}Installing Flask and dependencies...${NC}"
    pip install flask werkzeug pyyaml --quiet 2>/dev/null || pip3 install flask werkzeug pyyaml --quiet
fi

echo -e "${GREEN}✓ Dependencies OK${NC}"

# -----------------------------------------------------------------------------
# Step 2: Create demo database with sample data
# -----------------------------------------------------------------------------
echo -e "${BLUE}[2/4]${NC} Creating demo database..."

python3 << 'PYTHON_SCRIPT'
import sqlite3
from datetime import datetime, timedelta
import random
import os

DB_PATH = "/tmp/ddos_protector_demo.db"

# Remove old demo db if exists
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)

# Create tables
conn.executescript('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    details TEXT
);

CREATE TABLE blocked_ips (
    ip TEXT PRIMARY KEY,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    notes TEXT
);

CREATE INDEX idx_events_ip ON events(ip);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_severity ON events(severity);
''')

# Add demo admin user with proper hashed password
from werkzeug.security import generate_password_hash
password_hash = generate_password_hash('LinuxOS')
conn.execute("INSERT INTO users (username, password_hash) VALUES ('rms', ?)", (password_hash,))

# Sample data
attacker_ips = [
    "185.220.101.42",   # Tor exit node
    "45.155.205.233",   # Known scanner
    "193.142.146.17",   # Brute forcer
    "5.188.206.14",     # Spam bot
]

internal_ips = [
    "192.168.1.100",
    "192.168.1.105", 
    "10.0.0.50",
]

event_types = [
    ("rate_limit", "INFO", "429 response, count: {}"),
    ("rate_limit", "WARN", "Rate limit exceeded {} times in 1 min"),
    ("high_rate", "WARN", "{} requests in 60 seconds"),
    ("ssh_failed", "INFO", "Failed SSH login attempt, count: {}"),
    ("ssh_failed", "WARN", "Multiple SSH failures, count: {}"),
    ("ssh_bruteforce", "ALERT", "{} failed logins in 5min - AUTO BLOCKED"),
    ("http_abuse", "ALERT", "{} suspicious events - AUTO BLOCKED"),
]

# Generate 75 events over last 24 hours
now = datetime.now()
for i in range(75):
    # Attackers are more likely to trigger events
    if random.random() < 0.7:
        ip = random.choice(attacker_ips)
    else:
        ip = random.choice(internal_ips)
    
    reason, severity, detail_template = random.choice(event_types)
    count = random.randint(1, 50)
    details = detail_template.format(count)
    
    # Random time in last 24 hours
    hours_ago = random.uniform(0, 24)
    ts = now - timedelta(hours=hours_ago)
    
    conn.execute(
        'INSERT INTO events (ip, ts, reason, severity, details) VALUES (?, ?, ?, ?, ?)',
        (ip, ts.strftime('%Y-%m-%d %H:%M:%S'), reason, severity, details)
    )

# Add blocked IPs
blocked = [
    ("185.220.101.42", "parser", "Auto-blocked: SSH brute force attack"),
    ("45.155.205.233", "parser", "Auto-blocked: HTTP abuse"),
    ("5.188.206.14", "dashboard", "Manual block - identified as spam bot"),
]
for ip, source, notes in blocked:
    conn.execute(
        'INSERT INTO blocked_ips (ip, source, notes) VALUES (?, ?, ?)',
        (ip, source, notes)
    )

conn.commit()
conn.close()

print("✓ Created demo database with:")
print("  - 75 sample security events")
print("  - 3 blocked IPs")
print("  - User: rms / LinuxOS")
PYTHON_SCRIPT

echo -e "${GREEN}✓ Demo database created${NC}"

# -----------------------------------------------------------------------------
# Step 3: Create empty blocklist file
# -----------------------------------------------------------------------------
echo -e "${BLUE}[3/4]${NC} Setting up demo environment..."
touch "$DEMO_BLOCKLIST"
echo -e "${GREEN}✓ Demo environment ready${NC}"

# -----------------------------------------------------------------------------
# Step 4: Start dashboard
# -----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   Starting Dashboard${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  ${GREEN}➜${NC}  Dashboard URL: ${YELLOW}http://localhost:8080/admin${NC}"
echo -e "  ${GREEN}➜${NC}  Login: ${YELLOW}rms${NC} / ${YELLOW}LinuxOS${NC} (auto-login enabled)"
echo -e "  ${GREEN}➜${NC}  Press ${RED}Ctrl+C${NC} to stop"
echo ""
echo -e "${CYAN}============================================================${NC}"
echo ""

cd "${SCRIPT_DIR}/dashboard"

python3 << PYTHON_DASHBOARD
import sys
sys.path.insert(0, '.')
import app

# Point to demo database
app.DB_PATH = "${DEMO_DB}"
app.BLOCKLIST_PATH = "${DEMO_BLOCKLIST}"
app.CONFIG['INSTALL_DIR'] = "/tmp"

# Auto-login for demo (skip authentication)
from flask import session
@app.app.before_request
def auto_login():
    session['user_id'] = 1
    session['username'] = 'rms'

# Disable secure cookie for localhost demo
app.app.config['SESSION_COOKIE_SECURE'] = False

print("\n🛡️  DDOS Protector Dashboard - DEMO MODE\n")
app.app.run(host='127.0.0.1', port=8080, debug=False)
PYTHON_DASHBOARD

# -----------------------------------------------------------------------------
# Cleanup on exit
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Cleaning up demo files...${NC}"
rm -f "$DEMO_DB" "$DEMO_BLOCKLIST" 2>/dev/null || true
echo -e "${GREEN}✓ Demo cleanup complete${NC}"
