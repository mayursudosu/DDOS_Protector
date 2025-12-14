#!/bin/bash
# =============================================================================
# DDOS Protector - Fedora Local Setup Script
# =============================================================================
# This script sets up DDOS Protector on your local Fedora machine for 
# demonstration purposes. You can then attack it from another terminal.
#
# Usage: sudo ./setup_fedora_local.sh
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${CYAN}"
echo "============================================================"
echo "   DDOS Protector - Fedora Local Setup"
echo "============================================================"
echo -e "${NC}"

# =============================================================================
# STEP 1: Install Dependencies
# =============================================================================
echo -e "${BLUE}[1/8]${NC} Installing dependencies..."

dnf install -y nginx python3 python3-pip ipset iptables sqlite >/dev/null 2>&1 || {
    echo -e "${YELLOW}Some packages may already be installed, continuing...${NC}"
}

# Install Python packages
pip3 install flask werkzeug pyyaml --quiet 2>/dev/null || pip install flask werkzeug pyyaml --quiet

echo -e "${GREEN}✓ Dependencies installed${NC}"

# =============================================================================
# STEP 2: Create Directories
# =============================================================================
echo -e "${BLUE}[2/8]${NC} Creating directories..."

mkdir -p /opt/scr-protector/{bin,logs,data}
mkdir -p /etc/nginx/snippets
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /var/log/scr-protector
mkdir -p /var/www/mysite

echo -e "${GREEN}✓ Directories created${NC}"

# =============================================================================
# STEP 3: Copy Files
# =============================================================================
echo -e "${BLUE}[3/8]${NC} Copying protection files..."

# Copy NGINX rate limiting config
cat > /etc/nginx/snippets/scr_protector.conf << 'EOF'
# DDOS Protector - Rate Limiting Configuration
# Included in server blocks to enable protection

# Rate limit zone (10 requests per second per IP)
limit_req_zone $binary_remote_addr zone=scr_limit:10m rate=10r/s;

# Apply rate limit with burst
limit_req zone=scr_limit burst=20 nodelay;

# Return 429 when rate limited
limit_req_status 429;

# Log rate limited requests
limit_req_log_level warn;
EOF

# Copy dashboard
cp -r "${SCRIPT_DIR}/dashboard" /opt/scr-protector/

echo -e "${GREEN}✓ Files copied${NC}"

# =============================================================================
# STEP 4: Create Database
# =============================================================================
echo -e "${BLUE}[4/8]${NC} Setting up database..."

sqlite3 /opt/scr-protector/data/events.db << 'EOF'
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    details TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
EOF

# Create admin user
python3 << 'PYEOF'
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('/opt/scr-protector/data/events.db')
conn.execute(
    'INSERT OR REPLACE INTO users (id, username, password_hash) VALUES (1, ?, ?)',
    ('rms', generate_password_hash('LinuxOS'))
)
conn.commit()
conn.close()
print("✓ Admin user created: rms / LinuxOS")
PYEOF

echo -e "${GREEN}✓ Database ready${NC}"

# =============================================================================
# STEP 5: Set Up ipset Blocklist
# =============================================================================
echo -e "${BLUE}[5/8]${NC} Setting up IP blocklist..."

# Create ipset (ignore if exists)
ipset create scr_blocklist hash:ip hashsize 4096 maxelem 100000 2>/dev/null || true

# Add iptables rule (check if not already added)
if ! iptables -C INPUT -m set --match-set scr_blocklist src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set scr_blocklist src -j DROP
fi

echo -e "${GREEN}✓ Blocklist ready${NC}"

# =============================================================================
# STEP 6: Create Demo Website
# =============================================================================
echo -e "${BLUE}[6/8]${NC} Creating demo website..."

cat > /var/www/mysite/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDOS Protector Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 {
            font-size: 3em;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .shield {
            font-size: 80px;
            margin-bottom: 20px;
        }
        p {
            font-size: 1.2em;
            color: #aaa;
            margin-bottom: 10px;
        }
        .status {
            display: inline-block;
            padding: 10px 20px;
            background: #00ff88;
            color: #000;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 20px;
        }
        .info {
            margin-top: 30px;
            padding: 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            text-align: left;
        }
        .info h3 { color: #00d2ff; margin-bottom: 10px; }
        .info ul { list-style: none; }
        .info li { padding: 5px 0; color: #ccc; }
        .info li::before { content: "✓ "; color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>DDOS Protector</h1>
        <p>Your server is protected!</p>
        <p>Try to attack this page from another terminal</p>
        <div class="status">PROTECTION ACTIVE</div>
        
        <div class="info">
            <h3>Protection Layers:</h3>
            <ul>
                <li>iptables - Kernel-level IP blocking</li>
                <li>NGINX - Rate limiting (10 req/sec)</li>
                <li>Dashboard - Real-time monitoring</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

# Create 429 error page (rate limit exceeded)
cat > /var/www/mysite/429.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Rate Limited - Slow Down!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #ff416c, #ff4b2b);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #fff;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(0,0,0,0.3);
            border-radius: 20px;
        }
        h1 { font-size: 4em; margin-bottom: 20px; }
        p { font-size: 1.3em; }
        .warning { font-size: 60px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">⚠️</div>
        <h1>429 - Too Many Requests</h1>
        <p>You've been rate limited!</p>
        <p>Please slow down and try again later.</p>
        <p style="margin-top:20px; font-size:0.9em; color:#ffc;">
            This means the DDOS protection is working!
        </p>
    </div>
</body>
</html>
EOF

# Set SELinux context
chcon -Rt httpd_sys_content_t /var/www/mysite 2>/dev/null || true

echo -e "${GREEN}✓ Demo website created${NC}"

# =============================================================================
# STEP 7: Configure NGINX
# =============================================================================
echo -e "${BLUE}[7/8]${NC} Configuring NGINX..."

# Create site config
cat > /etc/nginx/sites-available/mysite.conf << 'EOF'
server {
    listen 80 default_server;
    server_name _;
    
    # Include DDOS protection rate limiting
    include /etc/nginx/snippets/scr_protector.conf;
    
    root /var/www/mysite;
    index index.html;
    
    # Custom 429 error page
    error_page 429 /429.html;
    location = /429.html {
        internal;
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/mysite.conf /etc/nginx/sites-enabled/

# Update nginx.conf to include sites-enabled
if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
    sed -i '/http {/a \    include /etc/nginx/sites-enabled/*.conf;' /etc/nginx/nginx.conf
fi

# Remove default site if exists
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Disable default server in main config (Fedora specific)
if [ -f /etc/nginx/nginx.conf.default ]; then
    sed -i 's/listen.*80.*default_server/#&/' /etc/nginx/nginx.conf 2>/dev/null || true
fi

# Test and reload
nginx -t && systemctl restart nginx

echo -e "${GREEN}✓ NGINX configured${NC}"

# =============================================================================
# STEP 8: Final Setup
# =============================================================================
echo -e "${BLUE}[8/8]${NC} Final setup..."

# Set permissions
chmod 660 /opt/scr-protector/data/events.db
chown -R nginx:nginx /var/www/mysite

echo -e "${GREEN}✓ Setup complete!${NC}"

# =============================================================================
# PRINT INSTRUCTIONS
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   Setup Complete! Here's how to demo:${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "${GREEN}1. Test the website:${NC}"
echo -e "   Open browser: ${YELLOW}http://localhost${NC}"
echo ""
echo -e "${GREEN}2. Start the Dashboard (new terminal):${NC}"
echo -e "   ${YELLOW}cd ${SCRIPT_DIR}/dashboard${NC}"
echo -e "   ${YELLOW}python3 app.py${NC}"
echo -e "   Open: ${YELLOW}http://localhost:8080${NC}"
echo -e "   Login: ${YELLOW}rms / LinuxOS${NC}"
echo ""
echo -e "${GREEN}3. Attack from another terminal:${NC}"
echo -e "   ${YELLOW}for i in \$(seq 1 50); do curl -s http://localhost/ > /dev/null; done${NC}"
echo ""
echo -e "${GREEN}4. Watch the attack:${NC}"
echo -e "   ${YELLOW}sudo tail -f /var/log/nginx/access.log${NC}"
echo ""
echo -e "${GREEN}5. Block an IP manually:${NC}"
echo -e "   ${YELLOW}sudo ipset add scr_blocklist 192.168.1.100${NC}"
echo ""
echo -e "${GREEN}6. View blocked IPs:${NC}"
echo -e "   ${YELLOW}sudo ipset list scr_blocklist${NC}"
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   Your Website Files Location${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "   Website root: ${YELLOW}/var/www/mysite/${NC}"
echo ""
echo -e "   To add your own files:"
echo -e "   ${YELLOW}sudo cp your_file.html /var/www/mysite/${NC}"
echo -e "   ${YELLOW}sudo cp -r your_folder/ /var/www/mysite/${NC}"
echo ""
echo -e "${CYAN}============================================================${NC}"
