# Arch Linux Deployment Guide

**DDOS Protector setup for Arch Linux (with or without GUI)**

---

## Prerequisites

Update your system first:

```bash
sudo pacman -Syu
```

---

## Step 1: Install Dependencies

```bash
# Core packages
sudo pacman -S --noconfirm git nginx python python-pip python-virtualenv \
    ipset iptables sqlite ufw fail2ban

# Enable services
sudo systemctl enable --now nginx
sudo systemctl enable --now fail2ban
```

---

## Step 2: Clone the Repository

```bash
cd ~
git clone https://github.com/mayursudosu/DDOS_Protector.git
cd DDOS_Protector
chmod +x *.sh
```

---

## Step 3: Create System User

```bash
# Create dedicated user for the service
sudo useradd -r -s /usr/bin/nologin scr-protector
```

---

## Step 4: Set Up Firewall (UFW)

```bash
# Enable UFW
sudo systemctl enable --now ufw

# Allow SSH (important - don't lock yourself out!)
sudo ufw allow ssh

# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

---

## Step 5: Manual Installation (Arch-Compatible)

Since `install.sh` is Ubuntu-focused, here's the manual setup:

### Create directories

```bash
sudo mkdir -p /opt/scr-protector/{bin,logs,data}
sudo mkdir -p /etc/nginx/snippets
sudo mkdir -p /var/log/scr-protector
```

### Copy core files

```bash
# Copy scripts
sudo cp core/parser.py /opt/scr-protector/bin/
sudo cp core/apply_blocklist.sh /opt/scr-protector/bin/
sudo chmod +x /opt/scr-protector/bin/*.sh

# Copy NGINX config
sudo cp nginx/scr_protector.conf /etc/nginx/snippets/

# Copy dashboard
sudo cp -r dashboard /opt/scr-protector/
```

### Set up Python virtual environment

```bash
cd /opt/scr-protector
sudo python -m venv venv
sudo /opt/scr-protector/venv/bin/pip install flask werkzeug pyyaml gunicorn
```

### Create config file

```bash
sudo tee /opt/scr-protector/config.yaml << 'EOF'
# DDOS Protector Configuration
rate_limit:
  requests_per_second: 10
  burst: 20

auto_block:
  enabled: true
  threshold: 50
  window_seconds: 60

dashboard:
  host: 127.0.0.1
  port: 8080

logging:
  level: INFO
  file: /var/log/scr-protector/parser.log
EOF
```

### Initialize database

```bash
sudo sqlite3 /opt/scr-protector/data/events.db << 'EOF'
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
```

### Create admin user

```bash
# Create admin user with password
sudo /opt/scr-protector/venv/bin/python3 << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash

username = "rms"
password = "LinuxOS"

conn = sqlite3.connect('/opt/scr-protector/data/events.db')
conn.execute(
    'INSERT OR REPLACE INTO users (id, username, password_hash) VALUES (1, ?, ?)',
    (username, generate_password_hash(password))
)
conn.commit()
conn.close()
print(f"✓ Created user: {username}")
EOF
```

### Set permissions

```bash
sudo chown -R scr-protector:scr-protector /opt/scr-protector
sudo chown -R scr-protector:scr-protector /var/log/scr-protector
sudo chmod 750 /opt/scr-protector
sudo chmod 660 /opt/scr-protector/data/events.db
```

---

## Step 6: Create Systemd Services

### Parser Service

```bash
sudo tee /etc/systemd/system/scr-protector-parser.service << 'EOF'
[Unit]
Description=DDOS Protector Log Parser
After=network.target nginx.service

[Service]
Type=simple
User=root
ExecStart=/opt/scr-protector/venv/bin/python /opt/scr-protector/bin/parser.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### Dashboard Service

```bash
sudo tee /etc/systemd/system/scr-protector-dashboard.service << 'EOF'
[Unit]
Description=DDOS Protector Dashboard
After=network.target

[Service]
Type=simple
User=scr-protector
Group=scr-protector
WorkingDirectory=/opt/scr-protector/dashboard
Environment="PATH=/opt/scr-protector/venv/bin"
ExecStart=/opt/scr-protector/venv/bin/gunicorn -w 2 -b 127.0.0.1:8080 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and start services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scr-protector-parser
sudo systemctl enable --now scr-protector-dashboard
```

---

## Step 7: Set Up ipset Blocklist

```bash
# Create the ipset
sudo ipset create scr_blocklist hash:ip hashsize 4096 maxelem 100000 2>/dev/null || true

# Add iptables rule to drop blocked IPs
sudo iptables -I INPUT -m set --match-set scr_blocklist src -j DROP

# Make ipset persistent (create a service)
sudo tee /etc/systemd/system/ipset-restore.service << 'EOF'
[Unit]
Description=Restore ipset rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/bin/ipset create scr_blocklist hash:ip hashsize 4096 maxelem 100000 -exist
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable ipset-restore
```

---

## Step 8: Configure Your Website

### Option A: Static Site

```bash
sudo mkdir -p /var/www/mysite
echo '<h1>Hello from Arch!</h1>' | sudo tee /var/www/mysite/index.html

sudo tee /etc/nginx/sites-available/mysite << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Include DDOS protection
    include /etc/nginx/snippets/scr_protector.conf;
    
    root /var/www/mysite;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

# Create sites-enabled directory (Arch doesn't have it by default)
sudo mkdir -p /etc/nginx/sites-enabled

# Enable the site
sudo ln -sf /etc/nginx/sites-available/mysite /etc/nginx/sites-enabled/
```

### Update nginx.conf to include sites-enabled

```bash
# Check if include line exists, if not add it
if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
    sudo sed -i '/http {/a \    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
fi

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

### Option B: Reverse Proxy

```bash
# Make sure directories exist first!
sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

sudo tee /etc/nginx/sites-available/myapp << 'EOF'
server {
    listen 80;
    server_name _;
    
    include /etc/nginx/snippets/scr_protector.conf;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Step 9: Add HTTPS (Optional)

```bash
# Install certbot
sudo pacman -S --noconfirm certbot certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal timer (already enabled by pacman)
sudo systemctl enable --now certbot-renew.timer
```

---

## Step 10: Verify Installation

```bash
# Check all services
echo "=== Service Status ==="
sudo systemctl status nginx --no-pager -l
sudo systemctl status scr-protector-parser --no-pager -l
sudo systemctl status scr-protector-dashboard --no-pager -l

# Check firewall
echo -e "\n=== Firewall ==="
sudo ufw status

# Check ipset
echo -e "\n=== Blocklist ==="
sudo ipset list scr_blocklist 2>/dev/null | head -10

# Check NGINX config
echo -e "\n=== NGINX Test ==="
sudo nginx -t
```

---

## Step 11: Access Dashboard

```bash
# From your local machine (SSH tunnel)
ssh -L 8080:localhost:8080 user@YOUR_SERVER_IP

# Then open browser: http://localhost:8080
# Login: rms / LinuxOS
```

Or if running locally with GUI, just open: **http://localhost:8080**

---

## Quick Test

```bash
# Simulate traffic (from another terminal)
for i in {1..30}; do curl -s http://localhost/ > /dev/null; done

# Check logs
sudo tail -f /var/log/nginx/access.log
```

---

## Arch-Specific Notes

| Ubuntu | Arch |
|--------|------|
| `apt install` | `pacman -S` |
| `apt update` | `pacman -Sy` |
| `apt upgrade` | `pacman -Syu` |
| `www-data` user | `http` user |
| `/etc/nginx/sites-available/` | Create manually |
| `certbot` | `certbot` (same) |

---

## Quick Reference

| Task | Command |
|------|---------|
| Restart NGINX | `sudo systemctl restart nginx` |
| Restart parser | `sudo systemctl restart scr-protector-parser` |
| Restart dashboard | `sudo systemctl restart scr-protector-dashboard` |
| View logs | `sudo journalctl -u scr-protector-parser -f` |
| Block IP | `sudo ipset add scr_blocklist 1.2.3.4` |
| Unblock IP | `sudo ipset del scr_blocklist 1.2.3.4` |
| List blocked | `sudo ipset list scr_blocklist` |

---

## Uninstall

```bash
# Stop services
sudo systemctl stop scr-protector-parser scr-protector-dashboard
sudo systemctl disable scr-protector-parser scr-protector-dashboard

# Remove files
sudo rm -rf /opt/scr-protector
sudo rm /etc/systemd/system/scr-protector-*.service
sudo rm /etc/nginx/snippets/scr_protector.conf

# Remove ipset
sudo ipset destroy scr_blocklist 2>/dev/null

# Reload systemd
sudo systemctl daemon-reload

echo "✓ DDOS Protector removed"
```

---

## Running Demo Mode (No Full Install)

If you just want to see the dashboard:

```bash
cd ~/DDOS_Protector
./demo.sh
```

This runs a demo with sample data - no root required!

---

**Works on Arch, Manjaro, EndeavourOS, and other Arch-based distros! 🐧**
