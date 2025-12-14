# Fedora Deployment Guide

**DDOS Protector setup for Fedora Workstation/Server**

---

## 🚀 Quick Local Setup (Recommended for Demo)

If you want to quickly set up everything for a demo:

```bash
cd ~/DDOS_Protector
chmod +x setup_fedora_local.sh
sudo ./setup_fedora_local.sh
```

This script:
- Installs all dependencies
- Sets up NGINX with rate limiting
- Creates a demo website at `/var/www/mysite/`
- Configures ipset blocklist
- Creates the database and admin user

Then you can attack from another terminal to demo!

---

## Prerequisites

Update your system first:

```bash
sudo dnf upgrade --refresh -y
```

---

## Step 1: Install Dependencies

```bash
# Core packages
sudo dnf install -y git nginx python3 python3-pip python3-virtualenv \
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
sudo useradd -r -s /sbin/nologin scr-protector
```

---

## Step 4: Set Up Firewall

Fedora uses `firewalld` by default, but we'll use UFW for consistency:

```bash
# Install and enable UFW
sudo dnf install -y ufw
sudo systemctl enable --now ufw

# Allow SSH (important!)
sudo ufw allow ssh

# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

**Alternative: Using firewalld (Fedora default)**

```bash
# If you prefer firewalld instead of UFW:
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

---

## Step 5: Manual Installation

### Create directories

```bash
sudo mkdir -p /opt/scr-protector/{bin,logs,data}
sudo mkdir -p /etc/nginx/snippets
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled
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
sudo python3 -m venv venv
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

# Make ipset persistent
sudo tee /etc/systemd/system/ipset-restore.service << 'EOF'
[Unit]
Description=Restore ipset rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ipset create scr_blocklist hash:ip hashsize 4096 maxelem 100000 -exist
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable ipset-restore
```

---

## Step 8: Configure NGINX

### Update nginx.conf to include sites-enabled

```bash
# Add include line if not present
if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
    sudo sed -i '/http {/a \    include /etc/nginx/sites-enabled/*.conf;' /etc/nginx/nginx.conf
fi
```

### Option A: Static Site

```bash
sudo mkdir -p /var/www/mysite
echo '<h1>Hello from Fedora!</h1>' | sudo tee /var/www/mysite/index.html

sudo tee /etc/nginx/sites-available/mysite.conf << 'EOF'
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

# Enable the site
sudo ln -sf /etc/nginx/sites-available/mysite.conf /etc/nginx/sites-enabled/

# Set SELinux context (Fedora uses SELinux)
sudo chcon -Rt httpd_sys_content_t /var/www/mysite

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

### Option B: Reverse Proxy

```bash
sudo tee /etc/nginx/sites-available/myapp.conf << 'EOF'
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

sudo ln -sf /etc/nginx/sites-available/myapp.conf /etc/nginx/sites-enabled/

# Allow NGINX to connect to network (SELinux)
sudo setsebool -P httpd_can_network_connect 1

sudo nginx -t && sudo systemctl reload nginx
```

---

## Step 9: SELinux Configuration (Important for Fedora!)

Fedora has SELinux enabled by default. You may need these:

```bash
# Allow NGINX to read custom configs
sudo semanage fcontext -a -t httpd_config_t "/etc/nginx/snippets(/.*)?"
sudo restorecon -Rv /etc/nginx/snippets

# Allow NGINX to connect to backend apps (for reverse proxy)
sudo setsebool -P httpd_can_network_connect 1

# Allow NGINX to read web content
sudo chcon -Rt httpd_sys_content_t /var/www/

# Check for SELinux denials
sudo ausearch -m avc -ts recent
```

If you're having issues, temporarily set SELinux to permissive for testing:

```bash
# Temporary (resets on reboot)
sudo setenforce 0

# Check current mode
getenforce
```

---

## Step 10: Add HTTPS (Optional)

```bash
# Install certbot
sudo dnf install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com

# Enable auto-renewal timer
sudo systemctl enable --now certbot-renew.timer
```

---

## Step 11: Verify Installation

```bash
# Check all services
echo "=== Service Status ==="
sudo systemctl status nginx --no-pager -l
sudo systemctl status scr-protector-parser --no-pager -l
sudo systemctl status scr-protector-dashboard --no-pager -l

# Check firewall
echo -e "\n=== Firewall ==="
sudo ufw status  # or: sudo firewall-cmd --list-all

# Check ipset
echo -e "\n=== Blocklist ==="
sudo ipset list scr_blocklist 2>/dev/null | head -10

# Check NGINX config
echo -e "\n=== NGINX Test ==="
sudo nginx -t

# Check SELinux
echo -e "\n=== SELinux ==="
getenforce
```

---

## Step 12: Access Dashboard

```bash
# If running locally with GUI, just open:
# http://localhost:8080

# From remote machine (SSH tunnel):
ssh -L 8080:localhost:8080 user@YOUR_SERVER_IP
# Then open: http://localhost:8080

# Login: rms / LinuxOS
```

---

## Quick Test

```bash
# Simulate traffic
for i in {1..30}; do curl -s http://localhost/ > /dev/null; done

# Check logs
sudo tail -f /var/log/nginx/access.log
```

---

## Fedora-Specific Notes

| Ubuntu/Debian | Fedora |
|---------------|--------|
| `apt install` | `dnf install` |
| `apt update` | `dnf check-update` |
| `apt upgrade` | `dnf upgrade` |
| `www-data` user | `nginx` user |
| No SELinux | SELinux enabled |
| `ufw` default | `firewalld` default |
| `/usr/bin/nologin` | `/sbin/nologin` |

---

## Troubleshooting SELinux

If something doesn't work, check SELinux first:

```bash
# View recent denials
sudo ausearch -m avc -ts recent

# Generate fix suggestions
sudo ausearch -m avc -ts recent | audit2why

# Create custom policy (if needed)
sudo ausearch -m avc -ts recent | audit2allow -M mypolicy
sudo semodule -i mypolicy.pp
```

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
| Check SELinux | `getenforce` |
| SELinux permissive | `sudo setenforce 0` |

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
sudo rm -rf /etc/nginx/sites-available /etc/nginx/sites-enabled

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

## 📁 Adding Your Website Files

Your website files go in: `/var/www/mysite/`

### Add Single Files

```bash
# Copy HTML file
sudo cp mypage.html /var/www/mysite/

# Copy CSS/JS files
sudo cp style.css /var/www/mysite/
sudo cp script.js /var/www/mysite/

# Copy images
sudo cp -r images/ /var/www/mysite/
```

### Add a Complete Website Folder

```bash
# Copy entire folder contents
sudo cp -r my-website/* /var/www/mysite/

# Or create a subdirectory
sudo cp -r my-project/ /var/www/mysite/project/
```

### Fix Permissions After Adding Files

```bash
# Set correct ownership
sudo chown -R nginx:nginx /var/www/mysite/

# Set correct permissions
sudo chmod -R 755 /var/www/mysite/

# Fix SELinux context
sudo chcon -Rt httpd_sys_content_t /var/www/mysite/
```

### Example: Add a React/Vue Build

```bash
# Build your app
cd my-react-app
npm run build

# Copy build output to server
sudo cp -r build/* /var/www/mysite/

# Fix permissions
sudo chown -R nginx:nginx /var/www/mysite/
sudo chcon -Rt httpd_sys_content_t /var/www/mysite/
```

### Example: Add PHP Files (if using PHP)

```bash
# Install PHP-FPM
sudo dnf install -y php-fpm php-common

# Start PHP-FPM
sudo systemctl enable --now php-fpm

# Add PHP file
sudo tee /var/www/mysite/info.php << 'EOF'
<?php phpinfo(); ?>
EOF

# Update NGINX config to handle PHP (edit /etc/nginx/sites-available/mysite.conf)
```

### Verify Your Files

```bash
# List files in website root
ls -la /var/www/mysite/

# Test in browser
curl http://localhost/

# Check NGINX can read them
sudo -u nginx cat /var/www/mysite/index.html
```

---

## 🎯 Demo Attack Commands

### Terminal 1: Watch the logs
```bash
sudo tail -f /var/log/nginx/access.log
```

### Terminal 2: Run the attack
```bash
# Simple flood (will trigger 429 after ~20 requests)
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/; done

# Faster attack
for i in $(seq 1 100); do curl -s -o /dev/null http://localhost/ & done; wait

# See the 429 responses
curl -I http://localhost/
```

### Terminal 3: Run the dashboard
```bash
cd ~/DDOS_Protector/dashboard
python3 app.py
# Open http://localhost:8080
```

### Block an attacker
```bash
# Block IP
sudo ipset add scr_blocklist 127.0.0.1

# Now requests will be dropped completely
curl http://localhost/  # Will timeout/fail

# Unblock
sudo ipset del scr_blocklist 127.0.0.1
```

---

**Works on Fedora Workstation, Fedora Server, and RHEL-based distros! 🎩**
