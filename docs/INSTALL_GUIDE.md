# scr-protector Installation Guide for Beginners

This guide walks you through installing scr-protector on a fresh Ubuntu server and deploying your website with protection enabled. No prior experience required!

---

## Table of Contents

1. [What You'll Need](#what-youll-need)
2. [Part 1: Prepare Your Server](#part-1-prepare-your-server)
3. [Part 2: Install scr-protector](#part-2-install-scr-protector)
4. [Part 3: Deploy Your Website](#part-3-deploy-your-website)
5. [Part 4: Access the Dashboard](#part-4-access-the-dashboard)
6. [Part 5: Test Your Protection](#part-5-test-your-protection)
7. [Common Tasks](#common-tasks)
8. [Troubleshooting](#troubleshooting)

---

## What You'll Need

- **A server** running Ubuntu 22.04 or newer (works on Raspberry Pi too!)
- **SSH access** to your server (terminal/command line)
- **Root or sudo privileges** on the server
- **A domain name** (optional, but recommended for websites)

### Terminology for Beginners

| Term | What it means |
|------|---------------|
| **SSH** | A secure way to connect to your server remotely |
| **Terminal** | The command-line interface where you type commands |
| **sudo** | A command that runs things with administrator privileges |
| **NGINX** | The web server software that serves your website |
| **Firewall** | Software that blocks unwanted network traffic |

---

## Part 1: Prepare Your Server

### Step 1.1: Connect to Your Server

On your **local computer** (Mac/Linux), open Terminal and run:

```bash
ssh your-username@your-server-ip
```

On **Windows**, use [PuTTY](https://www.putty.org/) or Windows Terminal:

```powershell
ssh your-username@your-server-ip
```

Replace:
- `your-username` with your server username (often `ubuntu`, `root`, or custom)
- `your-server-ip` with your server's IP address (e.g., `203.0.113.50`)

**Example:**
```bash
ssh ubuntu@203.0.113.50
```

You'll be asked for your password. Type it (it won't show on screen) and press Enter.

### Step 1.2: Update Your Server

Once connected, update your system:

```bash
sudo apt update && sudo apt upgrade -y
```

This may take a few minutes. Wait for it to complete.

### Step 1.3: Install Git

```bash
sudo apt install git -y
```

---

## Part 2: Install scr-protector

### Step 2.1: Download scr-protector

```bash
cd ~
git clone https://github.com/yourusername/scr-protector.git
cd scr-protector
```

### Step 2.2: Run Initial Setup

This script prepares your server with security hardening:

```bash
sudo ./setup_ubuntu.sh
```

**What it will ask you:**

1. **Username to create** — Press Enter for default (`adminuser`) or type a custom name
2. **Password** — Create a strong password for this new user
3. **SSH public key** — If you have one, you can add it. Otherwise, type `n`
4. **Allow HTTP/HTTPS traffic** — Type `y` if you're hosting a website

**Example interaction:**
```
Enter sudo username to create [default: adminuser]: myuser
Set password for myuser:
********
Install SSH public key for myuser? [y/N]: n
Allow HTTP/HTTPS traffic now? [Y/n]: y
Create 1GB swap file? [y/N]: y
```

Wait for the script to complete. You'll see a summary of what was configured.

### Step 2.3: Install scr-protector

```bash
sudo ./install.sh
```

**What it will ask you:**

1. **Site root selection** — Press `1` to use the default `/var/www/html`
2. **Admin username** — Press Enter for `admin` or type a custom name
3. **Admin password** — Create a password for the dashboard (remember this!)

**Example interaction:**
```
Found existing site roots:
  [1] /var/www/html
  [0] Create new default site
Select site root [1]: 1

Enter dashboard admin username [admin]: admin
Enter dashboard admin password: ********
Confirm password: ********
```

### Step 2.4: Verify Installation

```bash
sudo ./test.sh
```

You should see mostly `[PASS]` results:

```
[PASS] NGINX configuration is valid
[PASS] ipset 'scr_blockset' exists
[PASS] Dashboard responding on 127.0.0.1:8080
...
All critical tests passed!
```

🎉 **Congratulations! scr-protector is now installed!**

---

## Part 3: Deploy Your Website

### Option A: Simple Static Website (HTML/CSS/JS)

#### Step 3.1: Upload Your Website Files

**From your local computer**, use `scp` to copy files:

```bash
# Copy a single file
scp index.html your-username@your-server-ip:/var/www/html/

# Copy an entire folder
scp -r ./my-website/* your-username@your-server-ip:/var/www/html/
```

**Or use SFTP** (with FileZilla or similar):
1. Connect to your server via SFTP
2. Navigate to `/var/www/html/`
3. Upload your website files

#### Step 3.2: Set Correct Permissions

```bash
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

#### Step 3.3: Test Your Website

Open a browser and go to: `http://your-server-ip`

You should see your website!

---

### Option B: WordPress Website

#### Step 3.1: Install Required Packages

```bash
sudo apt install php-fpm php-mysql php-xml php-mbstring php-curl mariadb-server -y
```

#### Step 3.2: Secure MariaDB

```bash
sudo mysql_secure_installation
```

Answer the prompts:
- Set root password: **Yes** (create a strong password)
- Remove anonymous users: **Yes**
- Disallow root login remotely: **Yes**
- Remove test database: **Yes**
- Reload privileges: **Yes**

#### Step 3.3: Create Database for WordPress

```bash
sudo mysql -u root -p
```

Enter the password you just created, then run:

```sql
CREATE DATABASE wordpress;
CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Remember these credentials!** You'll need them later.

#### Step 3.4: Download WordPress

```bash
cd /tmp
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
sudo mv wordpress/* /var/www/html/
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

#### Step 3.5: Configure NGINX for WordPress

Create a new configuration:

```bash
sudo nano /etc/nginx/sites-available/wordpress
```

Paste this configuration (press `Ctrl+Shift+V` to paste):

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    root /var/www/html;
    index index.php index.html;

    # Include scr-protector
    include /etc/nginx/snippets/scr_protector.conf;
    limit_req zone=scr_limit burst=20 nodelay;
    error_page 429 = /__scr_challenge;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
```

Replace `your-domain.com` with your actual domain.

Save and exit: `Ctrl+X`, then `Y`, then `Enter`

#### Step 3.6: Enable the Site

```bash
sudo ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

#### Step 3.7: Complete WordPress Setup

1. Open your browser: `http://your-domain.com` or `http://your-server-ip`
2. Select your language
3. Enter database details:
   - Database Name: `wordpress`
   - Username: `wpuser`
   - Password: (the password you created)
   - Database Host: `localhost`
   - Table Prefix: `wp_`
4. Click "Run the installation"
5. Set up your site title and admin account

---

### Option C: Node.js Application

#### Step 3.1: Install Node.js

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs -y
```

Verify installation:
```bash
node --version
npm --version
```

#### Step 3.2: Upload Your Application

```bash
# Create app directory
sudo mkdir -p /var/www/myapp
sudo chown $USER:$USER /var/www/myapp

# From your local machine, copy your app:
scp -r ./my-node-app/* your-username@your-server-ip:/var/www/myapp/
```

#### Step 3.3: Install Dependencies and Start

```bash
cd /var/www/myapp
npm install
```

#### Step 3.4: Install PM2 (Process Manager)

```bash
sudo npm install -g pm2
pm2 start app.js --name "myapp"
pm2 startup
pm2 save
```

#### Step 3.5: Configure NGINX as Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/myapp
```

Paste:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Include scr-protector
    include /etc/nginx/snippets/scr_protector.conf;
    limit_req zone=scr_limit burst=20 nodelay;
    error_page 429 = /__scr_challenge;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

### Option D: Python Flask/Django Application

#### Step 3.1: Install Python and Dependencies

```bash
sudo apt install python3 python3-pip python3-venv -y
```

#### Step 3.2: Set Up Your Application

```bash
# Create app directory
sudo mkdir -p /var/www/myflaskapp
sudo chown $USER:$USER /var/www/myflaskapp
cd /var/www/myflaskapp

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install your dependencies
pip install flask gunicorn
# Or for Django:
# pip install django gunicorn
```

#### Step 3.3: Create a Simple Flask App (Example)

```bash
nano app.py
```

Paste:

```python
from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return '<h1>Hello! Protected by scr-protector</h1>'

if __name__ == '__main__':
    app.run()
```

#### Step 3.4: Create Systemd Service

```bash
sudo nano /etc/systemd/system/myflaskapp.service
```

Paste:

```ini
[Unit]
Description=My Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/myflaskapp
Environment="PATH=/var/www/myflaskapp/venv/bin"
ExecStart=/var/www/myflaskapp/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable myflaskapp
sudo systemctl start myflaskapp
```

#### Step 3.5: Configure NGINX

```bash
sudo nano /etc/nginx/sites-available/myflaskapp
```

Paste:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Include scr-protector
    include /etc/nginx/snippets/scr_protector.conf;
    limit_req zone=scr_limit burst=20 nodelay;
    error_page 429 = /__scr_challenge;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable:

```bash
sudo ln -s /etc/nginx/sites-available/myflaskapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Part 4: Access the Dashboard

The dashboard is **only accessible via SSH tunnel** for security.

### Step 4.1: Create SSH Tunnel

**On your local computer**, run:

```bash
ssh -L 8080:localhost:8080 your-username@your-server-ip
```

This creates a secure tunnel. Keep this terminal window open!

### Step 4.2: Open Dashboard

While the tunnel is active, open your browser and go to:

```
http://localhost:8080/admin
```

Log in with the admin credentials you created during installation.

### What You'll See

- **Events Today** — Number of security events logged
- **Alerts Today** — High-severity events
- **Blocked IPs** — Currently blocked IP addresses
- **Rate Limits** — Number of rate-limited requests

---

## Part 5: Test Your Protection

### Test Rate Limiting

Run this command to send many requests quickly:

```bash
for i in {1..30}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/; done
```

After about 20 requests, you should see `429` responses (rate limited).

### Check Blocked IPs

```bash
sudo ipset list scr_blockset
```

### View Security Events

Check the dashboard or run:

```bash
sqlite3 /opt/scr-protector/dashboard.db "SELECT * FROM events ORDER BY ts DESC LIMIT 10;"
```

---

## Common Tasks

### Manually Block an IP

```bash
echo "1.2.3.4" | sudo tee -a /opt/scr-protector/blocklist.txt
sudo /opt/scr-protector/bin/apply_blocklist.sh
```

### Unblock an IP

```bash
sudo sed -i '/1.2.3.4/d' /opt/scr-protector/blocklist.txt
sudo /opt/scr-protector/bin/apply_blocklist.sh
```

### View Service Logs

```bash
# Dashboard logs
journalctl -u scr-protector-dashboard -f

# Parser logs
journalctl -u scr-protector-parser -f

# NGINX logs
sudo tail -f /var/log/nginx/access.log
```

### Restart Services

```bash
sudo systemctl restart scr-protector-dashboard
sudo systemctl restart scr-protector-parser
sudo systemctl restart nginx
```

### Change Configuration

Edit the config file:

```bash
sudo nano /opt/scr-protector/config.yaml
```

Then restart services:

```bash
sudo systemctl restart scr-protector-dashboard
sudo systemctl restart scr-protector-parser
```

### Add SSL Certificate (HTTPS)

Install Certbot:

```bash
sudo apt install certbot python3-certbot-nginx -y
```

Get certificate:

```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

Certbot will automatically configure NGINX for HTTPS.

---

## Troubleshooting

### "Permission denied" errors

Run commands with `sudo`:
```bash
sudo ./install.sh
```

### NGINX won't start

Check configuration:
```bash
sudo nginx -t
```

Look for syntax errors in the output and fix them.

### Can't access website

Check if NGINX is running:
```bash
sudo systemctl status nginx
```

Check firewall:
```bash
sudo ufw status
```

Make sure ports 80 and 443 are allowed:
```bash
sudo ufw allow 'Nginx Full'
```

### Dashboard not loading

Check if service is running:
```bash
sudo systemctl status scr-protector-dashboard
```

Make sure your SSH tunnel is active.

### Rate limiting too aggressive

Edit config to increase limits:
```bash
sudo nano /opt/scr-protector/config.yaml
```

Change:
```yaml
RATE_LIMIT: 20r/s    # Increase from 10r/s
BURST: 40            # Increase from 20
```

Then update NGINX and restart:
```bash
sudo systemctl restart nginx
```

### Getting locked out by rate limiting

If you're testing and getting blocked:

```bash
# Clear the blocklist
sudo truncate -s 0 /opt/scr-protector/blocklist.txt
sudo /opt/scr-protector/bin/apply_blocklist.sh
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Check service status | `sudo systemctl status scr-protector-dashboard` |
| View blocked IPs | `sudo ipset list scr_blockset` |
| Block an IP | `echo "IP" \| sudo tee -a /opt/scr-protector/blocklist.txt` |
| Apply blocklist | `sudo /opt/scr-protector/bin/apply_blocklist.sh` |
| Restart all services | `sudo systemctl restart scr-protector-{dashboard,parser} nginx` |
| View logs | `journalctl -u scr-protector-dashboard -f` |
| Run tests | `sudo ./test.sh` |
| SSH tunnel for dashboard | `ssh -L 8080:localhost:8080 user@server` |

---

## Getting Help

- **Documentation**: Read the [README.md](README.md)
- **Issues**: Open an issue on GitHub
- **Logs**: Check `journalctl` for error messages

---

**You're all set!** Your server is now protected by scr-protector. 🛡️
