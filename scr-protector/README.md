# scr-protector

**Server-first HTTP security layer for Ubuntu Server (including Raspberry Pi)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

scr-protector is a lightweight, server-first security layer designed to protect your web server from HTTP abuse, brute-force attacks, and malicious traffic. It works **even if no website is deployed yet** — protecting the default NGINX landing page out of the box.

## 🛡️ Features

- **HTTP Rate Limiting** — NGINX-based rate limiting with configurable thresholds
- **Automatic IP Blocking** — Suspicious IPs are automatically added to ipset blocklist
- **Challenge Page** — Temporary challenge for rate-limited clients (Anubis placeholder ready)
- **Local Dashboard** — Flask-based admin panel for monitoring and management
- **SSH Brute-Force Detection** — Monitors auth.log for failed login attempts
- **Alert System** — Severity-based alerting (INFO, WARN, ALERT)
- **Zero-Website Mode** — Protects default NGINX page if no site is configured
- **Raspberry Pi Support** — Optimized for low-resource ARM64/ARMv7 devices

## 📋 Requirements

- Ubuntu Server 22.04+ (arm64 or amd64)
- Root/sudo access
- Internet connection (for package installation)

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/scr-protector.git
cd scr-protector

# Run initial server setup (creates user, configures firewall, installs packages)
sudo ./setup_ubuntu.sh

# Install scr-protector
sudo ./install.sh

# Verify installation
sudo ./test.sh
```

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INCOMING TRAFFIC                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IPTABLES / IPSET                                   │
│                      (scr_blockset: blocked IPs)                             │
│                             DROP if matched                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NGINX                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    Rate Limiting (10r/s burst=20)                        ││
│  │                         limit_req zone=scr_limit                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                       │                                      │
│                         ┌─────────────┴─────────────┐                        │
│                         │                           │                        │
│                    Under Limit              Over Limit (429)                 │
│                         │                           │                        │
│                         ▼                           ▼                        │
│                   Normal Request           Challenge Page                    │
│                                        (/__scr_challenge)                    │
│                                                                              │
│  [ ANUBIS PLACEHOLDER: Insert Layer-0 anti-bot challenge here ]              │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOG PARSER (parser.py)                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  • Tails nginx access.log                                             │   │
│  │  • Tracks per-IP request rates (sliding window)                       │   │
│  │  • Detects 429 responses                                              │   │
│  │  • Monitors auth.log for SSH failures                                 │   │
│  │  • Writes events to SQLite database                                   │   │
│  │  • AUTO-BLOCKS IPs exceeding thresholds                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLOCKLIST + APPLY SCRIPT                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  blocklist.txt → apply_blocklist.sh → ipset scr_blockset             │   │
│  │  Runs every 30 seconds via systemd timer                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DASHBOARD (Flask + SQLite)                           │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  • Blocked IPs list with unblock button                              │   │
│  │  • Recent events timeline                                             │   │
│  │  • Alerts tab (WARN + ALERT severity)                                │   │
│  │  • Statistics and graphs                                             │   │
│  │  • Manual IP block/unblock                                           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                       Binds to 127.0.0.1:8080 only                          │
│                      Access via SSH tunnel                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🔐 Security Principles

1. **Ports Closed by Default** — UFW denies all incoming traffic except SSH. HTTP/HTTPS only opened on explicit user approval.

2. **Dashboard Never Public** — The admin dashboard binds to `127.0.0.1:8080` only. Access it via SSH tunnel.

3. **Idempotent Scripts** — All installation scripts can be safely re-run without breaking the system.

4. **Automatic Backups** — Configuration files are backed up to `/var/backups/scr-protector/` before modification.

5. **Fail-Safe NGINX** — Configuration is validated with `nginx -t` before reload; backup restored on failure.

## 📱 Accessing the Dashboard

The dashboard is intentionally not exposed to the internet. Access it securely via SSH tunnel:

```bash
# From your local machine:
ssh -L 8080:localhost:8080 user@your-server-ip

# Then open in your browser:
http://localhost:8080/admin
```

To allow public dashboard access (not recommended):
```yaml
# In /opt/scr-protector/config.yaml
ALLOW_DASHBOARD_PUBLIC: true
DASHBOARD_BIND: 0.0.0.0
```

Then add UFW rule: `sudo ufw allow 8080/tcp`

## ⚠️ Alert System

scr-protector uses a three-tier severity system:

| Severity | Description | Action |
|----------|-------------|--------|
| **INFO** | Normal events, logging only | None |
| **WARN** | Suspicious activity detected | Logged for review |
| **ALERT** | High-severity threat | Auto-block triggered |

### Alert Thresholds (configurable in `config.yaml`):

- **HTTP Abuse**: >5 rate-limit hits (429) in 1 minute → WARN
- **HTTP Abuse**: >7 suspicious events in 10 minutes → ALERT → Auto-block
- **SSH Abuse**: >5 failed logins in 5 minutes → ALERT → Auto-block

⚠️ **False Positives**: Thresholds are configurable. Adjust based on your traffic patterns.

## 🌐 Hosting a Website

scr-protector works with any website. To add protection to your site:

### Option 1: Default Site (/var/www/html)
Place your files in `/var/www/html`. Protection is automatic.

### Option 2: Custom Server Block
Add to your NGINX server block:

```nginx
server {
    listen 80;
    server_name example.com;
    
    # Include scr-protector
    include /etc/nginx/snippets/scr_protector.conf;
    
    # Apply rate limiting
    limit_req zone=scr_limit burst=20 nodelay;
    
    # Redirect rate-limited requests to challenge
    error_page 429 = /__scr_challenge;
    
    # Your site configuration...
    root /var/www/example.com;
    index index.html;
}
```

### Option 3: Auto-Configure (during install)
```bash
sudo ./install.sh --auto-nginx
```

## 🔧 Configuration

Edit `/opt/scr-protector/config.yaml`:

```yaml
# Rate limiting
RATE_LIMIT: 10r/s
BURST: 20

# Auto-blocking
AUTO_BLOCK_ENABLED: true
ALERT_THRESHOLD_HTTP: 7
ALERT_THRESHOLD_SSH: 5

# SSH monitoring
SSH_ANALYTICS_ENABLED: true
```

After changing configuration:
```bash
sudo systemctl restart scr-protector-parser
sudo systemctl restart scr-protector-dashboard
```

## 📝 Anubis Integration

scr-protector supports [Anubis](https://anubis.techaro.lol) for Layer-0 anti-bot protection. Anubis provides browser-based challenges that distinguish humans from bots before they reach your application.

### Setup Instructions

1. **Register with Anubis**
   - Go to [https://anubis.techaro.lol](https://anubis.techaro.lol)
   - Create an account and register your domain
   - Obtain your site key and client configuration

2. **Add Anubis Script to Your Website**
   
   Add the following to your website's `<head>` section:
   ```html
   <script src="https://anubis.techaro.lol/static/js/anubis.js" data-sitekey="YOUR_SITE_KEY"></script>
   <noscript><meta http-equiv="refresh" content="0; url=/__scr_challenge"></noscript>
   ```

3. **Enable Anubis in Configuration**
   ```yaml
   # In /opt/scr-protector/config.yaml
   USE_ANUBIS: true
   ```

4. **Re-run Installation or Restart Services**
   ```bash
   sudo ./install.sh
   # Or just restart services:
   sudo systemctl restart scr-protector-dashboard
   ```

### How It Works

- When `USE_ANUBIS=true`, the local JavaScript challenge (`challenge.html`) is disabled
- Anubis handles bot verification at the browser level before requests reach NGINX
- Rate-limited clients (429) are still redirected to `/__scr_challenge` as a fallback
- The dashboard shows "Anubis layer active" when enabled

### Fallback Behavior

- If `USE_ANUBIS=false` (default), the built-in JavaScript challenge is used
- The local challenge provides basic bot protection without external dependencies
- You can switch between modes by changing the config and restarting services

## 🛠️ Management Commands

```bash
# View service status
sudo systemctl status scr-protector-dashboard
sudo systemctl status scr-protector-parser
sudo systemctl status scr-protector-blocker.timer

# View logs
journalctl -u scr-protector-dashboard -f
journalctl -u scr-protector-parser -f

# Manually block an IP
echo "1.2.3.4" | sudo tee -a /opt/scr-protector/blocklist.txt
sudo /opt/scr-protector/bin/apply_blocklist.sh

# View blocked IPs
sudo ipset list scr_blockset

# Unblock an IP
sudo sed -i '/1.2.3.4/d' /opt/scr-protector/blocklist.txt
sudo /opt/scr-protector/bin/apply_blocklist.sh

# Run diagnostics
sudo ./test.sh
```

## 🗑️ Uninstallation

```bash
sudo ./uninstall.sh
```

The uninstaller will ask for confirmation before removing each component.

## 📁 File Structure

```
/opt/scr-protector/
├── config.yaml           # Configuration
├── dashboard.db          # SQLite database
├── blocklist.txt         # Blocked IPs (one per line)
├── credentials           # Admin user info
├── bin/
│   └── apply_blocklist.sh
├── core/
│   └── parser.py
├── dashboard/
│   ├── app.py
│   ├── requirements.txt
│   ├── templates/
│   └── static/
└── venv/                 # Python virtual environment

/etc/nginx/snippets/
└── scr_protector.conf    # NGINX rate limiting snippet

/var/backups/scr-protector/
└── *.bak                 # Configuration backups

/var/www/html/.scr-protector/
└── challenge.html        # Rate-limit challenge page
```

## 🔮 Future Enhancements

See `core/future_hooks.md` for planned features:
- Port scan detection
- Geographic IP filtering
- Reputation-based scoring
- Webhook notifications
- Prometheus metrics export

## 📄 License

MIT License — see [LICENSE](LICENSE)

## 🤝 Contributing

Contributions welcome! Please ensure:
- Scripts remain idempotent
- Security principles are maintained
- Raspberry Pi compatibility is preserved
- Configuration changes are backward compatible

---

**scr-protector** — Simple. Secure. Server-first.
