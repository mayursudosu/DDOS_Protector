# Quick Deployment Guide for Public Testing

**For your friend** - Step-by-step after `sudo apt update && sudo apt upgrade -y`

---

## Step 1: Install Git and Clone the Repo

```bash
sudo apt install -y git
cd ~
git clone https://github.com/YOUR_USERNAME/scr-protector.git
cd scr-protector
```

> 📝 Replace `YOUR_USERNAME` with wherever the repo is hosted, or just copy the folder to the server.

---

## Step 2: Run the Ubuntu Setup Script

```bash
sudo chmod +x setup_ubuntu.sh install.sh uninstall.sh test.sh
sudo ./setup_ubuntu.sh
```

**What this does:**
- Installs NGINX, Python, ipset, fail2ban, UFW
- Sets up firewall (allows SSH + HTTP + HTTPS)
- Creates a `scr-protector` system user

---

## Step 3: Run the Main Installer

```bash
sudo ./install.sh
```

**What this does:**
- Copies protection configs to NGINX
- Sets up the dashboard
- Creates systemd services
- Starts everything

---

## Step 4: Set Up Your Website

### Option A: Simple Static Website

```bash
# Create website folder
sudo mkdir -p /var/www/mysite

# Add a test page
echo '<html><body><h1>Hello World!</h1></body></html>' | sudo tee /var/www/mysite/index.html

# Create NGINX config
sudo nano /etc/nginx/sites-available/mysite
```

Paste this config:

```nginx
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;
    
    # Include scr-protector rate limiting
    include /etc/nginx/snippets/scr_protector.conf;
    
    root /var/www/mysite;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

Enable it:

```bash
sudo ln -s /etc/nginx/sites-available/mysite /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remove default site
sudo nginx -t  # Test config
sudo systemctl reload nginx
```

### Option B: Reverse Proxy (Node.js, Python, etc.)

```bash
sudo nano /etc/nginx/sites-available/myapp
```

Paste:

```nginx
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;
    
    # Include scr-protector
    include /etc/nginx/snippets/scr_protector.conf;
    
    location / {
        proxy_pass http://127.0.0.1:3000;  # Your app's port
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable it:

```bash
sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

---

## Step 5: Point Your Domain (Optional)

If you have a domain:

1. Go to your domain registrar (Namecheap, Cloudflare, GoDaddy, etc.)
2. Add an **A record**:
   - Name: `@` (or subdomain like `test`)
   - Value: Your server's public IP
   - TTL: Auto or 300

3. Wait 5-10 minutes for DNS to propagate

---

## Step 6: Add HTTPS with Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Get certificate (replace with your domain)
sudo certbot --nginx -d yourdomain.com

# Auto-renewal is set up automatically
```

---

## Step 7: Verify Everything Works

```bash
# Run the test script
sudo ./test.sh

# Check services are running
sudo systemctl status nginx
sudo systemctl status scr-protector-parser
sudo systemctl status scr-protector-dashboard

# Check firewall
sudo ufw status

# Check the blocklist is loaded
sudo ipset list scr_blocklist | head -20
```

---

## Step 8: Access the Dashboard

From **your local computer** (not the server), open a terminal:

```bash
ssh -L 8080:localhost:8080 your_user@YOUR_SERVER_IP
```

Then open browser: **http://localhost:8080**

Default password is in `/etc/scr-protector/config.yaml`

---

## Quick Test: Simulate an Attack

From another computer or your phone's mobile data:

```bash
# Send 50 rapid requests (will trigger rate limit)
for i in {1..50}; do curl -s http://YOUR_SERVER_IP/ > /dev/null; done
```

After about 20-30 requests, you should see the challenge page!

---

## Common Issues & Fixes

### "502 Bad Gateway"
Your app isn't running:
```bash
# Check if your app is listening
sudo ss -tlnp | grep 3000  # or whatever port
```

### "403 Forbidden"
Permission issue:
```bash
sudo chown -R www-data:www-data /var/www/mysite
sudo chmod -R 755 /var/www/mysite
```

### "Connection refused"
Firewall blocking:
```bash
sudo ufw allow 80
sudo ufw allow 443
sudo ufw reload
```

### NGINX won't start
Config error:
```bash
sudo nginx -t  # Shows the error
sudo tail -20 /var/log/nginx/error.log
```

### Rate limiting not working
Check the include is there:
```bash
grep -r "scr_protector" /etc/nginx/sites-enabled/
```

---

## Monitor Attacks in Real-Time

```bash
# Watch access log
sudo tail -f /var/log/nginx/access.log

# Watch for blocked IPs
sudo tail -f /var/log/scr-protector/parser.log

# See who's hitting you hard
sudo awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20
```

---

## Emergency: Block an IP Immediately

```bash
sudo ipset add scr_blocklist 123.456.789.0
```

## Emergency: Unblock an IP

```bash
sudo ipset del scr_blocklist 123.456.789.0
```

---

## Quick Reference Card

| Task | Command |
|------|---------|
| Restart NGINX | `sudo systemctl restart nginx` |
| Restart protector | `sudo systemctl restart scr-protector-parser` |
| View blocked IPs | `sudo ipset list scr_blocklist` |
| Check logs | `sudo tail -f /var/log/nginx/access.log` |
| Test config | `sudo nginx -t` |
| Reload NGINX | `sudo systemctl reload nginx` |

---

## Rollback if Something Breaks

```bash
cd ~/scr-protector
sudo ./uninstall.sh
```

This safely removes scr-protector but keeps NGINX and your website.

---

**Good luck with testing! 🛡️**

If it works, the challenge page should appear when someone hammers your server too hard.
