#!/bin/bash
# =============================================================================
# scr-protector: install.sh
# Purpose: Install and configure scr-protector HTTP security layer
# 
# This script is IDEMPOTENT - safe to run multiple times.
# Must be run as root.
#
# What this does:
# 1. Sets up the web protection (NGINX rate limiting, challenge page)
# 2. Configures ipset/iptables blocking
# 3. Installs the dashboard (Flask + SQLite)
# 4. Sets up the log parser for threat detection
# 5. Enables systemd services
# =============================================================================

set -euo pipefail

# =============================================================================
# CONSTANTS
# =============================================================================
readonly INSTALL_DIR="/opt/scr-protector"
readonly BACKUP_DIR="/var/backups/scr-protector"
readonly MARKER_FILE="${INSTALL_DIR}/.setup_done"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

prompt_yn() {
    local prompt="$1"
    local default="${2:-n}"
    local response
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " response
        response="${response:-y}"
    else
        read -rp "$prompt [y/N]: " response
        response="${response:-n}"
    fi
    [[ "${response,,}" == "y" ]]
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local filename=$(basename "$src")
        local timestamp=$(date +%Y%m%d_%H%M%S)
        mkdir -p "$BACKUP_DIR"
        cp "$src" "${BACKUP_DIR}/${filename}.${timestamp}.bak"
        log_info "Backed up $src"
    fi
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo $0"
    exit 1
fi

echo ""
echo "============================================================"
echo "  scr-protector: Installation"
echo "============================================================"
echo ""

# Check if setup was run
if [[ ! -f "$MARKER_FILE" ]]; then
    log_warn "Setup has not been completed yet."
    if prompt_yn "Run setup_ubuntu.sh now?" "y"; then
        bash "${SCRIPT_DIR}/setup_ubuntu.sh"
    else
        log_error "Please run setup_ubuntu.sh first"
        exit 1
    fi
fi

# Parse command line arguments
AUTO_NGINX=false
for arg in "$@"; do
    case $arg in
        --auto-nginx)
            AUTO_NGINX=true
            shift
            ;;
    esac
done

# =============================================================================
# COPY FILES TO INSTALL DIRECTORY
# =============================================================================

log_info "Installing scr-protector files..."

# Create directory structure
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/core"
mkdir -p "${INSTALL_DIR}/dashboard/templates"
mkdir -p "${INSTALL_DIR}/dashboard/static"

# Copy core files
cp "${SCRIPT_DIR}/core/apply_blocklist.sh" "${INSTALL_DIR}/bin/"
chmod +x "${INSTALL_DIR}/bin/apply_blocklist.sh"

cp "${SCRIPT_DIR}/core/parser.py" "${INSTALL_DIR}/core/"
cp "${SCRIPT_DIR}/core/log_format.conf" "${INSTALL_DIR}/core/" 2>/dev/null || true

# Copy dashboard files
cp "${SCRIPT_DIR}/dashboard/app.py" "${INSTALL_DIR}/dashboard/"
cp "${SCRIPT_DIR}/dashboard/requirements.txt" "${INSTALL_DIR}/dashboard/"
cp -r "${SCRIPT_DIR}/dashboard/templates/"* "${INSTALL_DIR}/dashboard/templates/"
cp -r "${SCRIPT_DIR}/dashboard/static/"* "${INSTALL_DIR}/dashboard/static/"

log_success "Files copied to ${INSTALL_DIR}"

# =============================================================================
# DETECT/CREATE SITE ROOT
# =============================================================================

log_info "Detecting web site root..."

SITE_ROOT=""
CANDIDATES=(
    "/var/www/html"
    "/var/www"
    "/srv/www"
    "/usr/share/nginx/html"
)

# Find existing site roots
FOUND_ROOTS=()
for candidate in "${CANDIDATES[@]}"; do
    if [[ -d "$candidate" ]] && [[ -n "$(ls -A "$candidate" 2>/dev/null)" ]]; then
        FOUND_ROOTS+=("$candidate")
    fi
done

if [[ ${#FOUND_ROOTS[@]} -gt 0 ]]; then
    log_info "Found existing site roots:"
    for i in "${!FOUND_ROOTS[@]}"; do
        echo "  [$((i+1))] ${FOUND_ROOTS[$i]}"
    done
    echo "  [0] Create new default site"
    
    read -rp "Select site root [1]: " selection
    selection="${selection:-1}"
    
    if [[ "$selection" == "0" ]]; then
        SITE_ROOT="/var/www/html"
    elif [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -le ${#FOUND_ROOTS[@]} ]]; then
        SITE_ROOT="${FOUND_ROOTS[$((selection-1))]}"
    else
        SITE_ROOT="${FOUND_ROOTS[0]}"
    fi
else
    log_info "No existing site found, creating default..."
    SITE_ROOT="/var/www/html"
fi

# Create site root if needed
mkdir -p "$SITE_ROOT"

# Create default landing page if site is empty
if [[ ! -f "${SITE_ROOT}/index.html" ]] && [[ ! -f "${SITE_ROOT}/index.php" ]] && [[ ! -f "${SITE_ROOT}/index.nginx-debian.html" ]]; then
    log_info "Creating default landing page..."
    cat > "${SITE_ROOT}/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected by scr-protector</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 { font-size: 2.5rem; margin-bottom: 1rem; }
        .shield { font-size: 4rem; margin-bottom: 1rem; }
        p { color: #a0a0a0; font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Protected by scr-protector</h1>
        <p>This server is secured with HTTP-layer protection.</p>
    </div>
</body>
</html>
EOF
    log_success "Created default landing page"
fi

log_success "Site root: $SITE_ROOT"

# =============================================================================
# SETUP CHALLENGE PAGE
# =============================================================================

log_info "Setting up challenge page..."

CHALLENGE_DIR="${SITE_ROOT}/.scr-protector"
mkdir -p "$CHALLENGE_DIR"

# Check if Anubis is enabled via environment variable or config
USE_ANUBIS="${USE_ANUBIS:-false}"

# Also check existing config file for USE_ANUBIS setting
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
if [[ -f "$CONFIG_FILE" ]]; then
    ANUBIS_FROM_CONFIG=$(grep -E "^USE_ANUBIS:\s*(true|True|TRUE)" "$CONFIG_FILE" 2>/dev/null || true)
    if [[ -n "$ANUBIS_FROM_CONFIG" ]]; then
        USE_ANUBIS="true"
    fi
fi

if [[ "$USE_ANUBIS" == "true" ]]; then
    log_info "Anubis integration enabled (USE_ANUBIS=true)"
    log_info "Skipping local challenge.html installation"
    log_warn "Make sure you have added the Anubis script to your website's <head>"
    
    # Create a minimal placeholder that redirects to Anubis
    cat > "${CHALLENGE_DIR}/challenge.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container { text-align: center; padding: 2rem; }
        .shield { font-size: 4rem; margin-bottom: 1rem; }
        p { color: #a0c4ff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Anubis Protection Active</h1>
        <p>This site is protected by Anubis anti-bot verification.</p>
        <p>If you are seeing this page, please ensure JavaScript is enabled.</p>
    </div>
</body>
</html>
EOF
    chmod 644 "${CHALLENGE_DIR}/challenge.html"
    log_success "Anubis placeholder page installed"
else
    # Install the full local challenge page
    cp "${SCRIPT_DIR}/.scr-protector/challenge.html" "$CHALLENGE_DIR/"
    chmod 644 "${CHALLENGE_DIR}/challenge.html"
    log_success "Local challenge page installed at ${CHALLENGE_DIR}"
fi

# =============================================================================
# NGINX CONFIGURATION
# =============================================================================

log_info "Configuring NGINX..."

NGINX_SNIPPET="/etc/nginx/snippets/scr_protector.conf"
backup_file "$NGINX_SNIPPET"

# Create the snippet with site root replaced
sed "s|<SITE_ROOT_PLACEHOLDER>|${SITE_ROOT}|g" "${SCRIPT_DIR}/nginx/scr_protector.conf" > "$NGINX_SNIPPET"

# Verify placeholder was replaced
if grep -q "SITE_ROOT_PLACEHOLDER" "$NGINX_SNIPPET"; then
    log_error "Failed to replace SITE_ROOT placeholder in NGINX config"
    exit 1
fi

log_success "NGINX snippet installed at $NGINX_SNIPPET"

# Create rate limit zone in conf.d (must be in http {} context)
RATE_LIMIT_CONF="/etc/nginx/conf.d/scr_rate_limit.conf"
if [[ ! -f "$RATE_LIMIT_CONF" ]]; then
    cat > "$RATE_LIMIT_CONF" << 'EOF'
# scr-protector rate limiting zone
# This must be in http {} context (conf.d is included in http {})
limit_req_zone $binary_remote_addr zone=scr_limit:10m rate=10r/s;
EOF
    log_success "Rate limit zone config created at $RATE_LIMIT_CONF"
else
    log_info "Rate limit zone config already exists"
fi

# Auto-nginx: inject include into server blocks
if $AUTO_NGINX; then
    log_info "Auto-configuring NGINX server blocks..."
    
    # Find default site config
    DEFAULT_CONF="/etc/nginx/sites-enabled/default"
    if [[ -f "$DEFAULT_CONF" ]]; then
        backup_file "$DEFAULT_CONF"
        
        # Check if already included
        if ! grep -q "scr_protector.conf" "$DEFAULT_CONF"; then
            # Insert after first server { line
            sed -i '/server {/a \    include /etc/nginx/snippets/scr_protector.conf;' "$DEFAULT_CONF"
            
            # Add rate limiting and error page
            if ! grep -q "limit_req zone=scr_limit" "$DEFAULT_CONF"; then
                sed -i '/include.*scr_protector.conf/a \    limit_req zone=scr_limit burst=20 nodelay;\n    error_page 429 = /__scr_challenge;' "$DEFAULT_CONF"
            fi
            
            log_success "Injected scr-protector into default NGINX config"
        else
            log_info "scr-protector already configured in NGINX"
        fi
    fi
    
    # Validate nginx config
    if nginx -t 2>/dev/null; then
        log_success "NGINX configuration valid"
    else
        log_error "NGINX configuration test failed!"
        log_info "Restoring backup..."
        # Find most recent backup
        LATEST_BACKUP=$(ls -t "${BACKUP_DIR}/default."*.bak 2>/dev/null | head -1)
        if [[ -n "$LATEST_BACKUP" ]]; then
            cp "$LATEST_BACKUP" "$DEFAULT_CONF"
            log_info "Backup restored"
        fi
        exit 1
    fi
else
    log_info "Skipping auto-NGINX configuration."
    log_info "Add this to your NGINX server block manually:"
    echo ""
    echo "    include /etc/nginx/snippets/scr_protector.conf;"
    echo "    limit_req zone=scr_limit burst=20 nodelay;"
    echo "    error_page 429 = /__scr_challenge;"
    echo ""
fi

# =============================================================================
# IPSET AND IPTABLES
# =============================================================================

log_info "Configuring IP blocking (ipset/iptables)..."

BLOCKLIST_FILE="${INSTALL_DIR}/blocklist.txt"
IPS_NAME="scr_blockset"

# Create blocklist file if not exists
touch "$BLOCKLIST_FILE"
chmod 644 "$BLOCKLIST_FILE"

# Create ipset if not exists
# Why ipset: Much more efficient than individual iptables rules
# A hash:ip set can hold thousands of IPs with O(1) lookup
ipset create "$IPS_NAME" hash:ip -exist
log_success "ipset '$IPS_NAME' created"

# Add iptables rule if not present
# Why INPUT chain: We want to drop packets before they reach any service
if ! iptables -C INPUT -m set --match-set "$IPS_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set "$IPS_NAME" src -j DROP
    log_success "iptables rule added"
else
    log_info "iptables rule already exists"
fi

# Save iptables rules to persist across reboots
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    log_success "iptables rules saved"
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4
    log_success "iptables rules saved to /etc/iptables/rules.v4"
fi

# Save ipset to persist
ipset save > /etc/ipset.conf
log_success "ipset saved"

# =============================================================================
# PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

log_info "Setting up Python virtual environment..."

VENV_DIR="${INSTALL_DIR}/venv"

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    log_success "Virtual environment created"
else
    log_info "Virtual environment already exists"
fi

# Activate and install requirements
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip --quiet
pip install -r "${INSTALL_DIR}/dashboard/requirements.txt" --quiet
deactivate

log_success "Python dependencies installed"

# =============================================================================
# DATABASE SETUP
# =============================================================================

log_info "Setting up database..."

DB_FILE="${INSTALL_DIR}/dashboard.db"

# Create database and tables
sqlite3 "$DB_FILE" << 'EOF'
-- Users table for dashboard authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Events table for logging security events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    details TEXT
);

-- Blocked IPs table
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    notes TEXT
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
EOF

chmod 660 "$DB_FILE"
log_success "Database initialized"

# =============================================================================
# ADMIN USER CREATION
# =============================================================================

log_info "Setting up dashboard admin user..."

# Check if admin already exists
ADMIN_EXISTS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users WHERE username='admin';")

if [[ "$ADMIN_EXISTS" == "0" ]]; then
    read -rp "Enter dashboard admin username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"
    
    while true; do
        read -rsp "Enter dashboard admin password: " ADMIN_PASS
        echo ""
        read -rsp "Confirm password: " ADMIN_PASS2
        echo ""
        
        if [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]]; then
            break
        else
            log_error "Passwords don't match, try again"
        fi
    done
    
    # Hash password using Python werkzeug (safe - passed via stdin to prevent command injection)
    PASS_HASH=$(echo "$ADMIN_PASS" | "${VENV_DIR}/bin/python3" -c "
import sys
from werkzeug.security import generate_password_hash
print(generate_password_hash(sys.stdin.read().strip()))")
    
    # Insert admin user (safe - using parameterized insert via Python to prevent SQL injection)
    "${VENV_DIR}/bin/python3" -c "
import sqlite3
import sys
conn = sqlite3.connect(sys.argv[1])
conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (sys.argv[2], sys.argv[3]))
conn.commit()
conn.close()" "$DB_FILE" "$ADMIN_USER" "$PASS_HASH"
    
    # Save credentials hint (not the actual password)
    CREDS_FILE="${INSTALL_DIR}/credentials"
    echo "Dashboard Admin User: ${ADMIN_USER}" > "$CREDS_FILE"
    echo "Password set on: $(date)" >> "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    
    log_success "Admin user '${ADMIN_USER}' created"
else
    log_info "Admin user already exists"
fi

# =============================================================================
# CONFIGURATION FILE
# =============================================================================

log_info "Setting up configuration..."

CONFIG_FILE="${INSTALL_DIR}/config.yaml"

if [[ ! -f "$CONFIG_FILE" ]]; then
    cp "${SCRIPT_DIR}/config.yaml.example" "$CONFIG_FILE"
    
    # Update site root in config
    sed -i "s|SITE_ROOT:.*|SITE_ROOT: ${SITE_ROOT}|" "$CONFIG_FILE"
    
    log_success "Configuration file created"
else
    log_info "Configuration file already exists"
fi

chmod 644 "$CONFIG_FILE"

# =============================================================================
# SYSTEMD SERVICES
# =============================================================================

log_info "Installing systemd services..."

# Copy service files
cp "${SCRIPT_DIR}/systemd/scr-protector-dashboard.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/scr-protector-parser.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/scr-protector-blocker.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/scr-protector-blocker.timer" /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable and start services
systemctl enable scr-protector-blocker.timer
systemctl start scr-protector-blocker.timer
log_success "Blocker timer enabled"

systemctl enable scr-protector-parser.service
systemctl start scr-protector-parser.service
log_success "Parser service enabled"

systemctl enable scr-protector-dashboard.service
systemctl start scr-protector-dashboard.service
log_success "Dashboard service enabled"

# =============================================================================
# NGINX RELOAD
# =============================================================================

log_info "Reloading NGINX..."

if nginx -t 2>/dev/null; then
    systemctl reload nginx
    log_success "NGINX reloaded"
else
    log_error "NGINX configuration test failed!"
    log_error "Please check your configuration manually"
fi

# =============================================================================
# INSTALLATION SUMMARY
# =============================================================================

echo ""
echo "============================================================"
echo "  INSTALLATION COMPLETE"
echo "============================================================"
echo ""
log_success "scr-protector is now active!"
echo ""
echo "  Site root:     $SITE_ROOT"
echo "  Config:        ${INSTALL_DIR}/config.yaml"
echo "  Database:      ${INSTALL_DIR}/dashboard.db"
echo "  Blocklist:     ${INSTALL_DIR}/blocklist.txt"
echo ""
echo "============================================================"
echo "  ACCESSING THE DASHBOARD"
echo "============================================================"
echo ""
echo "  The dashboard is bound to localhost only (127.0.0.1:8080)"
echo "  for security. Access it via SSH tunnel:"
echo ""
echo "    ssh -L 8080:localhost:8080 user@your-server"
echo ""
echo "  Then open in your browser:"
echo ""
echo "    http://localhost:8080/admin"
echo ""
echo "============================================================"
echo "  TESTING"
echo "============================================================"
echo ""
echo "  Run: sudo ./test.sh"
echo ""
echo "  To test rate limiting:"
echo "    for i in {1..25}; do curl -s http://localhost/ > /dev/null; done"
echo ""
if ! $AUTO_NGINX; then
echo "============================================================"
echo "  MANUAL NGINX CONFIGURATION REQUIRED"
echo "============================================================"
echo ""
echo "  Add to your NGINX server block:"
echo ""
echo "    include /etc/nginx/snippets/scr_protector.conf;"
echo "    limit_req zone=scr_limit burst=20 nodelay;"
echo "    error_page 429 = /__scr_challenge;"
echo ""
echo "  Then: sudo nginx -t && sudo systemctl reload nginx"
echo ""
fi
echo "============================================================"
echo "  SERVICE STATUS"
echo "============================================================"
echo ""
systemctl status scr-protector-dashboard.service --no-pager -l 2>/dev/null | head -5 || true
echo ""
systemctl status scr-protector-parser.service --no-pager -l 2>/dev/null | head -5 || true
echo ""
echo "============================================================"
