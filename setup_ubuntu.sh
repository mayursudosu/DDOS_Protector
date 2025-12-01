#!/bin/bash
# =============================================================================
# scr-protector: setup_ubuntu.sh
# Purpose: Prepare a fresh Ubuntu Server (including Raspberry Pi) for scr-protector
# 
# This script is IDEMPOTENT - safe to run multiple times.
# Must be run as root.
#
# Security Philosophy:
# - Ports closed by default (UFW deny incoming)
# - SSH hardened but accessible
# - Dashboard never exposed publicly
# - Minimal attack surface
# =============================================================================

set -euo pipefail

# =============================================================================
# CONSTANTS AND COLORS
# =============================================================================
readonly BACKUP_DIR="/var/backups/scr-protector"
readonly INSTALL_DIR="/opt/scr-protector"
readonly MARKER_FILE="${INSTALL_DIR}/.setup_done"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

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
        local filename
        filename=$(basename "$src")
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        cp "$src" "${BACKUP_DIR}/${filename}.${timestamp}.bak"
        log_info "Backed up $src to ${BACKUP_DIR}/${filename}.${timestamp}.bak"
    fi
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

# Must be root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo $0"
    exit 1
fi

echo ""
echo "============================================================"
echo "  scr-protector: Ubuntu Server Setup"
echo "============================================================"
echo ""

# =============================================================================
# OS DETECTION
# =============================================================================

log_info "Detecting operating system..."

if command -v lsb_release &>/dev/null; then
    OS_ID=$(lsb_release -is 2>/dev/null || echo "Unknown")
    OS_VERSION=$(lsb_release -rs 2>/dev/null || echo "Unknown")
    OS_CODENAME=$(lsb_release -cs 2>/dev/null || echo "Unknown")
else
    OS_ID="Unknown"
    OS_VERSION="Unknown"
    OS_CODENAME="Unknown"
fi

# Detect architecture (important for Raspberry Pi)
ARCH=$(uname -m)
IS_PI=false
if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "armv7l" ]]; then
    if grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        IS_PI=true
    fi
fi

log_info "Detected: $OS_ID $OS_VERSION ($OS_CODENAME) on $ARCH"
if $IS_PI; then
    log_info "Running on Raspberry Pi - will optimize for low resources"
fi

# Warn if not Ubuntu
if [[ "$OS_ID" != "Ubuntu" ]]; then
    log_warn "This script is designed for Ubuntu Server."
    log_warn "Detected: $OS_ID"
    if ! prompt_yn "Continue anyway?"; then
        log_error "Aborted by user."
        exit 1
    fi
fi

# =============================================================================
# CREATE DIRECTORIES
# =============================================================================

log_info "Creating required directories..."

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
log_success "Backup directory: $BACKUP_DIR"

mkdir -p "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
log_success "Install directory: $INSTALL_DIR"

# =============================================================================
# APT UPDATE AND INSTALL PACKAGES
# =============================================================================

log_info "Updating package lists..."
apt update

log_info "Upgrading existing packages..."
apt upgrade -y

log_info "Installing required packages..."
# Core packages for scr-protector functionality
PACKAGES=(
    git
    python3-venv
    python3-pip
    ipset
    iptables-persistent
    nginx
    net-tools
    ufw
    fail2ban
    chrony
    unattended-upgrades
    curl
    sqlite3
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l "$pkg" &>/dev/null; then
        log_info "Package $pkg already installed"
    else
        log_info "Installing $pkg..."
        apt install -y "$pkg"
    fi
done

log_success "All packages installed"

# =============================================================================
# USER CREATION
# =============================================================================

echo ""
log_info "--- User Configuration ---"

read -rp "Enter sudo username to create [default: adminuser]: " SUDO_USER
SUDO_USER="${SUDO_USER:-adminuser}"

if id "$SUDO_USER" &>/dev/null; then
    log_info "User '$SUDO_USER' already exists"
else
    log_info "Creating user '$SUDO_USER'..."
    useradd -m -s /bin/bash "$SUDO_USER"
    usermod -aG sudo "$SUDO_USER"
    
    # Set password interactively
    echo "Set password for $SUDO_USER:"
    passwd "$SUDO_USER"
    
    log_success "User '$SUDO_USER' created with sudo privileges"
fi

# SSH key installation
if prompt_yn "Install SSH public key for $SUDO_USER?"; then
    read -rp "Enter path to SSH public key file (or paste the key): " SSH_KEY_INPUT
    
    USER_HOME=$(eval echo "~$SUDO_USER")
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chown "$SUDO_USER:$SUDO_USER" "$SSH_DIR"
    
    if [[ -f "$SSH_KEY_INPUT" ]]; then
        cat "$SSH_KEY_INPUT" >> "$AUTH_KEYS"
    else
        echo "$SSH_KEY_INPUT" >> "$AUTH_KEYS"
    fi
    
    chmod 600 "$AUTH_KEYS"
    chown "$SUDO_USER:$SUDO_USER" "$AUTH_KEYS"
    log_success "SSH key installed for $SUDO_USER"
fi

# =============================================================================
# SSH HARDENING
# =============================================================================

echo ""
log_info "--- SSH Configuration ---"

SSHD_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSHD_CONFIG"

# Disable root login - critical security measure
# Why: Root is a known username, disabling direct root login forces attackers
# to guess both username AND password
if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
else
    echo "PermitRootLogin no" >> "$SSHD_CONFIG"
fi
log_success "Disabled root SSH login"

# Ask about password authentication
if prompt_yn "Disable password authentication? (Only if you have SSH keys set up)"; then
    if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    else
        echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
    fi
    log_success "Disabled password authentication"
else
    log_info "Password authentication kept enabled"
fi

# Restart SSH to apply changes
systemctl restart sshd
log_success "SSH daemon restarted"

# =============================================================================
# UFW FIREWALL CONFIGURATION
# =============================================================================

echo ""
log_info "--- Firewall Configuration ---"

# Default deny incoming - fundamental security principle
# Why: Whitelist approach - only explicitly allowed traffic gets through
ufw default deny incoming
log_success "UFW: Default deny incoming"

# Allow outgoing - server needs to reach the internet
ufw default allow outgoing
log_success "UFW: Default allow outgoing"

# Always allow SSH - otherwise we lock ourselves out
ufw allow OpenSSH
log_success "UFW: Allowed OpenSSH"

# HTTP/HTTPS - conditional based on deployment needs
# For non-Pi servers, default to allowing HTTP/HTTPS since they're typically web servers
# For Pi, be more conservative
ALLOW_WEB=false

if $IS_PI; then
    if prompt_yn "Allow HTTP/HTTPS traffic now? (Required if serving websites)"; then
        ALLOW_WEB=true
    fi
else
    # For regular servers, default to allowing web traffic
    log_info "For web servers, HTTP/HTTPS is typically needed."
    if prompt_yn "Allow HTTP/HTTPS traffic now?" "y"; then
        ALLOW_WEB=true
    fi
fi

if $ALLOW_WEB; then
    ufw allow 'Nginx Full'
    log_success "UFW: Allowed Nginx Full (80, 443)"
else
    log_info "HTTP/HTTPS NOT opened. Run 'sudo ufw allow \"Nginx Full\"' when ready."
fi

# IMPORTANT: Do NOT open port 8080 for dashboard
# Dashboard binds to 127.0.0.1 only - accessed via SSH tunnel
# Why: Exposing admin interfaces is a major security risk
log_info "Dashboard port (8080) NOT opened - access via SSH tunnel only"

# Enable UFW
if ! ufw status | grep -q "Status: active"; then
    log_info "Enabling UFW firewall..."
    echo "y" | ufw enable
fi
log_success "UFW enabled"

# =============================================================================
# SWAP CONFIGURATION (for low-memory systems)
# =============================================================================

echo ""
log_info "--- Memory Configuration ---"

TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
log_info "Total memory: ${TOTAL_MEM}MB"

if [[ $TOTAL_MEM -lt 1024 ]]; then
    log_warn "Low memory detected (< 1GB)"
    if prompt_yn "Create 1GB swap file?"; then
        SWAPFILE="/swapfile"
        if [[ -f "$SWAPFILE" ]]; then
            log_info "Swap file already exists"
        else
            log_info "Creating swap file..."
            fallocate -l 1G "$SWAPFILE" || dd if=/dev/zero of="$SWAPFILE" bs=1M count=1024
            chmod 600 "$SWAPFILE"
            mkswap "$SWAPFILE"
            swapon "$SWAPFILE"
            
            # Add to fstab if not present
            if ! grep -q "$SWAPFILE" /etc/fstab; then
                echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
            fi
            
            log_success "1GB swap file created and enabled"
        fi
    fi
else
    log_info "Sufficient memory available, skipping swap"
fi

# =============================================================================
# SYSCTL HARDENING
# =============================================================================

echo ""
log_info "--- Kernel Hardening ---"

SYSCTL_CONF="/etc/sysctl.d/99-scr-protector.conf"

cat > "$SYSCTL_CONF" << 'EOF'
# scr-protector: Kernel hardening settings
# These are conservative, safe values that improve security

# Enable TCP SYN cookies
# Why: Protects against SYN flood attacks by not allocating resources until
# the three-way handshake is complete
net.ipv4.tcp_syncookies=1

# Enable reverse path filtering (strict mode)
# Why: Prevents IP spoofing by validating that incoming packets could be
# replied to via the interface they arrived on
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Ignore ICMP broadcast requests
# Why: Prevents participation in Smurf attacks
net.ipv4.icmp_echo_ignore_broadcasts=1

# Disable source routing
# Why: Source routing can be used to bypass firewall rules
net.ipv4.conf.all.accept_source_route=0

# Disable ICMP redirects
# Why: ICMP redirects can be used for MITM attacks
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0

# Log martian packets (packets with impossible addresses)
# Why: Helps detect spoofing attempts
net.ipv4.conf.all.log_martians=1
EOF

# Apply sysctl settings
sysctl --system >/dev/null 2>&1
log_success "Kernel hardening applied"

# =============================================================================
# FAIL2BAN CONFIGURATION
# =============================================================================

echo ""
log_info "--- Fail2Ban Configuration ---"

F2B_JAIL="/etc/fail2ban/jail.d/scr-ssh.conf"

cat > "$F2B_JAIL" << 'EOF'
# scr-protector: SSH brute-force protection
# Conservative values to avoid locking out legitimate users

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
# Ban for 10 minutes after 5 failed attempts in 10 minutes
# Why: Balances security with usability - legitimate users who mistype
# passwords won't be locked out too long
maxretry = 5
findtime = 10m
bantime = 10m
EOF

# Restart fail2ban to apply
systemctl restart fail2ban
log_success "Fail2Ban configured for SSH protection"

# =============================================================================
# CREATE MARKER FILE
# =============================================================================

touch "$MARKER_FILE"
chmod 644 "$MARKER_FILE"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo "============================================================"
echo "  SETUP COMPLETE"
echo "============================================================"
echo ""
log_success "Packages installed:"
echo "    - git, python3-venv, python3-pip"
echo "    - ipset, iptables-persistent"
echo "    - nginx, ufw, fail2ban"
echo "    - chrony, unattended-upgrades"
echo ""
log_success "User created: $SUDO_USER (with sudo)"
echo ""
log_success "UFW Firewall status:"
ufw status numbered
echo ""
log_success "Security measures applied:"
echo "    - SSH: Root login disabled"
echo "    - UFW: Default deny incoming"
echo "    - Kernel: Hardening via sysctl"
echo "    - Fail2Ban: SSH protection enabled"
echo ""
log_info "Dashboard port (8080) is NOT open in firewall."
log_info "Access dashboard via SSH tunnel:"
echo "    ssh -L 8080:localhost:8080 $SUDO_USER@<server-ip>"
echo "    Then open: http://localhost:8080/admin"
echo ""
echo "============================================================"
echo "  NEXT STEPS"
echo "============================================================"
echo ""
echo "  1. cd scr-protector"
echo "  2. sudo ./install.sh"
echo ""
echo "============================================================"
