#!/bin/bash
# =============================================================================
# scr-protector: uninstall.sh
# Purpose: Safely remove scr-protector from the system
#
# This script is interactive and asks for confirmation before removing
# each component to prevent accidental data loss.
# =============================================================================

set -euo pipefail

# =============================================================================
# CONSTANTS
# =============================================================================
readonly INSTALL_DIR="/opt/scr-protector"
readonly BACKUP_DIR="/var/backups/scr-protector"

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

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo $0"
    exit 1
fi

echo ""
echo "============================================================"
echo "  scr-protector: Uninstall"
echo "============================================================"
echo ""
log_warn "This will remove scr-protector from your system."
echo ""

if ! prompt_yn "Continue with uninstall?"; then
    log_info "Uninstall cancelled."
    exit 0
fi

# =============================================================================
# STOP SERVICES
# =============================================================================

echo ""
log_info "Stopping services..."

# Stop and disable all scr-protector services
SERVICES=(
    "scr-protector-dashboard.service"
    "scr-protector-parser.service"
    "scr-protector-blocker.timer"
    "scr-protector-blocker.service"
)

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        systemctl stop "$service"
        log_success "Stopped $service"
    fi
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        systemctl disable "$service"
        log_success "Disabled $service"
    fi
done

# =============================================================================
# REMOVE SYSTEMD UNITS
# =============================================================================

log_info "Removing systemd unit files..."

for service in "${SERVICES[@]}"; do
    if [[ -f "/etc/systemd/system/${service}" ]]; then
        rm -f "/etc/systemd/system/${service}"
        log_success "Removed /etc/systemd/system/${service}"
    fi
done

systemctl daemon-reload
log_success "systemd daemon reloaded"

# =============================================================================
# IPTABLES AND IPSET
# =============================================================================

echo ""
log_info "--- Network Rules ---"

IPS_NAME="scr_blockset"

if prompt_yn "Remove iptables blocking rule?"; then
    if iptables -C INPUT -m set --match-set "$IPS_NAME" src -j DROP 2>/dev/null; then
        iptables -D INPUT -m set --match-set "$IPS_NAME" src -j DROP
        log_success "iptables rule removed"
        
        # Save iptables
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4
        fi
    else
        log_info "iptables rule not found"
    fi
fi

if prompt_yn "Remove ipset '$IPS_NAME'?"; then
    if ipset list "$IPS_NAME" &>/dev/null; then
        ipset destroy "$IPS_NAME"
        log_success "ipset '$IPS_NAME' destroyed"
    else
        log_info "ipset not found"
    fi
fi

# =============================================================================
# NGINX CONFIGURATION
# =============================================================================

echo ""
log_info "--- NGINX Configuration ---"

NGINX_SNIPPET="/etc/nginx/snippets/scr_protector.conf"

if prompt_yn "Remove NGINX snippet ($NGINX_SNIPPET)?"; then
    if [[ -f "$NGINX_SNIPPET" ]]; then
        rm -f "$NGINX_SNIPPET"
        log_success "NGINX snippet removed"
    else
        log_info "NGINX snippet not found"
    fi
fi

# Offer to restore nginx backups
if [[ -d "$BACKUP_DIR" ]]; then
    NGINX_BACKUPS=($(ls "${BACKUP_DIR}/"*.bak 2>/dev/null | grep -E "nginx|default" || true))
    
    if [[ ${#NGINX_BACKUPS[@]} -gt 0 ]]; then
        echo ""
        log_info "Found NGINX backup files:"
        for backup in "${NGINX_BACKUPS[@]}"; do
            echo "  - $backup"
        done
        
        if prompt_yn "Restore NGINX configuration from most recent backup?"; then
            # Restore default site config
            LATEST_DEFAULT=$(ls -t "${BACKUP_DIR}/default."*.bak 2>/dev/null | head -1 || true)
            if [[ -n "$LATEST_DEFAULT" ]]; then
                cp "$LATEST_DEFAULT" /etc/nginx/sites-enabled/default
                log_success "Restored NGINX default config"
            fi
        fi
    fi
fi

# Test and reload nginx
if nginx -t 2>/dev/null; then
    systemctl reload nginx
    log_success "NGINX reloaded"
else
    log_warn "NGINX configuration test failed - please check manually"
fi

# =============================================================================
# REMOVE INSTALLATION DIRECTORY
# =============================================================================

echo ""
log_info "--- Installation Directory ---"

if [[ -d "$INSTALL_DIR" ]]; then
    echo ""
    log_warn "The following will be permanently deleted:"
    echo "  - Configuration: ${INSTALL_DIR}/config.yaml"
    echo "  - Database: ${INSTALL_DIR}/dashboard.db"
    echo "  - Blocklist: ${INSTALL_DIR}/blocklist.txt"
    echo "  - All other files in ${INSTALL_DIR}"
    echo ""
    
    if prompt_yn "Remove ${INSTALL_DIR} and all contents?"; then
        # Create final backup of important files
        if prompt_yn "Create backup of database and config before removal?"; then
            TIMESTAMP=$(date +%Y%m%d_%H%M%S)
            mkdir -p "$BACKUP_DIR"
            
            if [[ -f "${INSTALL_DIR}/dashboard.db" ]]; then
                cp "${INSTALL_DIR}/dashboard.db" "${BACKUP_DIR}/dashboard.db.${TIMESTAMP}.bak"
                log_info "Database backed up to ${BACKUP_DIR}/dashboard.db.${TIMESTAMP}.bak"
            fi
            
            if [[ -f "${INSTALL_DIR}/config.yaml" ]]; then
                cp "${INSTALL_DIR}/config.yaml" "${BACKUP_DIR}/config.yaml.${TIMESTAMP}.bak"
                log_info "Config backed up to ${BACKUP_DIR}/config.yaml.${TIMESTAMP}.bak"
            fi
            
            if [[ -f "${INSTALL_DIR}/blocklist.txt" ]]; then
                cp "${INSTALL_DIR}/blocklist.txt" "${BACKUP_DIR}/blocklist.txt.${TIMESTAMP}.bak"
                log_info "Blocklist backed up to ${BACKUP_DIR}/blocklist.txt.${TIMESTAMP}.bak"
            fi
        fi
        
        rm -rf "$INSTALL_DIR"
        log_success "Removed ${INSTALL_DIR}"
    else
        log_info "Installation directory preserved"
    fi
else
    log_info "Installation directory not found"
fi

# =============================================================================
# WHAT WE DON'T REMOVE
# =============================================================================

echo ""
echo "============================================================"
echo "  PRESERVED COMPONENTS"
echo "============================================================"
echo ""
log_info "The following were NOT removed (require manual removal):"
echo ""
echo "  - UFW firewall rules (use: sudo ufw status)"
echo "  - Fail2ban configuration (/etc/fail2ban/jail.d/scr-ssh.conf)"
echo "  - System user created by setup_ubuntu.sh"
echo "  - Sysctl hardening (/etc/sysctl.d/99-scr-protector.conf)"
echo "  - Installed packages (nginx, python3-venv, etc.)"
echo "  - Backup directory: ${BACKUP_DIR}"
echo ""
log_info "To fully remove hardening settings, delete:"
echo "  - /etc/fail2ban/jail.d/scr-ssh.conf"
echo "  - /etc/sysctl.d/99-scr-protector.conf"
echo "  - Then run: sudo sysctl --system"
echo ""

# =============================================================================
# SUMMARY
# =============================================================================

echo "============================================================"
echo "  UNINSTALL COMPLETE"
echo "============================================================"
echo ""
log_success "scr-protector has been removed."
echo ""
