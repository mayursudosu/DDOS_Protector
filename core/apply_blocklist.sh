#!/bin/bash
# =============================================================================
# scr-protector: apply_blocklist.sh
# Purpose: Sync blocklist.txt with ipset for efficient IP blocking
# 
# This script is called by the systemd timer every 30 seconds.
# It can also be called manually when IPs are added via the dashboard.
#
# Why ipset over individual iptables rules?
# - O(1) lookup time regardless of list size
# - Can hold 65,536+ IPs efficiently
# - Atomic swap for updates (no packet loss during reload)
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Load from config.yaml if available, otherwise use defaults
CONFIG_FILE="/opt/scr-protector/config.yaml"

if command -v python3 &>/dev/null && [[ -f "$CONFIG_FILE" ]]; then
    IPS_NAME=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['IPS_NAME'])" 2>/dev/null || echo "scr_blockset")
    BLOCKLIST_FILE=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['BLOCKLIST_FILE'])" 2>/dev/null || echo "/opt/scr-protector/blocklist.txt")
else
    IPS_NAME="scr_blockset"
    BLOCKLIST_FILE="/opt/scr-protector/blocklist.txt"
fi

# Temporary set for atomic swap
TEMP_SET="${IPS_NAME}_temp"

# Logging
LOG_TAG="scr-protector-blocker"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    logger -t "$LOG_TAG" "[INFO] $1"
    echo "[INFO] $1"
}

log_error() {
    logger -t "$LOG_TAG" "[ERROR] $1"
    echo "[ERROR] $1" >&2
}

# Validate IP address format
is_valid_ip() {
    local ip="$1"
    # Simple regex for IPv4
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    # Simple check for IPv6
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        return 0
    fi
    return 1
}

# =============================================================================
# MAIN LOGIC
# =============================================================================

# Ensure blocklist file exists
if [[ ! -f "$BLOCKLIST_FILE" ]]; then
    log_info "Blocklist file not found, creating empty file"
    touch "$BLOCKLIST_FILE"
    chmod 644 "$BLOCKLIST_FILE"
fi

# Ensure main ipset exists
# hash:ip - stores individual IP addresses
# maxelem 65536 - maximum entries (can be increased)
# -exist - don't error if already exists
if ! ipset list "$IPS_NAME" &>/dev/null; then
    log_info "Creating ipset $IPS_NAME"
    ipset create "$IPS_NAME" hash:ip maxelem 65536 -exist
fi

# Count IPs in blocklist
TOTAL_IPS=$(grep -cE '^[0-9]' "$BLOCKLIST_FILE" 2>/dev/null || echo "0")

if [[ "$TOTAL_IPS" -eq 0 ]]; then
    # If blocklist is empty, just flush the set
    ipset flush "$IPS_NAME" 2>/dev/null || true
    log_info "Blocklist empty, ipset flushed"
    exit 0
fi

# =============================================================================
# ATOMIC UPDATE VIA SWAP
# =============================================================================
# We create a temporary set, populate it, then atomically swap with the main set.
# This prevents any packet loss during the update.

# Create temporary set
ipset create "$TEMP_SET" hash:ip maxelem 65536 -exist 2>/dev/null || true
ipset flush "$TEMP_SET"

# Read blocklist and add valid IPs to temporary set
ADDED=0
SKIPPED=0

while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Extract IP (first word, trim whitespace)
    ip=$(echo "$line" | awk '{print $1}' | tr -d '[:space:]')
    
    # Skip if empty after processing
    [[ -z "$ip" ]] && continue
    
    # Validate IP format
    if is_valid_ip "$ip"; then
        if ipset add "$TEMP_SET" "$ip" -exist 2>/dev/null; then
            ADDED=$((ADDED + 1))
        fi
    else
        log_error "Invalid IP format: $ip"
        SKIPPED=$((SKIPPED + 1))
    fi
done < "$BLOCKLIST_FILE"

# Atomic swap: replace main set with temp set
if ipset swap "$TEMP_SET" "$IPS_NAME" 2>/dev/null; then
    log_info "Successfully synced $ADDED IPs to $IPS_NAME (skipped: $SKIPPED)"
else
    # Fallback: just copy the entries
    log_info "Swap failed, using flush+restore method"
    ipset flush "$IPS_NAME"
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        ip=$(echo "$line" | awk '{print $1}' | tr -d '[:space:]')
        [[ -z "$ip" ]] && continue
        is_valid_ip "$ip" && ipset add "$IPS_NAME" "$ip" -exist 2>/dev/null
    done < "$BLOCKLIST_FILE"
fi

# Cleanup temporary set
ipset destroy "$TEMP_SET" 2>/dev/null || true

# =============================================================================
# VERIFY IPTABLES RULE
# =============================================================================
# Ensure the iptables rule exists to actually block traffic

if ! iptables -C INPUT -m set --match-set "$IPS_NAME" src -j DROP 2>/dev/null; then
    log_info "Adding iptables rule for $IPS_NAME"
    iptables -I INPUT -m set --match-set "$IPS_NAME" src -j DROP
fi

# Save rules for persistence
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save >/dev/null 2>&1 || true
fi

# Save ipset for persistence across reboots
ipset save > /etc/ipset.conf 2>/dev/null || true

log_info "Blocklist sync complete"
