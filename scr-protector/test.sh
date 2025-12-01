#!/bin/bash
# =============================================================================
# scr-protector: test.sh
# Purpose: Run diagnostic checks to verify installation and functionality
# =============================================================================

set -euo pipefail

# =============================================================================
# CONSTANTS
# =============================================================================
readonly INSTALL_DIR="/opt/scr-protector"
readonly IPS_NAME="scr_blockset"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++))
}

test_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

test_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# =============================================================================
# HEADER
# =============================================================================

echo ""
echo "============================================================"
echo "  scr-protector: Diagnostic Tests"
echo "============================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    test_warn "Not running as root - some tests may fail"
    echo ""
fi

# =============================================================================
# TEST 1: NGINX CONFIGURATION
# =============================================================================

echo "--- NGINX Configuration ---"

if nginx -t 2>/dev/null; then
    test_pass "NGINX configuration is valid"
else
    test_fail "NGINX configuration test failed"
fi

if [[ -f "/etc/nginx/snippets/scr_protector.conf" ]]; then
    test_pass "scr_protector.conf snippet exists"
else
    test_fail "scr_protector.conf snippet not found"
fi

if systemctl is-active --quiet nginx; then
    test_pass "NGINX is running"
else
    test_fail "NGINX is not running"
fi

echo ""

# =============================================================================
# TEST 2: IPSET AND IPTABLES
# =============================================================================

echo "--- IP Blocking (ipset/iptables) ---"

if ipset list "$IPS_NAME" &>/dev/null; then
    test_pass "ipset '$IPS_NAME' exists"
    
    # Count entries
    ENTRY_COUNT=$(ipset list "$IPS_NAME" | grep -c "^[0-9]" || echo "0")
    test_info "Currently blocked IPs: $ENTRY_COUNT"
else
    test_fail "ipset '$IPS_NAME' not found"
fi

if iptables -C INPUT -m set --match-set "$IPS_NAME" src -j DROP 2>/dev/null; then
    test_pass "iptables blocking rule is active"
else
    test_warn "iptables blocking rule not found"
fi

echo ""

# =============================================================================
# TEST 3: BLOCKLIST FILE
# =============================================================================

echo "--- Blocklist Management ---"

BLOCKLIST_FILE="${INSTALL_DIR}/blocklist.txt"

if [[ -f "$BLOCKLIST_FILE" ]]; then
    test_pass "Blocklist file exists"
    
    LINE_COUNT=$(wc -l < "$BLOCKLIST_FILE")
    test_info "Blocklist entries: $LINE_COUNT"
else
    test_fail "Blocklist file not found"
fi

# Test apply_blocklist.sh script
APPLY_SCRIPT="${INSTALL_DIR}/bin/apply_blocklist.sh"
if [[ -x "$APPLY_SCRIPT" ]]; then
    test_pass "apply_blocklist.sh is executable"
    
    # Test adding and removing a test IP (use TEST.ONLY.IP.ADDR pattern to avoid collision)
    TEST_IP="192.0.2.1"  # RFC 5737 TEST-NET-1, reserved for documentation/testing
    TEST_MARKER="# SCR-PROTECTOR-TEST-ENTRY - safe to delete"
    
    # Add test IP with clear marker
    echo "${TEST_IP}  ${TEST_MARKER}" >> "$BLOCKLIST_FILE"
    
    if bash "$APPLY_SCRIPT" 2>/dev/null; then
        if ipset test "$IPS_NAME" "$TEST_IP" 2>/dev/null; then
            test_pass "Test IP successfully added to ipset"
        else
            test_warn "Test IP not found in ipset after apply"
        fi
    else
        test_warn "apply_blocklist.sh returned non-zero"
    fi
    
    # Remove test IP (only lines containing our marker)
    grep -v "SCR-PROTECTOR-TEST-ENTRY" "$BLOCKLIST_FILE" > "${BLOCKLIST_FILE}.tmp" 2>/dev/null || true
    mv "${BLOCKLIST_FILE}.tmp" "$BLOCKLIST_FILE"
    bash "$APPLY_SCRIPT" 2>/dev/null || true
else
    test_fail "apply_blocklist.sh not found or not executable"
fi

echo ""

# =============================================================================
# TEST 4: SYSTEMD SERVICES
# =============================================================================

echo "--- Systemd Services ---"

SERVICES=(
    "scr-protector-dashboard.service"
    "scr-protector-parser.service"
    "scr-protector-blocker.timer"
)

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$service"; then
        test_pass "$service is running"
    else
        test_fail "$service is not running"
    fi
done

echo ""

# =============================================================================
# TEST 5: DASHBOARD CONNECTIVITY
# =============================================================================

echo "--- Dashboard ---"

if systemctl is-active --quiet "scr-protector-dashboard.service"; then
    # Test local dashboard
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/admin" 2>/dev/null || echo "000")
    
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]]; then
        test_pass "Dashboard responding on 127.0.0.1:8080 (HTTP $HTTP_CODE)"
    else
        test_warn "Dashboard returned HTTP $HTTP_CODE"
    fi
    
    # Test API endpoint
    API_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/api/stats" 2>/dev/null || echo "000")
    
    if [[ "$API_CODE" == "200" ]] || [[ "$API_CODE" == "401" ]]; then
        test_pass "API endpoint accessible (HTTP $API_CODE)"
    else
        test_warn "API endpoint returned HTTP $API_CODE"
    fi
else
    test_fail "Dashboard service not running - skipping connectivity tests"
fi

echo ""

# =============================================================================
# TEST 6: DATABASE
# =============================================================================

echo "--- Database ---"

DB_FILE="${INSTALL_DIR}/dashboard.db"

if [[ -f "$DB_FILE" ]]; then
    test_pass "Database file exists"
    
    # Check tables exist
    TABLES=$(sqlite3 "$DB_FILE" ".tables" 2>/dev/null || echo "")
    
    if echo "$TABLES" | grep -q "users"; then
        test_pass "Table 'users' exists"
    else
        test_fail "Table 'users' not found"
    fi
    
    if echo "$TABLES" | grep -q "events"; then
        test_pass "Table 'events' exists"
        
        # Show recent events count
        EVENT_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM events WHERE ts > datetime('now', '-1 hour');" 2>/dev/null || echo "0")
        test_info "Events in last hour: $EVENT_COUNT"
    else
        test_fail "Table 'events' not found"
    fi
    
    if echo "$TABLES" | grep -q "blocked_ips"; then
        test_pass "Table 'blocked_ips' exists"
    else
        test_fail "Table 'blocked_ips' not found"
    fi
else
    test_fail "Database file not found"
fi

echo ""

# =============================================================================
# TEST 7: CONFIGURATION
# =============================================================================

echo "--- Configuration ---"

CONFIG_FILE="${INSTALL_DIR}/config.yaml"

if [[ -f "$CONFIG_FILE" ]]; then
    test_pass "Configuration file exists"
else
    test_fail "Configuration file not found"
fi

echo ""

# =============================================================================
# TEST 8: CHALLENGE PAGE
# =============================================================================

echo "--- Challenge Page ---"

# Find site root from config or default
SITE_ROOT="/var/www/html"
CHALLENGE_FILE="${SITE_ROOT}/.scr-protector/challenge.html"

if [[ -f "$CHALLENGE_FILE" ]]; then
    test_pass "Challenge page exists"
else
    test_warn "Challenge page not found at $CHALLENGE_FILE"
fi

echo ""

# =============================================================================
# TEST 9: RECENT EVENTS (if any)
# =============================================================================

echo "--- Recent Security Events ---"

if [[ -f "$DB_FILE" ]]; then
    echo ""
    sqlite3 -header -column "$DB_FILE" "
        SELECT id, ip, severity, reason, 
               datetime(ts, 'localtime') as time
        FROM events 
        ORDER BY ts DESC 
        LIMIT 5;
    " 2>/dev/null || echo "  No events found"
    echo ""
fi

# =============================================================================
# SUMMARY
# =============================================================================

echo "============================================================"
echo "  TEST SUMMARY"
echo "============================================================"
echo ""
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All critical tests passed!${NC}"
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
fi

echo ""
echo "============================================================"
echo "  QUICK HEALTH CHECK COMMANDS"
echo "============================================================"
echo ""
echo "  Check service logs:"
echo "    journalctl -u scr-protector-dashboard -f"
echo "    journalctl -u scr-protector-parser -f"
echo ""
echo "  Test rate limiting (run 25+ requests quickly):"
echo "    for i in {1..30}; do curl -s -o /dev/null -w '%{http_code}\n' http://localhost/; done"
echo ""
echo "  View blocked IPs:"
echo "    sudo ipset list $IPS_NAME"
echo ""
echo "  Access dashboard:"
echo "    ssh -L 8080:localhost:8080 user@server"
echo "    Then open: http://localhost:8080/admin"
echo ""
echo "============================================================"

# Exit with error if any tests failed
exit $FAIL
