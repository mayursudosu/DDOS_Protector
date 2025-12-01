# Future Hooks for scr-protector

This document describes planned security features that are not yet fully implemented. These exist as hooks in the code for future development.

## SSH Brute-Force Detection

**Status**: ✅ Implemented

The parser monitors `/var/log/auth.log` for failed SSH login attempts:
- Tracks failed logins per IP in a sliding window
- Generates WARN events at 3+ failures
- Generates ALERT and auto-blocks at 5+ failures (configurable)

Configuration in `config.yaml`:
```yaml
SSH_ANALYTICS_ENABLED: true
ALERT_THRESHOLD_SSH: 5
ALERT_WINDOW_SSH_MIN: 5
```

---

## Port Scan Detection

**Status**: 🔲 Not Implemented

Detect port scanning attempts by monitoring connection patterns:
- Track unique ports accessed per IP
- Alert when IP probes multiple closed ports
- Integrate with iptables LOG target or connection tracking

Implementation approach:
1. Configure iptables to log dropped packets
2. Parse `/var/log/kern.log` or `/var/log/syslog` for iptables logs
3. Track port access patterns per IP
4. Alert/block on suspicious patterns

Future config:
```yaml
PORT_SCAN_DETECTION_ENABLED: false
PORT_SCAN_THRESHOLD: 10        # ports in window
PORT_SCAN_WINDOW_MIN: 5
```

---

## Geographic IP Filtering

**Status**: 🔲 Not Implemented

Allow/deny traffic based on country:
- Use MaxMind GeoIP2 or IP2Location database
- Configurable allow/deny country lists
- Dashboard shows country statistics

Implementation:
1. Download GeoIP database
2. Add geoip2 Python library
3. Lookup country on each request
4. Compare against allow/deny lists

Future config:
```yaml
GEOIP_ENABLED: false
GEOIP_DATABASE: /opt/scr-protector/GeoLite2-Country.mmdb
GEOIP_MODE: deny    # 'allow' or 'deny'
GEOIP_COUNTRIES:
  - CN
  - RU
```

---

## Reputation-Based Scoring

**Status**: 🔲 Not Implemented

Assign reputation scores to IPs based on behavior:
- Start with neutral score
- Decrease score on suspicious events
- Increase score on clean traffic
- Auto-block at threshold

Implementation:
1. Add `reputation` table to database
2. Update score on each event
3. Decay scores over time
4. Block when score drops below threshold

Future config:
```yaml
REPUTATION_ENABLED: false
REPUTATION_BLOCK_THRESHOLD: -100
REPUTATION_DECAY_RATE: 0.1    # per hour
```

---

## Webhook Notifications

**Status**: 🔲 Not Implemented

Send alerts to external services:
- Slack
- Discord
- PagerDuty
- Custom webhooks

Implementation:
1. Add webhook URL to config
2. Format alert as JSON payload
3. POST to webhook on ALERT events

Future config:
```yaml
WEBHOOK_ENABLED: false
WEBHOOK_URL: https://hooks.slack.com/services/xxx
WEBHOOK_EVENTS:
  - ALERT
  - block
```

---

## Prometheus Metrics Export

**Status**: 🔲 Not Implemented

Export metrics for monitoring:
- `scr_requests_total{status}`
- `scr_blocked_ips_total`
- `scr_events_total{severity}`
- `scr_rate_limit_hits_total`

Implementation:
1. Add prometheus_client library
2. Create metrics in parser
3. Expose /metrics endpoint in dashboard

Future config:
```yaml
PROMETHEUS_ENABLED: false
PROMETHEUS_PORT: 9090
```

---

## User-Agent Fingerprinting

**Status**: 🔲 Not Implemented

Detect suspicious or malicious user agents:
- Known bad bots (scrapers, vulnerability scanners)
- Empty or malformed user agents
- User agent anomaly detection

Implementation:
1. Parse User-Agent from nginx logs
2. Match against known-bad patterns
3. Track User-Agent changes per IP

---

## Request Pattern Analysis

**Status**: 🔲 Not Implemented

Detect suspicious request patterns:
- Path traversal attempts (`../`)
- SQL injection patterns
- XSS attempts
- Known vulnerability probes

Implementation:
1. Parse request path from nginx logs
2. Match against attack patterns
3. Score and alert on matches

---

## Contributing

Want to implement one of these features? Here's how:

1. Update `config.yaml.example` with new settings
2. Add parsing logic to `parser.py`
3. Add relevant database tables/columns
4. Update dashboard to display new data
5. Update this document to mark as implemented
6. Submit a pull request

Guidelines:
- Keep resource usage low (Raspberry Pi compatibility)
- Make features configurable and off by default
- Maintain idempotent installation
- Add tests in `test.sh`
