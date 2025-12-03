"""
Example Plugin Template for DDOS Protector

This file demonstrates how to create custom plugins for:
1. Detection - Find new types of threats
2. Actions - Respond to threats (notifications, etc.)
3. Blocking - Block IPs via external services

Copy this file and modify to create your own plugin.
"""

from datetime import datetime
from typing import Dict, Any, Optional
import logging

# Import the plugin base classes
import sys
sys.path.insert(0, '/opt/scr-protector/core')
from plugin_system import DetectorPlugin, ActionPlugin, BlockerPlugin, SecurityEvent

logger = logging.getLogger('scr-protector.plugins.example')


# =============================================================================
# EXAMPLE DETECTOR PLUGIN
# =============================================================================

class ExampleDetector(DetectorPlugin):
    """
    Example detector that looks for a specific pattern in requests.
    
    Customize this to detect:
    - SQL injection attempts
    - XSS payloads
    - Path traversal attacks
    - Specific user agents (bots)
    - Unusual request patterns
    """
    
    @property
    def name(self) -> str:
        return "example_detector"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize with configuration.
        
        Example config in config.yaml:
            plugins:
              example_detector:
                enabled: true
                pattern: "malicious"
                severity: WARN
        """
        self.pattern = config.get('pattern', 'example')
        self.severity = config.get('severity', 'INFO')
        logger.info(f"ExampleDetector initialized with pattern: {self.pattern}")
        return True
    
    def analyze(self, data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        Analyze incoming data for threats.
        
        Args:
            data: Contains 'ip', 'path', 'method', 'status', 'user_agent', etc.
        
        Returns:
            SecurityEvent if threat detected, None otherwise
        """
        path = data.get('path', '')
        ip = data.get('ip', 'unknown')
        
        # Example: Check if pattern exists in path
        if self.pattern.lower() in path.lower():
            return SecurityEvent(
                ip=ip,
                timestamp=datetime.now(),
                event_type='pattern_match',
                severity=self.severity,
                details=f"Pattern '{self.pattern}' found in path: {path}",
                source=self.name
            )
        
        return None
    
    def cleanup(self):
        logger.info("ExampleDetector cleaned up")


# =============================================================================
# EXAMPLE ACTION PLUGIN
# =============================================================================

class ExampleAction(ActionPlugin):
    """
    Example action that logs events to a file.
    
    Customize this to:
    - Send webhook notifications
    - Post to Slack/Discord
    - Send email alerts
    - Write to external logging service
    - Trigger custom scripts
    """
    
    @property
    def name(self) -> str:
        return "example_action"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Example config:
            plugins:
              example_action:
                enabled: true
                log_file: /var/log/scr-protector/alerts.log
                min_severity: WARN
        """
        self.log_file = config.get('log_file', '/tmp/scr-alerts.log')
        self.min_severity = config.get('min_severity', 'INFO')
        
        # Severity levels for comparison
        self.severity_levels = {'INFO': 0, 'WARN': 1, 'ALERT': 2}
        
        logger.info(f"ExampleAction initialized, logging to: {self.log_file}")
        return True
    
    def execute(self, event: SecurityEvent) -> bool:
        """
        Execute action when security event occurs.
        """
        # Check if severity meets minimum threshold
        event_level = self.severity_levels.get(event.severity, 0)
        min_level = self.severity_levels.get(self.min_severity, 0)
        
        if event_level < min_level:
            return True  # Skip but don't fail
        
        # Write to log file
        try:
            with open(self.log_file, 'a') as f:
                f.write(
                    f"[{event.timestamp.isoformat()}] "
                    f"[{event.severity}] "
                    f"IP={event.ip} "
                    f"Type={event.event_type} "
                    f"Details={event.details}\n"
                )
            return True
        except Exception as e:
            logger.error(f"Failed to write alert log: {e}")
            return False
    
    def cleanup(self):
        logger.info("ExampleAction cleaned up")


# =============================================================================
# EXAMPLE BLOCKER PLUGIN
# =============================================================================

class ExampleBlocker(BlockerPlugin):
    """
    Example blocker that writes to a file (simulating external API).
    
    Customize this to:
    - Call Cloudflare API
    - Update AWS WAF rules
    - Modify external firewall
    - Send to fail2ban
    - Update router ACLs
    """
    
    @property
    def name(self) -> str:
        return "example_blocker"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Example config:
            plugins:
              example_blocker:
                enabled: false  # Disabled by default
                blocklist_file: /tmp/external-blocklist.txt
        """
        self.blocklist_file = config.get('blocklist_file', '/tmp/external-blocklist.txt')
        self.blocked_ips = set()
        
        # Load existing blocked IPs
        try:
            with open(self.blocklist_file, 'r') as f:
                self.blocked_ips = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            pass
        
        logger.info(f"ExampleBlocker initialized with {len(self.blocked_ips)} IPs")
        return True
    
    def block(self, ip: str, reason: str, duration: Optional[int] = None) -> bool:
        """Block an IP address."""
        try:
            self.blocked_ips.add(ip)
            with open(self.blocklist_file, 'a') as f:
                f.write(f"{ip}  # {reason} - {datetime.now().isoformat()}\n")
            logger.info(f"ExampleBlocker: Blocked {ip}")
            return True
        except Exception as e:
            logger.error(f"ExampleBlocker failed to block {ip}: {e}")
            return False
    
    def unblock(self, ip: str) -> bool:
        """Unblock an IP address."""
        try:
            self.blocked_ips.discard(ip)
            
            # Rewrite file without this IP
            with open(self.blocklist_file, 'r') as f:
                lines = f.readlines()
            with open(self.blocklist_file, 'w') as f:
                for line in lines:
                    if not line.strip().startswith(ip):
                        f.write(line)
            
            logger.info(f"ExampleBlocker: Unblocked {ip}")
            return True
        except Exception as e:
            logger.error(f"ExampleBlocker failed to unblock {ip}: {e}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips
    
    def cleanup(self):
        logger.info("ExampleBlocker cleaned up")


# =============================================================================
# WEBHOOK ACTION EXAMPLE
# =============================================================================

class WebhookAction(ActionPlugin):
    """
    Send alerts to a webhook URL (Slack, Discord, custom endpoint).
    
    Config:
        plugins:
          webhook_action:
            enabled: true
            url: https://hooks.slack.com/services/XXX/YYY/ZZZ
            min_severity: ALERT
    """
    
    @property
    def name(self) -> str:
        return "webhook_action"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.url = config.get('url')
        self.min_severity = config.get('min_severity', 'ALERT')
        
        if not self.url:
            logger.warning("WebhookAction: No URL configured, plugin disabled")
            return False
        
        return True
    
    def execute(self, event: SecurityEvent) -> bool:
        import urllib.request
        import json
        
        severity_levels = {'INFO': 0, 'WARN': 1, 'ALERT': 2}
        if severity_levels.get(event.severity, 0) < severity_levels.get(self.min_severity, 0):
            return True
        
        # Format message
        payload = {
            "text": f"🚨 *DDOS Protector Alert*\n"
                   f"*Severity:* {event.severity}\n"
                   f"*IP:* `{event.ip}`\n"
                   f"*Type:* {event.event_type}\n"
                   f"*Details:* {event.details}\n"
                   f"*Time:* {event.timestamp.isoformat()}"
        }
        
        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.error(f"Webhook failed: {e}")
            return False
