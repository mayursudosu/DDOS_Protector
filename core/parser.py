#!/usr/bin/env python3
"""
scr-protector: Log Parser and Threat Detector

This daemon monitors nginx access logs and SSH auth logs for suspicious
activity, logs events to the database, and optionally auto-blocks IPs.

Features:
- Tail nginx access log for 429 responses and high request rates
- Monitor SSH auth.log for brute-force attempts
- Severity-based alerting (INFO, WARN, ALERT)
- Auto-blocking when thresholds are exceeded
- Sliding window rate tracking per IP

Run as systemd service: scr-protector-parser.service
"""

import os
import sys
import time
import re
import sqlite3
import signal
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, Tuple

# Try to import yaml, fallback to defaults if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CONFIG = {
    'INSTALL_DIR': '/opt/scr-protector',
    'NGINX_ACCESS_LOG': '/var/log/nginx/access.log',
    'SSH_AUTH_LOG': '/var/log/auth.log',
    'AUTO_BLOCK_ENABLED': True,
    'WARN_THRESHOLD_429': 5,
    'WARN_WINDOW_429_MIN': 1,
    'ALERT_THRESHOLD_HTTP': 7,
    'ALERT_WINDOW_HTTP_MIN': 10,
    'ALERT_THRESHOLD_SSH': 5,
    'ALERT_WINDOW_SSH_MIN': 5,
    'HIGH_RATE_THRESHOLD': 100,
    'HIGH_RATE_WINDOW_SEC': 60,
    'SSH_ANALYTICS_ENABLED': True,
    'EMAIL_ALERT_ENABLED': False,
}

def load_config() -> dict:
    """Load configuration from YAML file or use defaults."""
    config = DEFAULT_CONFIG.copy()
    config_file = Path('/opt/scr-protector/config.yaml')
    
    if YAML_AVAILABLE and config_file.exists():
        try:
            with open(config_file) as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    config.update(file_config)
        except Exception as e:
            logging.warning(f"Failed to load config file: {e}")
    
    return config

# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('scr-parser')

# =============================================================================
# RATE TRACKER
# =============================================================================

class SlidingWindowCounter:
    """
    Track event counts per IP in a sliding time window.
    Uses a simple list of timestamps per IP, cleaning expired entries periodically.
    """
    
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self.events: Dict[str, list] = defaultdict(list)
        self.last_cleanup = datetime.now()
    
    def add(self, ip: str) -> int:
        """Add an event for IP, return current count in window."""
        now = datetime.now()
        self.events[ip].append(now)
        
        # Cleanup old entries periodically
        if (now - self.last_cleanup).seconds > 60:
            self._cleanup()
        
        return self.count(ip)
    
    def count(self, ip: str) -> int:
        """Get current count for IP within window."""
        now = datetime.now()
        cutoff = now - self.window
        
        # Filter to only recent events
        self.events[ip] = [ts for ts in self.events[ip] if ts > cutoff]
        return len(self.events[ip])
    
    def _cleanup(self):
        """Remove expired entries for all IPs."""
        now = datetime.now()
        cutoff = now - self.window
        
        for ip in list(self.events.keys()):
            self.events[ip] = [ts for ts in self.events[ip] if ts > cutoff]
            if not self.events[ip]:
                del self.events[ip]
        
        self.last_cleanup = now

# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

class Database:
    """SQLite database interface for events and blocked IPs."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_tables()
    
    def _get_conn(self):
        return sqlite3.connect(self.db_path)
    
    def _ensure_tables(self):
        """Ensure required tables exist."""
        conn = self._get_conn()
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT NOT NULL,
                    severity TEXT DEFAULT 'INFO',
                    details TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    notes TEXT
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            conn.commit()
        finally:
            conn.close()
    
    def log_event(self, ip: str, reason: str, severity: str = 'INFO', details: str = None):
        """Log a security event."""
        conn = self._get_conn()
        try:
            conn.execute(
                'INSERT INTO events (ip, reason, severity, details) VALUES (?, ?, ?, ?)',
                (ip, reason, severity, details)
            )
            conn.commit()
            logger.info(f"Event: {severity} - {ip} - {reason}")
        finally:
            conn.close()
    
    def add_blocked_ip(self, ip: str, source: str = 'parser', notes: str = None):
        """Add IP to blocked list in database."""
        conn = self._get_conn()
        try:
            conn.execute(
                'INSERT OR REPLACE INTO blocked_ips (ip, source, notes) VALUES (?, ?, ?)',
                (ip, source, notes)
            )
            conn.commit()
        finally:
            conn.close()
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is already blocked."""
        conn = self._get_conn()
        try:
            cursor = conn.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,))
            return cursor.fetchone() is not None
        finally:
            conn.close()

# =============================================================================
# BLOCKLIST MANAGER
# =============================================================================

class BlocklistManager:
    """Manage the blocklist file and trigger ipset updates."""
    
    def __init__(self, blocklist_path: str, apply_script: str):
        self.blocklist_path = blocklist_path
        self.apply_script = apply_script
        self._ensure_file()
    
    def _ensure_file(self):
        """Ensure blocklist file exists."""
        Path(self.blocklist_path).touch(exist_ok=True)
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is in blocklist file."""
        try:
            with open(self.blocklist_path) as f:
                for line in f:
                    if line.strip() == ip:
                        return True
        except Exception:
            pass
        return False
    
    def block(self, ip: str, reason: str = ''):
        """Add IP to blocklist and apply."""
        if self.is_blocked(ip):
            return False
        
        try:
            with open(self.blocklist_path, 'a') as f:
                if reason:
                    f.write(f"{ip}  # {reason} - {datetime.now().isoformat()}\n")
                else:
                    f.write(f"{ip}\n")
            
            # Trigger immediate apply
            self._apply()
            logger.warning(f"BLOCKED: {ip} - {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
    
    def _apply(self):
        """Run apply_blocklist.sh to sync with ipset."""
        try:
            import subprocess
            subprocess.run([self.apply_script], capture_output=True, check=False)
        except Exception as e:
            logger.error(f"Failed to apply blocklist: {e}")

# =============================================================================
# LOG PARSERS
# =============================================================================

# NGINX access log pattern (common/combined format)
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'  # IP address
    r'[^\[]+\['                         # Skip to timestamp
    r'(?P<timestamp>[^\]]+)\]\s+'       # Timestamp
    r'"(?P<method>\w+)\s+'              # HTTP method
    r'(?P<path>[^"]*)\s+'               # Request path
    r'[^"]*"\s+'                        # Protocol
    r'(?P<status>\d+)\s+'               # Status code
    r'(?P<bytes>\d+|-)'                 # Bytes sent
)

# SSH auth.log patterns
SSH_FAILED_PATTERN = re.compile(
    r'sshd\[\d+\]:\s+Failed\s+password\s+for\s+.*\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
SSH_INVALID_USER_PATTERN = re.compile(
    r'sshd\[\d+\]:\s+Invalid\s+user\s+.*\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_nginx_line(line: str) -> Optional[Tuple[str, int, str]]:
    """Parse nginx access log line, return (ip, status, path) or None."""
    match = NGINX_PATTERN.match(line)
    if match:
        return (
            match.group('ip'),
            int(match.group('status')),
            match.group('path')
        )
    return None

def parse_ssh_line(line: str) -> Optional[str]:
    """Parse SSH auth log line, return IP if failed login, else None."""
    for pattern in [SSH_FAILED_PATTERN, SSH_INVALID_USER_PATTERN]:
        match = pattern.search(line)
        if match:
            return match.group('ip')
    return None

# =============================================================================
# FILE TAILER
# =============================================================================

class FileTailer:
    """
    Tail a file like 'tail -f', handling rotation.
    """
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.inode = None
        self._open()
    
    def _open(self):
        """Open file and seek to end."""
        try:
            self.file = open(self.filepath, 'r')
            self.file.seek(0, 2)  # Seek to end
            self.inode = os.stat(self.filepath).st_ino
        except FileNotFoundError:
            self.file = None
            self.inode = None
    
    def readline(self) -> Optional[str]:
        """Read a line, handling rotation."""
        if self.file is None:
            self._open()
            if self.file is None:
                return None
        
        line = self.file.readline()
        
        if not line:
            # Check for file rotation
            try:
                current_inode = os.stat(self.filepath).st_ino
                if current_inode != self.inode:
                    # File rotated, reopen
                    self.file.close()
                    self._open()
            except FileNotFoundError:
                self.file.close()
                self.file = None
            return None
        
        return line.strip()
    
    def close(self):
        if self.file:
            self.file.close()

# =============================================================================
# EMAIL ALERTS (PLACEHOLDER)
# =============================================================================

def send_email_alert(subject: str, body: str, config: dict):
    """
    Send email alert if configured.
    
    This is a placeholder implementation. To enable:
    1. Set EMAIL_ALERT_ENABLED: true in config.yaml
    2. Configure SMTP settings
    3. Install smtplib (standard library)
    
    Example implementation:
    
    import smtplib
    from email.mime.text import MIMEText
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config['EMAIL_FROM']
    msg['To'] = config['EMAIL_TO']
    
    with smtplib.SMTP(config['EMAIL_SMTP_SERVER'], config['EMAIL_SMTP_PORT']) as server:
        server.starttls()
        server.login(config['EMAIL_SMTP_USER'], config['EMAIL_SMTP_PASS'])
        server.send_message(msg)
    """
    if not config.get('EMAIL_ALERT_ENABLED'):
        return
    
    logger.info(f"EMAIL ALERT (placeholder): {subject}")
    # TODO: Implement actual email sending

# =============================================================================
# MAIN PARSER DAEMON
# =============================================================================

class ParserDaemon:
    """Main daemon that monitors logs and processes events."""
    
    def __init__(self, config: dict):
        self.config = config
        self.running = True
        
        # Database
        db_path = os.path.join(config['INSTALL_DIR'], 'dashboard.db')
        self.db = Database(db_path)
        
        # Blocklist
        blocklist_path = os.path.join(config['INSTALL_DIR'], 'blocklist.txt')
        apply_script = os.path.join(config['INSTALL_DIR'], 'bin', 'apply_blocklist.sh')
        self.blocklist = BlocklistManager(blocklist_path, apply_script)
        
        # Rate trackers
        self.request_counter = SlidingWindowCounter(config['HIGH_RATE_WINDOW_SEC'])
        self.rate_limit_counter = SlidingWindowCounter(config['WARN_WINDOW_429_MIN'] * 60)
        self.http_alert_counter = SlidingWindowCounter(config['ALERT_WINDOW_HTTP_MIN'] * 60)
        self.ssh_counter = SlidingWindowCounter(config['ALERT_WINDOW_SSH_MIN'] * 60)
        
        # File tailers
        self.nginx_tailer = FileTailer(config['NGINX_ACCESS_LOG'])
        self.ssh_tailer = None
        if config.get('SSH_ANALYTICS_ENABLED'):
            self.ssh_tailer = FileTailer(config['SSH_AUTH_LOG'])
        
        # Tracking already blocked to avoid duplicate blocks
        self.recently_blocked = set()
        
        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
    
    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def process_nginx_line(self, line: str):
        """Process a single nginx access log line."""
        parsed = parse_nginx_line(line)
        if not parsed:
            return
        
        ip, status, path = parsed
        
        # Skip localhost
        if ip in ('127.0.0.1', '::1'):
            return
        
        # Track request rate
        request_count = self.request_counter.add(ip)
        
        # Check for high request rate
        if request_count >= self.config['HIGH_RATE_THRESHOLD']:
            self.db.log_event(ip, 'high_rate', 'WARN', 
                              f'{request_count} requests in {self.config["HIGH_RATE_WINDOW_SEC"]}s')
            self.http_alert_counter.add(ip)
        
        # Check for rate limit hit (429)
        if status == 429:
            count_429 = self.rate_limit_counter.add(ip)
            
            # Log event
            if count_429 >= self.config['WARN_THRESHOLD_429']:
                severity = 'WARN'
                self.http_alert_counter.add(ip)
            else:
                severity = 'INFO'
            
            self.db.log_event(ip, 'rate_limit', severity, f'429 response, count: {count_429}')
        
        # Check HTTP alert threshold for auto-block
        http_alert_count = self.http_alert_counter.count(ip)
        if http_alert_count >= self.config['ALERT_THRESHOLD_HTTP']:
            self._trigger_block(ip, 'http_abuse', 
                               f'{http_alert_count} suspicious events in {self.config["ALERT_WINDOW_HTTP_MIN"]}min')
    
    def process_ssh_line(self, line: str):
        """Process a single SSH auth log line."""
        ip = parse_ssh_line(line)
        if not ip:
            return
        
        # Skip localhost
        if ip in ('127.0.0.1', '::1'):
            return
        
        # Track SSH failures
        ssh_count = self.ssh_counter.add(ip)
        
        # Determine severity
        if ssh_count >= self.config['ALERT_THRESHOLD_SSH']:
            severity = 'ALERT'
            self._trigger_block(ip, 'ssh_bruteforce',
                               f'{ssh_count} failed logins in {self.config["ALERT_WINDOW_SSH_MIN"]}min')
        elif ssh_count >= 3:
            severity = 'WARN'
        else:
            severity = 'INFO'
        
        self.db.log_event(ip, 'ssh_failed', severity, f'Failed SSH login, count: {ssh_count}')
    
    def _trigger_block(self, ip: str, reason: str, details: str):
        """Trigger IP block if auto-blocking is enabled."""
        # Skip if already blocked recently
        if ip in self.recently_blocked:
            return
        
        # Log ALERT event
        self.db.log_event(ip, reason, 'ALERT', details)
        
        if not self.config.get('AUTO_BLOCK_ENABLED'):
            logger.warning(f"AUTO-BLOCK DISABLED: Would block {ip} for {reason}")
            return
        
        # Add to blocklist
        if self.blocklist.block(ip, reason):
            self.db.add_blocked_ip(ip, 'parser', details)
            self.recently_blocked.add(ip)
            
            # Send email alert if configured
            if self.config.get('EMAIL_ALERT_ENABLED'):
                send_email_alert(
                    f"[scr-protector] IP Blocked: {ip}",
                    f"IP {ip} has been automatically blocked.\n\n"
                    f"Reason: {reason}\n"
                    f"Details: {details}\n"
                    f"Time: {datetime.now().isoformat()}",
                    self.config
                )
    
    def run(self):
        """Main daemon loop."""
        logger.info("Parser daemon started")
        logger.info(f"Monitoring nginx: {self.config['NGINX_ACCESS_LOG']}")
        if self.ssh_tailer:
            logger.info(f"Monitoring SSH: {self.config['SSH_AUTH_LOG']}")
        logger.info(f"Auto-blocking: {'ENABLED' if self.config.get('AUTO_BLOCK_ENABLED') else 'DISABLED'}")
        
        while self.running:
            activity = False
            
            # Process nginx log
            line = self.nginx_tailer.readline()
            if line:
                self.process_nginx_line(line)
                activity = True
            
            # Process SSH log
            if self.ssh_tailer:
                line = self.ssh_tailer.readline()
                if line:
                    self.process_ssh_line(line)
                    activity = True
            
            # If no activity, sleep briefly to avoid busy loop
            if not activity:
                time.sleep(0.1)
            
            # Clear recently_blocked set periodically (every hour)
            # This allows re-blocking if IP keeps trying
            if len(self.recently_blocked) > 10000:
                self.recently_blocked.clear()
        
        # Cleanup
        self.nginx_tailer.close()
        if self.ssh_tailer:
            self.ssh_tailer.close()
        
        logger.info("Parser daemon stopped")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    config = load_config()
    daemon = ParserDaemon(config)
    daemon.run()

if __name__ == '__main__':
    main()
