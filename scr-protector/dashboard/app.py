#!/usr/bin/env python3
"""
scr-protector: Dashboard Application

Flask-based admin dashboard for monitoring and managing security events.
Binds to localhost by default for security.

Features:
- Login-protected admin interface
- Blocked IPs management (block/unblock)
- Security events timeline
- Alerts view (WARN + ALERT severity)
- Statistics and graphs
- API endpoints for automation

Access via SSH tunnel:
    ssh -L 8080:localhost:8080 user@server
    http://localhost:8080/admin
"""

import os
import sys
import sqlite3
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, g
)
from werkzeug.security import check_password_hash, generate_password_hash

# Try to import yaml
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
    'DASHBOARD_PORT': 8080,
    'DASHBOARD_BIND': '127.0.0.1',
    'ALLOW_DASHBOARD_PUBLIC': False,
    'BLOCKLIST_FILE': '/opt/scr-protector/blocklist.txt',
    'USE_ANUBIS': False,
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
            print(f"Warning: Failed to load config: {e}")
    
    return config

CONFIG = load_config()

# =============================================================================
# FLASK APP SETUP
# =============================================================================

app = Flask(__name__)

# Generate or load persistent secret key (survives restarts)
SECRET_KEY_FILE = os.path.join(CONFIG['INSTALL_DIR'], '.secret_key')
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'rb') as f:
        app.secret_key = f.read()
else:
    app.secret_key = os.urandom(32)
    try:
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(app.secret_key)
        os.chmod(SECRET_KEY_FILE, 0o600)
    except Exception:
        pass  # Will regenerate on restart if can't save

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS

# Database path
DB_PATH = os.path.join(CONFIG['INSTALL_DIR'], 'dashboard.db')
BLOCKLIST_PATH = CONFIG['BLOCKLIST_FILE']
APPLY_SCRIPT = os.path.join(CONFIG['INSTALL_DIR'], 'bin', 'apply_blocklist.sh')

# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db():
    """Get database connection for request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# =============================================================================
# AUTHENTICATION
# =============================================================================

def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        user = db.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            next_url = request.args.get('next')
            if next_url:
                return redirect(next_url)
            return redirect(url_for('admin'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('login'))

# =============================================================================
# ADMIN PAGES
# =============================================================================

@app.route('/')
def index():
    """Redirect to admin."""
    return redirect(url_for('admin'))

@app.route('/admin')
@login_required
def admin():
    """Main admin dashboard."""
    db = get_db()
    
    # Get statistics
    stats = {
        'total_events_today': db.execute('''
            SELECT COUNT(*) FROM events 
            WHERE date(ts) = date('now')
        ''').fetchone()[0],
        
        'alerts_today': db.execute('''
            SELECT COUNT(*) FROM events 
            WHERE severity = 'ALERT' AND date(ts) = date('now')
        ''').fetchone()[0],
        
        'blocked_ips': db.execute('''
            SELECT COUNT(*) FROM blocked_ips
        ''').fetchone()[0],
        
        'rate_limit_hits': db.execute('''
            SELECT COUNT(*) FROM events 
            WHERE reason = 'rate_limit' AND date(ts) = date('now')
        ''').fetchone()[0],
    }
    
    # Get recent events
    recent_events = db.execute('''
        SELECT id, ip, datetime(ts, 'localtime') as time, reason, severity, details
        FROM events 
        ORDER BY ts DESC 
        LIMIT 20
    ''').fetchall()
    
    # Get blocked IPs
    blocked_ips = db.execute('''
        SELECT ip, datetime(ts, 'localtime') as time, source, notes
        FROM blocked_ips 
        ORDER BY ts DESC
    ''').fetchall()
    
    # Get alerts (WARN + ALERT)
    alerts = db.execute('''
        SELECT id, ip, datetime(ts, 'localtime') as time, reason, severity, details
        FROM events 
        WHERE severity IN ('WARN', 'ALERT')
        ORDER BY ts DESC 
        LIMIT 50
    ''').fetchall()
    
    return render_template('admin.html',
                          stats=stats,
                          recent_events=recent_events,
                          blocked_ips=blocked_ips,
                          alerts=alerts,
                          username=session.get('username'),
                          use_anubis=CONFIG.get('USE_ANUBIS', False))

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Get dashboard statistics."""
    db = get_db()
    
    # Events by severity (last 24 hours)
    severity_counts = db.execute('''
        SELECT severity, COUNT(*) as count
        FROM events
        WHERE ts > datetime('now', '-24 hours')
        GROUP BY severity
    ''').fetchall()
    
    # Events by reason (last 24 hours)
    reason_counts = db.execute('''
        SELECT reason, COUNT(*) as count
        FROM events
        WHERE ts > datetime('now', '-24 hours')
        GROUP BY reason
    ''').fetchall()
    
    # Hourly event counts (last 24 hours)
    hourly = db.execute('''
        SELECT strftime('%H', ts) as hour, COUNT(*) as count
        FROM events
        WHERE ts > datetime('now', '-24 hours')
        GROUP BY strftime('%Y-%m-%d %H', ts)
        ORDER BY ts
    ''').fetchall()
    
    # Top blocked IPs
    top_ips = db.execute('''
        SELECT ip, COUNT(*) as count
        FROM events
        WHERE ts > datetime('now', '-24 hours')
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 10
    ''').fetchall()
    
    return jsonify({
        'severity': {row['severity']: row['count'] for row in severity_counts},
        'reasons': {row['reason']: row['count'] for row in reason_counts},
        'hourly': [{'hour': row['hour'], 'count': row['count']} for row in hourly],
        'top_ips': [{'ip': row['ip'], 'count': row['count']} for row in top_ips],
        'total_blocked': db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0],
    })

@app.route('/api/blocked')
@login_required
def api_blocked():
    """Get list of blocked IPs."""
    db = get_db()
    blocked = db.execute('''
        SELECT ip, datetime(ts, 'localtime') as time, source, notes
        FROM blocked_ips
        ORDER BY ts DESC
    ''').fetchall()
    
    return jsonify([{
        'ip': row['ip'],
        'time': row['time'],
        'source': row['source'],
        'notes': row['notes']
    } for row in blocked])

@app.route('/api/block', methods=['POST'])
@login_required
def api_block():
    """Block an IP address."""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address required'}), 400
    
    ip = data['ip'].strip()
    notes = data.get('notes', 'Blocked via dashboard')
    
    # Validate IP format properly
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': 'Invalid IP address format'}), 400
    
    try:
        # Add to blocklist file
        with open(BLOCKLIST_PATH, 'a') as f:
            f.write(f"{ip}  # {notes} - {datetime.now().isoformat()}\n")
        
        # Add to database
        db = get_db()
        db.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip, source, notes)
            VALUES (?, 'dashboard', ?)
        ''', (ip, notes))
        db.commit()
        
        # Apply blocklist
        subprocess.run([APPLY_SCRIPT], capture_output=True)
        
        return jsonify({'success': True, 'ip': ip})
    
    except Exception as e:
        app.logger.error(f"Block failed for {ip}: {e}")
        return jsonify({'error': 'Operation failed'}), 500

@app.route('/api/unblock', methods=['POST'])
@login_required
def api_unblock():
    """Unblock an IP address."""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address required'}), 400
    
    ip = data['ip'].strip()
    
    try:
        # Remove from blocklist file
        if os.path.exists(BLOCKLIST_PATH):
            with open(BLOCKLIST_PATH, 'r') as f:
                lines = f.readlines()
            
            with open(BLOCKLIST_PATH, 'w') as f:
                for line in lines:
                    # Extract IP (first word) and match exactly
                    line_ip = line.strip().split()[0] if line.strip() else ''
                    if line_ip != ip:
                        f.write(line)
        
        # Remove from database
        db = get_db()
        db.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        db.commit()
        
        # Apply blocklist
        subprocess.run([APPLY_SCRIPT], capture_output=True)
        
        return jsonify({'success': True, 'ip': ip})
    
    except Exception as e:
        app.logger.error(f"Unblock failed for {ip}: {e}")
        return jsonify({'error': 'Operation failed'}), 500

@app.route('/api/alerts')
@login_required
def api_alerts():
    """Get alert events (WARN + ALERT severity)."""
    db = get_db()
    
    limit = min(request.args.get('limit', 50, type=int), 1000)
    offset = max(request.args.get('offset', 0, type=int), 0)
    
    alerts = db.execute('''
        SELECT id, ip, datetime(ts, 'localtime') as time, reason, severity, details
        FROM events
        WHERE severity IN ('WARN', 'ALERT')
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
    ''', (limit, offset)).fetchall()
    
    return jsonify([{
        'id': row['id'],
        'ip': row['ip'],
        'time': row['time'],
        'reason': row['reason'],
        'severity': row['severity'],
        'details': row['details']
    } for row in alerts])

@app.route('/api/events')
@login_required
def api_events():
    """Get all events with pagination."""
    db = get_db()
    
    limit = min(request.args.get('limit', 50, type=int), 1000)
    offset = max(request.args.get('offset', 0, type=int), 0)
    severity = request.args.get('severity')
    
    if severity:
        events = db.execute('''
            SELECT id, ip, datetime(ts, 'localtime') as time, reason, severity, details
            FROM events
            WHERE severity = ?
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        ''', (severity, limit, offset)).fetchall()
    else:
        events = db.execute('''
            SELECT id, ip, datetime(ts, 'localtime') as time, reason, severity, details
            FROM events
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
    
    return jsonify([{
        'id': row['id'],
        'ip': row['ip'],
        'time': row['time'],
        'reason': row['reason'],
        'severity': row['severity'],
        'details': row['details']
    } for row in events])

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run the Flask application."""
    host = CONFIG['DASHBOARD_BIND']
    port = CONFIG['DASHBOARD_PORT']
    
    if CONFIG.get('ALLOW_DASHBOARD_PUBLIC'):
        host = '0.0.0.0'
        print(f"WARNING: Dashboard exposed publicly on {host}:{port}")
    else:
        print(f"Dashboard bound to {host}:{port} (access via SSH tunnel)")
    
    # Use gunicorn in production, Flask dev server for testing
    try:
        import gunicorn
        # If gunicorn is available, we're likely being run via gunicorn
        pass
    except ImportError:
        # Development mode
        app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    main()
