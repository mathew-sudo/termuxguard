import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "termux_firewall_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///firewall.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Import routes after app initialization to avoid circular imports
from models import User, FirewallRule, MalwareScan, SecurityLog, SystemConfig

@app.route('/')
def index():
    """Main dashboard for the firewall application."""
    # Check if a user is logged in
    if 'user_id' not in session:
        # If no user is logged in, redirect to the login page
        return render_template('index.html')
    
    # Get the latest security logs, limited to 10 entries
    latest_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()
    
    # Get active firewall rules
    active_rules = FirewallRule.query.filter_by(is_active=True).all()
    
    # Get latest scan results
    latest_scans = MalwareScan.query.order_by(MalwareScan.timestamp.desc()).limit(5).all()
    
    # Get system status
    try:
        from network_monitor import get_network_status
        network_status = get_network_status()
    except Exception as e:
        logger.error(f"Failed to get network status: {e}")
        network_status = {"status": "unknown", "error": str(e)}
    
    return render_template(
        'dashboard.html',
        logs=latest_logs,
        rules=active_rules,
        scans=latest_scans,
        network_status=network_status
    )

@app.route('/logs')
def logs():
    """View all security logs."""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False)
    
    return render_template('logs.html', logs=logs)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Modify firewall and system settings."""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(
            auto_start=True,
            scan_interval=60,
            notification_level="high",
            breach_protection_enabled=True
        )
        db.session.add(config)
        db.session.commit()
    
    if request.method == 'POST':
        config.auto_start = 'auto_start' in request.form
        config.scan_interval = int(request.form.get('scan_interval', 60))
        config.notification_level = request.form.get('notification_level', 'high')
        config.breach_protection_enabled = 'breach_protection' in request.form
        
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', config=config)

@app.route('/scan', methods=['GET'])
def scan():
    """Malware scanner page with advanced options."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if there's an active scan or get the latest scan result
    from models import MalwareScan
    latest_scan = MalwareScan.query.order_by(MalwareScan.timestamp.desc()).first()
    
    # If the scan is in progress or was recently completed, get threats
    scan_status = None
    if latest_scan:
        # Convert to dictionary for template
        scan_status = {
            'id': latest_scan.id,
            'status': latest_scan.status,
            'files_scanned': latest_scan.files_scanned,
            'threats_found': latest_scan.threats_found,
            'scan_type': latest_scan.scan_type,
            'scan_path': latest_scan.scan_path,
            'scan_depth': latest_scan.scan_depth,
            'thorough_scan': latest_scan.thorough_scan,
            'auto_quarantine': latest_scan.auto_quarantine,
            'duration_seconds': latest_scan.duration_seconds,
            'threats': []
        }
        
        # If the scan is completed and found threats, get the threat details
        if latest_scan.status in ['completed', 'failed', 'cancelled'] and latest_scan.threats_found > 0:
            from models import MalwareThreat
            threats = MalwareThreat.query.filter_by(scan_id=latest_scan.id).all()
            
            for threat in threats:
                scan_status['threats'].append({
                    'id': threat.id,
                    'file_path': threat.file_path,
                    'threat_type': threat.threat_type,
                    'threat_name': threat.threat_name,
                    'severity': threat.severity,
                    'action_taken': threat.action_taken,
                    'file_hash': threat.file_hash,
                    'file_size': threat.file_size,
                    'can_restore': threat.can_restore
                })
    
    return render_template('scan.html', scan_status=scan_status)

@app.route('/quarantine', methods=['GET'])
def quarantine():
    """Quarantine management page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get all quarantined files
    from models import MalwareThreat
    quarantined_files = MalwareThreat.query.filter_by(
        action_taken='quarantined'
    ).order_by(MalwareThreat.timestamp.desc()).all()
    
    return render_template('quarantine.html', quarantined_files=quarantined_files)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a malware scan with the specified options."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        from malware_scanner import start_scan_task
        
        # Parse advanced scan options from form
        scan_type = request.form.get('scan_type', 'full')
        scan_path = request.form.get('scan_path')
        
        # Validate path for targeted scans
        if scan_type == 'targeted' and not scan_path:
            flash('Path must be specified for targeted scans.', 'danger')
            return redirect(url_for('scan'))
        
        # Parse other options
        try:
            scan_depth = int(request.form.get('scan_depth', 3))
        except ValueError:
            scan_depth = 3
            
        thorough_scan = 'thorough_scan' in request.form
        auto_quarantine = 'auto_quarantine' in request.form
        
        # Start the scan with the specified options
        scan_id = start_scan_task(
            scan_type=scan_type,
            scan_path=scan_path,
            scan_depth=scan_depth,
            thorough_scan=thorough_scan,
            auto_quarantine=auto_quarantine
        )
        
        if scan_id:
            flash(f'Scan started successfully. ID: {scan_id}', 'success')
        else:
            flash('Failed to start scan. Another scan may already be in progress.', 'danger')
            
        return redirect(url_for('scan'))
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        flash(f'Error starting scan: {e}', 'danger')
        return redirect(url_for('scan'))
        
@app.route('/api/start_scan', methods=['POST'])
def api_start_scan():
    """API endpoint to start a malware scan."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from malware_scanner import start_scan_task
        
        # Parse advanced scan options from request
        data = request.get_json() or {}
        scan_type = data.get('scan_type', 'full')
        scan_path = data.get('scan_path')
        scan_depth = data.get('scan_depth', 3)
        thorough_scan = data.get('thorough_scan', False)
        auto_quarantine = data.get('auto_quarantine', False)
        
        scan_id = start_scan_task(
            scan_type=scan_type,
            scan_path=scan_path,
            scan_depth=scan_depth,
            thorough_scan=thorough_scan,
            auto_quarantine=auto_quarantine
        )
        
        return jsonify({
            "status": "success", 
            "scan_id": scan_id,
            "scan_type": scan_type,
            "thorough_scan": thorough_scan,
            "auto_quarantine": auto_quarantine
        })
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/scan_status/<int:scan_id>', methods=['GET'])
def scan_status(scan_id):
    """API endpoint to check the status of a malware scan."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from malware_scanner import get_scan_status
        status_data = get_scan_status(scan_id)
        
        if status_data:
            return jsonify(status_data)
        else:
            return jsonify({"status": "error", "message": "Scan not found"}), 404
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/toggle_firewall', methods=['POST'])
def toggle_firewall():
    """API endpoint to enable/disable the firewall."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from firewall import toggle_firewall_status
        data = request.get_json()
        enabled = data.get('enabled', True)
        status = toggle_firewall_status(enabled)
        return jsonify({"status": "success", "firewall_enabled": status})
    except Exception as e:
        logger.error(f"Failed to toggle firewall: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login endpoint."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('index.html')

@app.route('/logout')
def logout():
    """User logout endpoint."""
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/api/add_rule', methods=['POST'])
def add_rule():
    """API endpoint to add a firewall rule."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        data = request.get_json()
        rule = FirewallRule(
            rule_type=data.get('rule_type'),
            target=data.get('target'),
            action=data.get('action'),
            priority=data.get('priority', 5),
            is_active=data.get('is_active', True),
            description=data.get('description', '')
        )
        db.session.add(rule)
        db.session.commit()
        
        # Apply the rule in real-time
        from firewall import apply_rule
        apply_rule(rule)
        
        return jsonify({"status": "success", "rule_id": rule.id})
    except Exception as e:
        logger.error(f"Failed to add rule: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/system_status')
def system_status():
    """Get the current system status."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from network_monitor import get_network_status
        from breach_monitor import get_breach_status
        
        network_status = get_network_status()
        breach_status = get_breach_status()
        
        return jsonify({
            "status": "success",
            "network": network_status,
            "breach": breach_status,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/reset_breach', methods=['POST'])
def reset_breach():
    """API endpoint to reset breach status."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from breach_monitor import reset_breach_status
        
        status = reset_breach_status()
        return jsonify({"status": "success", "breach_status": status})
    except Exception as e:
        logger.error(f"Failed to reset breach status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/cancel_scan', methods=['POST'])
def cancel_scan():
    """API endpoint to cancel an ongoing malware scan."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from malware_scanner import cancel_scan
        
        result = cancel_scan()
        if result:
            return jsonify({"status": "success", "message": "Scan cancellation requested"})
        else:
            return jsonify({"status": "error", "message": "No scan is currently in progress"}), 400
    except Exception as e:
        logger.error(f"Failed to cancel scan: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/quarantined_files', methods=['GET'])
def get_quarantined_files():
    """API endpoint to get all quarantined files."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from models import MalwareThreat
        
        # Query all threats that have been quarantined
        quarantined = MalwareThreat.query.filter_by(
            action_taken='quarantined',
            can_restore=True
        ).order_by(MalwareThreat.timestamp.desc()).all()
        
        # Prepare the response
        files = []
        for item in quarantined:
            files.append({
                'id': item.id,
                'file_path': item.file_path,
                'threat_name': item.threat_name,
                'threat_type': item.threat_type,
                'severity': item.severity,
                'quarantine_path': item.quarantine_path,
                'timestamp': item.timestamp.isoformat() if item.timestamp else None,
                'scan_id': item.scan_id
            })
        
        return jsonify({
            "status": "success", 
            "quarantined_files": files,
            "count": len(files)
        })
    except Exception as e:
        logger.error(f"Failed to get quarantined files: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/restore_file', methods=['POST'])
def restore_file():
    """Web endpoint to restore a file from quarantine."""
    if 'user_id' not in session:
        flash('Authentication required', 'danger')
        return redirect(url_for('login'))
    
    try:
        from malware_scanner import restore_from_quarantine
        from models import MalwareThreat
        
        threat_id = request.form.get('threat_id')
        
        if not threat_id:
            flash('Threat ID is required', 'danger')
            return redirect(url_for('quarantine'))
        
        # Find the threat in the database
        threat = MalwareThreat.query.get(threat_id)
        if not threat or threat.action_taken != 'quarantined' or not threat.can_restore:
            flash('Threat not found or cannot be restored', 'danger')
            return redirect(url_for('quarantine'))
        
        # Restore the file
        result = restore_from_quarantine(threat.quarantine_path)
        if result:
            # Update the threat record
            threat.action_taken = 'restored'
            threat.can_restore = False
            db.session.commit()
            
            # Add a log entry
            log = SecurityLog(
                log_type='malware',
                severity='warning',
                source=threat.file_path,
                message=f"Malware restored from quarantine: {threat.threat_name}",
                details=f"User manually restored quarantined file: {threat.file_path}"
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'File restored successfully to: {threat.file_path}', 'success')
        else:
            flash('Failed to restore file', 'danger')
        
        return redirect(url_for('quarantine'))
    except Exception as e:
        logger.error(f"Failed to restore file: {e}")
        flash(f'Error restoring file: {str(e)}', 'danger')
        return redirect(url_for('quarantine'))

@app.route('/api/restore_file', methods=['POST'])
def api_restore_file():
    """API endpoint to restore a file from quarantine."""
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    
    try:
        from malware_scanner import restore_from_quarantine
        from models import MalwareThreat
        
        data = request.get_json()
        threat_id = data.get('threat_id')
        
        if not threat_id:
            return jsonify({"status": "error", "message": "Threat ID is required"}), 400
        
        # Find the threat in the database
        threat = MalwareThreat.query.get(threat_id)
        if not threat or threat.action_taken != 'quarantined' or not threat.can_restore:
            return jsonify({"status": "error", "message": "Threat not found or cannot be restored"}), 404
        
        # Restore the file
        result = restore_from_quarantine(threat.quarantine_path)
        if result:
            # Update the threat record
            threat.action_taken = 'restored'
            threat.can_restore = False
            db.session.commit()
            
            # Add a log entry
            log = SecurityLog(
                log_type='malware',
                severity='warning',
                source=threat.file_path,
                message=f"Malware restored from quarantine: {threat.threat_name}",
                details=f"User manually restored quarantined file: {threat.file_path}"
            )
            db.session.add(log)
            db.session.commit()
            
            return jsonify({"status": "success", "message": "File restored successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to restore file"}), 500
    except Exception as e:
        logger.error(f"Failed to restore file: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Setup context processor for global template variables
@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    def is_logged_in():
        return 'user_id' in session
    
    def get_username():
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            return user.username if user else 'User'
        return None
    
    return dict(is_logged_in=is_logged_in, get_username=get_username)

with app.app_context():
    # Create all database tables
    db.create_all()
    
    # Create default admin user if no users exist
    if not User.query.first():
        admin_user = User(
            username="admin",
            password_hash=generate_password_hash("termuxadmin")
        )
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Created default admin user")
    
    # Create default system configuration if not exists
    if not SystemConfig.query.first():
        default_config = SystemConfig(
            auto_start=True,
            scan_interval=60,
            notification_level="high",
            breach_protection_enabled=True
        )
        db.session.add(default_config)
        db.session.commit()
        logger.info("Created default system configuration")

    logger.info("Application initialized successfully")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
