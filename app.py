import os
import logging
from datetime import datetime
import threading
import time
import secrets
import string

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

# Initialize logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize Flask app and SQLAlchemy
db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "termux_antimalware_secret")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Heroku-style fix for SQLAlchemy 1.4+
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///termux_antimalware.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set application version
app.config['APP_VERSION'] = '1.0.0'

# Initialize the app with the extension
db.init_app(app)

# Import models and utility modules after initializing db
with app.app_context():
    from models import User, ScanResult, SecurityLog, FirewallRule, ContentFilter
    from utils.security_utils import generate_security_token, verify_token
    from utils.firewall import init_firewall, update_firewall_rules
    from utils.scanner import scan_directory
    from utils.content_filter import update_content_filters
    from utils.ai_detection import train_ai_model, predict_threat
    from utils.notification import send_notification
    import config
    
    # Create all tables
    db.create_all()
    
    # Initialize default data if not exists
    if not User.query.first():
        # Create default admin user
        default_user = User(
            username="admin",
            email="admin@termux.local",
            password_hash=generate_password_hash("termuxadmin"),
            is_admin=True
        )
        db.session.add(default_user)
        
        # Create default firewall rules
        default_rules = [
            FirewallRule(name="Block SSH", protocol="tcp", port=22, action="BLOCK"),
            FirewallRule(name="Allow HTTP", protocol="tcp", port=80, action="ALLOW"),
            FirewallRule(name="Allow HTTPS", protocol="tcp", port=443, action="ALLOW")
        ]
        for rule in default_rules:
            db.session.add(rule)
        
        # Create default content filters
        default_filters = [
            ContentFilter(name="Block Executables", file_type="exe", action="BLOCK"),
            ContentFilter(name="Block Scripts", file_type="sh", action="BLOCK"),
            ContentFilter(name="Block APKs", file_type="apk", action="SCAN")
        ]
        for filter_rule in default_filters:
            db.session.add(filter_rule)
        
        db.session.commit()
        logger.info("Default data initialized")

# Scheduler for background tasks
scheduler = BackgroundScheduler()

# Function to update security token periodically
def update_security_token():
    with app.app_context():
        new_token = generate_security_token()
        app.config['SECURITY_TOKEN'] = new_token
        logger.info(f"Security token updated at {datetime.now()}")
        
        # Log this security event
        security_log = SecurityLog(
            event_type="TOKEN_UPDATE",
            description=f"Security token automatically updated",
            timestamp=datetime.now()
        )
        db.session.add(security_log)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/terminal-guide')
def terminal_guide():
    """Documentation for using the command-line interface in Termux"""
    return render_template('terminal_guide.html')

@app.route('/dashboard')
def dashboard():
    # Get recent scan results
    recent_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).limit(5).all()
    
    # Get recent security logs
    recent_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()
    
    # Get system status
    firewall_active = config.FIREWALL_ENABLED
    filter_active = config.CONTENT_FILTER_ENABLED
    ai_active = config.AI_DETECTION_ENABLED
    
    return render_template(
        'dashboard.html',
        recent_scans=recent_scans,
        recent_logs=recent_logs,
        firewall_active=firewall_active,
        filter_active=filter_active,
        ai_active=ai_active
    )

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        directory = request.form.get('directory', '/data/data/com.termux/files')
        
        try:
            # Run scan
            results = scan_directory(directory)
            
            # Save results to database
            scan_entry = ScanResult(
                directory=directory,
                threats_found=len(results['threats']),
                files_scanned=results['total_files'],
                timestamp=datetime.now()
            )
            db.session.add(scan_entry)
            db.session.commit()
            
            flash('Scan completed successfully', 'success')
            return render_template('scan.html', results=results, directory=directory)
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            flash(f'Error during scan: {str(e)}', 'danger')
    
    return render_template('scan.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        # Update settings based on form submission
        config.FIREWALL_ENABLED = 'firewall_enabled' in request.form
        config.CONTENT_FILTER_ENABLED = 'content_filter_enabled' in request.form
        config.AI_DETECTION_ENABLED = 'ai_detection_enabled' in request.form
        
        # Apply changes
        if config.FIREWALL_ENABLED:
            update_firewall_rules()
        
        if config.CONTENT_FILTER_ENABLED:
            update_content_filters()
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    
    # Get current firewall rules
    firewall_rules = FirewallRule.query.all()
    
    # Get current content filters
    content_filters = ContentFilter.query.all()
    
    return render_template(
        'settings.html',
        firewall_enabled=config.FIREWALL_ENABLED,
        content_filter_enabled=config.CONTENT_FILTER_ENABLED,
        ai_detection_enabled=config.AI_DETECTION_ENABLED,
        firewall_rules=firewall_rules,
        content_filters=content_filters
    )

@app.route('/logs')
def logs():
    # Get all security logs
    all_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=all_logs)

@app.route('/api/firewall/rule', methods=['POST'])
def add_firewall_rule():
    data = request.json
    try:
        new_rule = FirewallRule(
            name=data['name'],
            protocol=data['protocol'],
            port=data['port'],
            action=data['action']
        )
        db.session.add(new_rule)
        db.session.commit()
        
        # Apply the rule
        if config.FIREWALL_ENABLED:
            update_firewall_rules()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/content-filter/rule', methods=['POST'])
def add_content_filter():
    data = request.json
    try:
        new_filter = ContentFilter(
            name=data['name'],
            file_type=data['file_type'],
            action=data['action']
        )
        db.session.add(new_filter)
        db.session.commit()
        
        # Apply the filter
        if config.CONTENT_FILTER_ENABLED:
            update_content_filters()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/ai/train', methods=['POST'])
def train_ai():
    try:
        train_ai_model()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/security-token')
def get_security_token():
    """API endpoint to get the current security token (first 6 characters only)"""
    if 'SECURITY_TOKEN' in app.config:
        token = app.config['SECURITY_TOKEN']
        return jsonify({"success": True, "token": token[:6] + "..."})
    else:
        return jsonify({"success": False, "error": "Security token not initialized"})

def init_app():
    # Initialize firewall
    if config.FIREWALL_ENABLED:
        init_firewall()
    
    # Initialize AI model
    if config.AI_DETECTION_ENABLED:
        try:
            train_ai_model()
        except Exception as e:
            logger.error(f"Failed to initialize AI model: {str(e)}")
    
    # Generate initial security token
    app.config['SECURITY_TOKEN'] = generate_security_token()
    
    # Schedule token update (every 20 seconds)
    scheduler.add_job(update_security_token, 'interval', seconds=20)
    
    # Start the scheduler
    scheduler.start()
    
    logger.info("Application initialized successfully")

# Initialize app when imported
init_app()

# Run the app if executed directly
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
