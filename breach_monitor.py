import os
import logging
import threading
import time
import json
import psutil
from datetime import datetime
from utils import get_termux_path, is_process_running

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
monitoring_active = False
monitor_thread = None
breach_detection_rules = []
breach_status = {
    'status': 'normal',
    'last_check': datetime.now().isoformat(),
    'alerts': []
}
RULES_FILE = os.path.join(get_termux_path('data'), 'breach_rules.json')

def load_breach_rules():
    """Load breach detection rules from file."""
    global breach_detection_rules
    
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                breach_detection_rules = json.load(f)
            logger.info(f"Loaded {len(breach_detection_rules)} breach detection rules")
        else:
            create_default_breach_rules()
    except Exception as e:
        logger.error(f"Failed to load breach detection rules: {e}")
        create_default_breach_rules()

def create_default_breach_rules():
    """Create default breach detection rules."""
    global breach_detection_rules
    
    default_rules = [
        {
            'id': 1,
            'type': 'file_change',
            'target': os.path.join(get_termux_path('home'), '.termux'),
            'severity': 'high',
            'description': 'Termux configuration files modified'
        },
        {
            'id': 2,
            'type': 'suspicious_process',
            'target': 'miner',
            'severity': 'critical',
            'description': 'Potential cryptominer process'
        },
        {
            'id': 3,
            'type': 'network_anomaly',
            'target': 'connections_spike',
            'threshold': 50,  # Number of connections
            'severity': 'medium',
            'description': 'Unusual number of network connections'
        },
        {
            'id': 4,
            'type': 'resource_usage',
            'target': 'cpu',
            'threshold': 90,  # Percentage
            'duration': 300,  # Seconds
            'severity': 'medium',
            'description': 'Sustained high CPU usage'
        }
    ]
    
    breach_detection_rules = default_rules
    
    # Save default rules to file
    try:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, 'w') as f:
            json.dump(default_rules, f, indent=2)
        logger.info("Created default breach detection rules")
    except Exception as e:
        logger.error(f"Failed to save default breach rules: {e}")

def check_file_changes():
    """Check for unauthorized changes to important files."""
    alerts = []
    
    for rule in breach_detection_rules:
        if rule['type'] == 'file_change':
            target_path = rule['target']
            
            try:
                # Get the last modification time of the file or directory
                if os.path.exists(target_path):
                    last_modified = os.path.getmtime(target_path)
                    now = time.time()
                    
                    # Alert on recent changes (within last 5 minutes)
                    if (now - last_modified) < 300:  # 5 minutes
                        alert = {
                            'type': 'file_change',
                            'timestamp': datetime.now().isoformat(),
                            'severity': rule['severity'],
                            'message': f"Recent changes detected in {target_path}",
                            'details': {
                                'file': target_path,
                                'modified_at': datetime.fromtimestamp(last_modified).isoformat()
                            }
                        }
                        alerts.append(alert)
                        logger.warning(f"File change detected: {target_path}")
            except Exception as e:
                logger.error(f"Error checking file changes for {target_path}: {e}")
    
    return alerts

def check_suspicious_processes():
    """Check for suspicious processes running on the system."""
    alerts = []
    
    for rule in breach_detection_rules:
        if rule['type'] == 'suspicious_process':
            suspicious_keyword = rule['target'].lower()
            
            try:
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    process_info = proc.info
                    
                    # Check process name and command line for suspicious keywords
                    process_name = process_info.get('name', '').lower()
                    cmdline = ' '.join([str(cmd) for cmd in process_info.get('cmdline', []) if cmd]).lower()
                    
                    if suspicious_keyword in process_name or suspicious_keyword in cmdline:
                        alert = {
                            'type': 'suspicious_process',
                            'timestamp': datetime.now().isoformat(),
                            'severity': rule['severity'],
                            'message': f"Suspicious process detected: {process_info.get('name')}",
                            'details': {
                                'pid': process_info.get('pid'),
                                'name': process_info.get('name'),
                                'cmdline': cmdline
                            }
                        }
                        alerts.append(alert)
                        logger.warning(f"Suspicious process detected: {process_info.get('name')}")
            except Exception as e:
                logger.error(f"Error checking suspicious processes: {e}")
    
    return alerts

def check_network_anomalies():
    """Check for network anomalies and suspicious connections."""
    alerts = []
    
    for rule in breach_detection_rules:
        if rule['type'] == 'network_anomaly':
            try:
                if rule['target'] == 'connections_spike':
                    # Count active network connections
                    connections = psutil.net_connections()
                    conn_count = len(connections)
                    
                    # Alert if connections exceed threshold
                    if conn_count > rule['threshold']:
                        alert = {
                            'type': 'network_anomaly',
                            'timestamp': datetime.now().isoformat(),
                            'severity': rule['severity'],
                            'message': f"Unusual number of network connections: {conn_count}",
                            'details': {
                                'connections_count': conn_count,
                                'threshold': rule['threshold']
                            }
                        }
                        alerts.append(alert)
                        logger.warning(f"Network anomaly detected: {conn_count} connections")
            except Exception as e:
                logger.error(f"Error checking network anomalies: {e}")
    
    return alerts

def check_resource_usage():
    """Check for abnormal resource usage."""
    alerts = []
    
    for rule in breach_detection_rules:
        if rule['type'] == 'resource_usage':
            try:
                if rule['target'] == 'cpu':
                    # Check CPU usage
                    cpu_percent = psutil.cpu_percent(interval=1)
                    
                    # Alert if CPU usage exceeds threshold
                    if cpu_percent > rule['threshold']:
                        alert = {
                            'type': 'resource_usage',
                            'timestamp': datetime.now().isoformat(),
                            'severity': rule['severity'],
                            'message': f"High CPU usage detected: {cpu_percent}%",
                            'details': {
                                'cpu_percent': cpu_percent,
                                'threshold': rule['threshold']
                            }
                        }
                        alerts.append(alert)
                        logger.warning(f"High CPU usage detected: {cpu_percent}%")
                
                elif rule['target'] == 'memory':
                    # Check memory usage
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    
                    # Alert if memory usage exceeds threshold
                    if memory_percent > rule['threshold']:
                        alert = {
                            'type': 'resource_usage',
                            'timestamp': datetime.now().isoformat(),
                            'severity': rule['severity'],
                            'message': f"High memory usage detected: {memory_percent}%",
                            'details': {
                                'memory_percent': memory_percent,
                                'threshold': rule['threshold']
                            }
                        }
                        alerts.append(alert)
                        logger.warning(f"High memory usage detected: {memory_percent}%")
            except Exception as e:
                logger.error(f"Error checking resource usage: {e}")
    
    return alerts

def perform_breach_checks():
    """Perform all breach detection checks."""
    global breach_status
    
    alerts = []
    
    # Run all checks
    file_alerts = check_file_changes()
    process_alerts = check_suspicious_processes()
    network_alerts = check_network_anomalies()
    resource_alerts = check_resource_usage()
    
    # Combine all alerts
    alerts.extend(file_alerts)
    alerts.extend(process_alerts)
    alerts.extend(network_alerts)
    alerts.extend(resource_alerts)
    
    # Update breach status
    breach_status['last_check'] = datetime.now().isoformat()
    
    # Add new alerts to the status
    for alert in alerts:
        breach_status['alerts'].append(alert)
        
        # Limit alerts list to last 50
        if len(breach_status['alerts']) > 50:
            breach_status['alerts'] = breach_status['alerts'][-50:]
    
    # Update overall status
    if any(alert['severity'] == 'critical' for alert in alerts):
        breach_status['status'] = 'critical'
    elif any(alert['severity'] == 'high' for alert in alerts):
        breach_status['status'] = 'high'
    elif any(alert['severity'] == 'medium' for alert in alerts) and breach_status['status'] != 'high':
        breach_status['status'] = 'medium'
    elif alerts and breach_status['status'] not in ['critical', 'high', 'medium']:
        breach_status['status'] = 'low'
    
    # Log alerts to the database
    if alerts:
        log_breach_alerts(alerts)
    
    return breach_status

def log_breach_alerts(alerts):
    """Log breach alerts to the database."""
    try:
        from app import app, db
        from models import SecurityLog
        
        # Use application context
        with app.app_context():
            for alert in alerts:
                log = SecurityLog(
                    log_type='breach',
                    severity=alert['severity'],
                    source=alert['type'],
                    message=alert['message'],
                    details=json.dumps(alert)
                )
                db.session.add(log)
            
            db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log breach alerts: {e}")

def monitor_worker():
    """Worker function for the monitoring thread."""
    global monitoring_active
    
    logger.info("Breach monitoring thread started")
    
    while monitoring_active:
        try:
            # Perform breach checks
            perform_breach_checks()
            
            # Sleep for 60 seconds before next check
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in breach monitor worker: {e}")
            time.sleep(30)  # Sleep and retry on error
    
    logger.info("Breach monitoring thread stopped")

def start_breach_monitoring():
    """Start the breach monitoring system."""
    global monitoring_active, monitor_thread
    
    if monitoring_active:
        logger.warning("Breach monitoring is already active")
        return True
    
    try:
        # Load breach detection rules
        load_breach_rules()
        
        # Start monitoring thread
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_worker)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        logger.info("Breach monitoring started successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to start breach monitoring: {e}")
        monitoring_active = False
        return False

def stop_breach_monitoring():
    """Stop the breach monitoring system."""
    global monitoring_active
    
    if not monitoring_active:
        logger.warning("Breach monitoring is not active")
        return True
    
    monitoring_active = False
    logger.info("Breach monitoring stopped")
    return True

def get_breach_status():
    """Get the current breach monitoring status."""
    global breach_status
    
    # Refresh status if it's stale (older than 5 minutes)
    last_check = datetime.fromisoformat(breach_status['last_check'])
    if (datetime.now() - last_check).total_seconds() > 300:
        perform_breach_checks()
    
    return breach_status

def reset_breach_status():
    """Reset the breach status and clear alerts."""
    global breach_status
    
    breach_status = {
        'status': 'normal',
        'last_check': datetime.now().isoformat(),
        'alerts': []
    }
    
    logger.info("Breach status reset to normal")
    return breach_status

# Standalone execution for testing
if __name__ == "__main__":
    print("Initializing breach monitor in standalone mode...")
    load_breach_rules()
    
    print("Performing breach checks...")
    status = perform_breach_checks()
    
    print(f"Current status: {status['status']}")
    if status['alerts']:
        print(f"Found {len(status['alerts'])} alerts:")
        for alert in status['alerts']:
            print(f"  - {alert['severity']} - {alert['message']}")
    else:
        print("No security alerts detected")
