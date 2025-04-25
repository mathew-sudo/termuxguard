import os
import logging
import json
import threading
import time
from datetime import datetime
import ipaddress
from utils import get_termux_path

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
firewall_rules = []
firewall_enabled = True
firewall_lock = threading.Lock()
RULES_FILE = os.path.join(get_termux_path('data'), 'firewall_rules.json')

def load_rules_from_db():
    """Load firewall rules from the database."""
    try:
        from app import db
        from models import FirewallRule
        
        with firewall_lock:
            global firewall_rules
            rules_from_db = FirewallRule.query.filter_by(is_active=True).order_by(FirewallRule.priority).all()
            
            # Convert DB rules to dictionary format for internal use
            firewall_rules = [
                {
                    'id': rule.id,
                    'rule_type': rule.rule_type,
                    'target': rule.target,
                    'action': rule.action,
                    'priority': rule.priority,
                    'description': rule.description
                }
                for rule in rules_from_db
            ]
            
            # Save rules to file for fallback
            save_rules_to_file()
            
            logger.info(f"Loaded {len(firewall_rules)} rules from database")
            return firewall_rules
    except Exception as e:
        logger.error(f"Failed to load rules from database: {e}")
        # Fallback to file-based rules
        return load_rules_from_file()

def load_rules_from_file():
    """Load firewall rules from a file as fallback."""
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                global firewall_rules
                with firewall_lock:
                    firewall_rules = json.load(f)
                logger.info(f"Loaded {len(firewall_rules)} rules from file")
                return firewall_rules
        else:
            logger.warning("Rules file not found, using default rules")
            return create_default_rules()
    except Exception as e:
        logger.error(f"Failed to load rules from file: {e}")
        return create_default_rules()

def save_rules_to_file():
    """Save firewall rules to a file for persistence."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        
        with open(RULES_FILE, 'w') as f:
            json.dump(firewall_rules, f, indent=2)
        logger.debug("Rules saved to file")
    except Exception as e:
        logger.error(f"Failed to save rules to file: {e}")

def create_default_rules():
    """Create default firewall rules."""
    default_rules = [
        {
            'id': 1,
            'rule_type': 'ip',
            'target': '0.0.0.0/0',  # All IPs
            'action': 'allow',
            'priority': 100,  # Lowest priority (applied last)
            'description': 'Default allow rule'
        },
        {
            'id': 2,
            'rule_type': 'port',
            'target': '22',
            'action': 'log',
            'priority': 10,
            'description': 'Log SSH attempts'
        },
        {
            'id': 3,
            'rule_type': 'domain',
            'target': 'malicious.example.com',
            'action': 'block',
            'priority': 1,  # High priority
            'description': 'Block known malicious domain'
        }
    ]
    
    with firewall_lock:
        global firewall_rules
        firewall_rules = default_rules
        save_rules_to_file()
    
    logger.info("Created default firewall rules")
    return default_rules

def initialize_firewall():
    """Initialize the firewall system."""
    try:
        # Load firewall rules
        load_rules_from_db()
        
        # Create dedicated directory for firewall logs
        os.makedirs(os.path.join(get_termux_path('data'), 'logs'), exist_ok=True)
        
        global firewall_enabled
        firewall_enabled = True
        
        logger.info("Firewall initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize firewall: {e}")
        return False

def toggle_firewall_status(enabled=True):
    """Enable or disable the firewall."""
    global firewall_enabled
    firewall_enabled = enabled
    
    # Log the status change
    try:
        from app import db
        from models import SecurityLog
        
        log = SecurityLog(
            log_type='firewall',
            severity='info',
            source='system',
            message=f"Firewall {'enabled' if enabled else 'disabled'}",
            details=json.dumps({'timestamp': datetime.now().isoformat()})
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log firewall status change: {e}")
    
    return firewall_enabled

def apply_rule(rule):
    """Apply a new or updated firewall rule."""
    try:
        with firewall_lock:
            # Check if the rule already exists (update case)
            for i, existing_rule in enumerate(firewall_rules):
                if existing_rule['id'] == rule.id:
                    # Update the existing rule
                    firewall_rules[i] = {
                        'id': rule.id,
                        'rule_type': rule.rule_type,
                        'target': rule.target,
                        'action': rule.action,
                        'priority': rule.priority,
                        'description': rule.description
                    }
                    logger.info(f"Updated rule {rule.id}")
                    # Re-sort rules by priority
                    firewall_rules.sort(key=lambda x: x['priority'])
                    save_rules_to_file()
                    return True
            
            # If rule doesn't exist, add it
            firewall_rules.append({
                'id': rule.id,
                'rule_type': rule.rule_type,
                'target': rule.target,
                'action': rule.action,
                'priority': rule.priority,
                'description': rule.description
            })
            # Sort rules by priority
            firewall_rules.sort(key=lambda x: x['priority'])
            logger.info(f"Added new rule {rule.id}")
            save_rules_to_file()
            return True
    except Exception as e:
        logger.error(f"Failed to apply rule: {e}")
        return False

def remove_rule(rule_id):
    """Remove a firewall rule."""
    try:
        with firewall_lock:
            global firewall_rules
            # Filter out the rule with the given ID
            firewall_rules = [rule for rule in firewall_rules if rule['id'] != rule_id]
            save_rules_to_file()
            logger.info(f"Removed rule {rule_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to remove rule: {e}")
        return False

def check_packet_against_rules(packet_data):
    """Check a packet against the firewall rules and determine the action."""
    if not firewall_enabled:
        return 'allow'
    
    with firewall_lock:
        for rule in firewall_rules:
            # Skip inactive rules
            if not rule.get('is_active', True):
                continue
            
            # Match by rule type
            if rule['rule_type'] == 'ip':
                # Check if src_ip or dst_ip matches the IP rule
                if 'src_ip' in packet_data and match_ip(packet_data['src_ip'], rule['target']):
                    return rule['action']
                if 'dst_ip' in packet_data and match_ip(packet_data['dst_ip'], rule['target']):
                    return rule['action']
            
            elif rule['rule_type'] == 'port':
                # Check if src_port or dst_port matches the port rule
                if 'src_port' in packet_data and str(packet_data['src_port']) == rule['target']:
                    return rule['action']
                if 'dst_port' in packet_data and str(packet_data['dst_port']) == rule['target']:
                    return rule['action']
            
            elif rule['rule_type'] == 'domain' and 'dns_query' in packet_data:
                # Check if dns_query contains the domain
                if packet_data['dns_query'] and rule['target'] in packet_data['dns_query']:
                    return rule['action']
    
    # Default action if no rule matches
    return 'allow'

def match_ip(ip, target):
    """Check if an IP matches a target IP or CIDR range."""
    try:
        # Handle single IP match
        if '/' not in target:
            return ip == target
        
        # Handle CIDR range match
        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(target, strict=False)
        return ip_obj in network
    except Exception as e:
        logger.error(f"Error matching IP {ip} against {target}: {e}")
        return False

def get_firewall_status():
    """Get the current firewall status and statistics."""
    status = {
        'enabled': firewall_enabled,
        'rules_count': len(firewall_rules),
        'last_updated': datetime.now().isoformat()
    }
    return status

# Standalone execution for testing
if __name__ == "__main__":
    print("Initializing firewall in standalone mode...")
    initialize_firewall()
    
    # Test packet
    test_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'protocol': 'UDP',
        'src_port': 53212,
        'dst_port': 53,
        'dns_query': 'malicious.example.com'
    }
    
    action = check_packet_against_rules(test_packet)
    print(f"Action for test packet: {action}")
    
    # Print current rules
    print("Current firewall rules:")
    for rule in firewall_rules:
        print(f"  {rule['priority']}: {rule['rule_type']} {rule['target']} -> {rule['action']}")
