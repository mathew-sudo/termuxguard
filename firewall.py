import os
import subprocess
import logging
import ipaddress
import re
import time
from datetime import datetime

from app import db
from models import FirewallRule, SecurityLog
import config

# Setup logger
logger = logging.getLogger(__name__)

def is_root():
    """Check if the script is running with root privileges."""
    return os.geteuid() == 0

def execute_command(command):
    """Execute a shell command and return the output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command execution failed: {e.stderr}")
        return None

def is_iptables_available():
    """Check if iptables is available on the system."""
    result = execute_command("which iptables")
    return bool(result)

def is_valid_ip(ip):
    """Validate if the string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    """Validate if the port number is valid."""
    try:
        port = int(port)
        return 0 < port < 65536
    except (ValueError, TypeError):
        return False

def init_firewall():
    """Initialize the firewall with default settings."""
    if not is_iptables_available():
        logger.error("iptables is not available. Firewall cannot be initialized.")
        return False

    try:
        # Flush existing rules
        execute_command("iptables -F")
        execute_command("iptables -X")
        
        # Set default policies
        execute_command("iptables -P INPUT ACCEPT")
        execute_command("iptables -P FORWARD ACCEPT")
        execute_command("iptables -P OUTPUT ACCEPT")
        
        # Allow established connections
        execute_command("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        
        # Allow localhost
        execute_command("iptables -A INPUT -i lo -j ACCEPT")
        
        # Apply rules from database
        update_firewall_rules()
        
        # Log initialization
        log_entry = SecurityLog(
            event_type="FIREWALL_INIT",
            description="Firewall initialized successfully",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info("Firewall initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize firewall: {str(e)}")
        return False

def update_firewall_rules():
    """Apply firewall rules from the database."""
    if not is_iptables_available():
        logger.error("iptables is not available. Cannot update firewall rules.")
        return False
        
    try:
        # Get all enabled rules from database
        rules = FirewallRule.query.filter_by(enabled=True).all()
        
        # Clear existing custom rules (keep the basic ones)
        execute_command("iptables -F INPUT")
        execute_command("iptables -F OUTPUT")
        
        # Allow established connections
        execute_command("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        
        # Allow localhost
        execute_command("iptables -A INPUT -i lo -j ACCEPT")
        
        # Apply each rule
        for rule in rules:
            rule_cmd = build_iptables_rule(rule)
            if rule_cmd:
                execute_command(rule_cmd)
                
        # Set default policy based on configuration
        default_action = "ACCEPT" if config.DEFAULT_FIREWALL_ACTION == "ALLOW" else "DROP"
        execute_command(f"iptables -A INPUT -j {default_action}")
        
        logger.info(f"Applied {len(rules)} firewall rules")
        return True
    except Exception as e:
        logger.error(f"Failed to update firewall rules: {str(e)}")
        return False

def build_iptables_rule(rule):
    """Build an iptables command from a rule object."""
    try:
        # Validate rule
        if rule.protocol not in ["tcp", "udp", "icmp", "all"]:
            logger.warning(f"Invalid protocol in rule {rule.id}: {rule.protocol}")
            return None
            
        # Build basic command
        cmd = f"iptables -A INPUT"
        
        # Add protocol
        if rule.protocol != "all":
            cmd += f" -p {rule.protocol}"
            
        # Add source IP if specified
        if rule.source_ip and is_valid_ip(rule.source_ip):
            cmd += f" -s {rule.source_ip}"
            
        # Add destination IP if specified
        if rule.destination_ip and is_valid_ip(rule.destination_ip):
            cmd += f" -d {rule.destination_ip}"
            
        # Add port if specified and protocol is tcp/udp
        if rule.port and is_valid_port(rule.port) and rule.protocol in ["tcp", "udp"]:
            cmd += f" --dport {rule.port}"
            
        # Add action
        action = "ACCEPT" if rule.action == "ALLOW" else "DROP"
        cmd += f" -j {action}"
        
        # Add logging if enabled
        if config.FIREWALL_LOG_BLOCKED and action == "DROP":
            log_cmd = cmd.replace(f" -j {action}", f" -j LOG --log-prefix \"[TERMUX-FIREWALL-BLOCKED] \"")
            return [log_cmd, cmd]
            
        return cmd
    except Exception as e:
        logger.error(f"Failed to build iptables rule: {str(e)}")
        return None

def get_active_connections():
    """Get list of active network connections."""
    try:
        netstat_output = execute_command("netstat -tuln")
        connections = []
        
        if netstat_output:
            # Parse netstat output
            lines = netstat_output.split('\n')
            for line in lines[2:]:  # Skip header lines
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 5:
                    proto = parts[0]
                    local_address = parts[3]
                    state = parts[5] if len(parts) > 5 else "UNKNOWN"
                    
                    connections.append({
                        "protocol": proto,
                        "local_address": local_address,
                        "state": state
                    })
        
        return connections
    except Exception as e:
        logger.error(f"Failed to get active connections: {str(e)}")
        return []

def add_temporary_block(ip, duration=300):
    """Temporarily block an IP address for specified duration (in seconds)."""
    if not is_valid_ip(ip):
        logger.error(f"Invalid IP address: {ip}")
        return False
        
    try:
        # Add rule to block the IP
        execute_command(f"iptables -I INPUT -s {ip} -j DROP")
        
        # Log the block
        log_entry = SecurityLog(
            event_type="TEMP_IP_BLOCK",
            description=f"Temporarily blocked IP {ip} for {duration} seconds",
            severity="MEDIUM",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Schedule rule removal
        def remove_block():
            time.sleep(duration)
            execute_command(f"iptables -D INPUT -s {ip} -j DROP")
            
            # Log the unblock
            log_entry = SecurityLog(
                event_type="TEMP_IP_UNBLOCK",
                description=f"Temporary block expired for IP {ip}",
                severity="INFO",
                timestamp=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()
            
        # Start thread to remove the block after duration
        import threading
        unblock_thread = threading.Thread(target=remove_block)
        unblock_thread.daemon = True
        unblock_thread.start()
        
        logger.info(f"Added temporary block for IP {ip} for {duration} seconds")
        return True
    except Exception as e:
        logger.error(f"Failed to add temporary block: {str(e)}")
        return False
