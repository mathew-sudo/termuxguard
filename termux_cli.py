#!/usr/bin/env python3
"""
Termux AntiMalware - Command Line Interface
This module provides a command-line interface for the Termux AntiMalware application.
"""
import os
import sys
import argparse
import time
from datetime import datetime

# Set up paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.append(BASE_DIR)

# ANSI color codes
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'reset': '\033[0m',
    'bold': '\033[1m'
}

def print_header():
    """Print the application header"""
    print(f"{COLORS['blue']}")
    print(" ████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗")
    print(" ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║╚██╗██╔╝")
    print("    ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║ ╚███╔╝ ")
    print("    ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║ ██╔██╗ ")
    print("    ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗")
    print("    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝")
    print(f"{COLORS['red']} ███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗   ")
    print(" ████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝   ")
    print(" ██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗     ")
    print(" ██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝     ")
    print(" ██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗   ")
    print(" ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ")
    print(f"{COLORS['green']}                      GUARD™                                   ")
    print(f"{COLORS['reset']}")
    print(f"{COLORS['yellow']}Security made for Termux{COLORS['reset']}")
    print()

def perform_scan(directory, recursive=True):
    """Perform a security scan on a directory"""
    from app import app
    from utils.scanner import scan_directory
    
    start_time = time.time()
    print(f"{COLORS['yellow']}Scanning directory: {directory}{COLORS['reset']}")
    print("Please wait, this may take some time...")
    
    with app.app_context():
        try:
            results = scan_directory(directory, recursive=recursive)
            
            # Print results
            print(f"\n{'-' * 70}")
            print(f"{COLORS['green']}Scan completed in {time.time() - start_time:.2f} seconds{COLORS['reset']}")
            print(f"{COLORS['cyan']}Directory: {COLORS['white']}{results['directory']}")
            print(f"{COLORS['cyan']}Total files: {COLORS['white']}{results['total_files']}")
            print(f"{COLORS['cyan']}Files scanned: {COLORS['white']}{results['scanned_files']}")
            print(f"{COLORS['cyan']}Threats found: {COLORS['white']}{len(results['threats'])}")
            print(f"{'-' * 70}")
            
            if results['threats']:
                print(f"\n{COLORS['red']}{COLORS['bold']}THREATS DETECTED:{COLORS['reset']}")
                for i, threat in enumerate(results['threats'], 1):
                    severity_color = COLORS['red'] if threat['severity'] == 'HIGH' else (
                        COLORS['yellow'] if threat['severity'] == 'MEDIUM' else COLORS['green']
                    )
                    
                    print(f"\n{COLORS['white']}{i}. {COLORS['reset']}File: {COLORS['cyan']}{threat['file_path']}{COLORS['reset']}")
                    print(f"   Type: {COLORS['yellow']}{threat['type']}{COLORS['reset']}")
                    print(f"   Severity: {severity_color}{threat['severity']}{COLORS['reset']}")
                    print(f"   Details: {COLORS['white']}{threat['details']}{COLORS['reset']}")
            else:
                print(f"\n{COLORS['green']}No threats found.{COLORS['reset']}")
                
            print(f"\n{'-' * 70}")
        except Exception as e:
            print(f"{COLORS['red']}Error during scan: {str(e)}{COLORS['reset']}")
            return False
            
    return True

def show_security_status():
    """Display current security status and logs"""
    from app import app
    import config
    from models import SecurityLog, FirewallRule, ContentFilter, ScanResult
    
    print(f"{COLORS['blue']}Termux AntiMalware Security Status{COLORS['reset']}")
    
    with app.app_context():
        # Current settings
        firewall_status = f"{COLORS['green']}Enabled{COLORS['reset']}" if config.FIREWALL_ENABLED else f"{COLORS['red']}Disabled{COLORS['reset']}"
        filter_status = f"{COLORS['green']}Enabled{COLORS['reset']}" if config.CONTENT_FILTER_ENABLED else f"{COLORS['red']}Disabled{COLORS['reset']}"
        ai_status = f"{COLORS['green']}Enabled{COLORS['reset']}" if config.AI_DETECTION_ENABLED else f"{COLORS['red']}Disabled{COLORS['reset']}"
        
        # Count active rules and filters
        firewall_count = FirewallRule.query.filter_by(enabled=True).count()
        filter_count = ContentFilter.query.filter_by(enabled=True).count()
        
        # Get scan stats
        scan_count = ScanResult.query.count()
        threat_count = ScanResult.query.with_entities(ScanResult.threats_found).all()
        total_threats = sum([t[0] for t in threat_count]) if threat_count else 0
        
        # Security token
        security_token = app.config.get('SECURITY_TOKEN', 'Not initialized')
        if security_token != 'Not initialized':
            security_token = security_token[:6] + '...'
            
        # Last 5 security logs
        logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(5).all()
        
        # Print results
        print(f"\n{'-' * 70}")
        print(f"{COLORS['cyan']}Security Status:{COLORS['reset']}")
        print(f"  Firewall: {firewall_status} ({firewall_count} active rules)")
        print(f"  Content Filter: {filter_status} ({filter_count} active filters)")
        print(f"  AI Protection: {ai_status}")
        print(f"  Security Token: {COLORS['yellow']}{security_token}{COLORS['reset']} (changes every 20 seconds)")
        
        print(f"\n{COLORS['cyan']}Scan Statistics:{COLORS['reset']}")
        print(f"  Total Scans Performed: {scan_count}")
        print(f"  Total Threats Detected: {total_threats}")
        
        print(f"\n{COLORS['cyan']}Recent Security Events:{COLORS['reset']}")
        if logs:
            for i, log in enumerate(logs, 1):
                severity_color = COLORS['red'] if log.severity == 'HIGH' else (
                    COLORS['yellow'] if log.severity == 'MEDIUM' else COLORS['green']
                )
                print(f"{i}. [{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {COLORS['yellow']}{log.event_type}{COLORS['reset']}")
                print(f"   Severity: {severity_color}{log.severity}{COLORS['reset']}")
                print(f"   {log.description}")
                if i < len(logs):
                    print()
        else:
            print(f"  No recent security events.")
            
        print(f"\n{'-' * 70}")
        
def enable_feature(feature_name, value=True):
    """Enable or disable a specific feature"""
    from app import app
    import config
    from utils.firewall import update_firewall_rules
    from utils.content_filter import update_content_filters
    from utils.security_utils import log_security_event
    
    with app.app_context():
        feature_map = {
            'firewall': {'attr': 'FIREWALL_ENABLED', 'update_func': update_firewall_rules},
            'filter': {'attr': 'CONTENT_FILTER_ENABLED', 'update_func': update_content_filters},
            'ai': {'attr': 'AI_DETECTION_ENABLED', 'update_func': None},
            'background': {'attr': 'BACKGROUND_SERVICE_ENABLED', 'update_func': None}
        }
        
        if feature_name in feature_map:
            feature = feature_map[feature_name]
            setattr(config, feature['attr'], value)
            
            status = "enabled" if value else "disabled"
            print(f"{COLORS['green'] if value else COLORS['yellow']}{feature_name.title()} {status}.{COLORS['reset']}")
            
            # Update if needed
            if feature['update_func'] and value:
                feature['update_func']()
                
            # Log change
            log_security_event(
                "FEATURE_CHANGE", 
                f"{feature_name.title()} {status} via CLI", 
                "INFO"
            )
            return True
        else:
            print(f"{COLORS['red']}Unknown feature: {feature_name}{COLORS['reset']}")
            print(f"Available features: firewall, filter, ai, background")
            return False

def main():
    """Main command-line interface entry point"""
    parser = argparse.ArgumentParser(description="Termux AntiMalware Command Line Interface")
    
    # Define subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for threats")
    scan_parser.add_argument("directory", nargs="?", default="/data/data/com.termux/files", 
                            help="Directory to scan (default: Termux files directory)")
    scan_parser.add_argument("--quick", action="store_true", help="Perform a non-recursive quick scan")
    
    # Status command
    subparsers.add_parser("status", help="Show security status")
    
    # Enable/disable commands
    enable_parser = subparsers.add_parser("enable", help="Enable a security feature")
    enable_parser.add_argument("feature", choices=["firewall", "filter", "ai", "background"], 
                              help="Feature to enable")
    
    disable_parser = subparsers.add_parser("disable", help="Disable a security feature")
    disable_parser.add_argument("feature", choices=["firewall", "filter", "ai", "background"], 
                               help="Feature to disable")
    
    # Version command
    subparsers.add_parser("version", help="Show version information")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print header for all commands
    print_header()
    
    # Process commands
    if args.command == "scan":
        perform_scan(args.directory, not args.quick)
    elif args.command == "status":
        show_security_status()
    elif args.command == "enable":
        enable_feature(args.feature, True)
    elif args.command == "disable":
        enable_feature(args.feature, False)
    elif args.command == "version":
        from app import app
        version = app.config.get('APP_VERSION', '1.0.0')
        print(f"Termux AntiMalware version {version}")
        print(f"© 2025 Termux Security Project")
    else:
        # No command or invalid command - show help
        parser.print_help()
    
if __name__ == "__main__":
    main()
