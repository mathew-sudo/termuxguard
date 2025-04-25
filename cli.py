import argparse
import sys
import os
import time
import json
from datetime import datetime
from utils import get_termux_path

def print_header():
    """Print the application header."""
    print("=" * 60)
    print("🔒 TERMUX FIREWALL & ANTI-MALWARE 🔒")
    print("=" * 60)
    print("A no-root security solution for Termux")
    print("=" * 60)

def print_status():
    """Print the current system status."""
    try:
        from network_monitor import get_network_status
        from firewall import get_firewall_status
        from breach_monitor import get_breach_status
        
        # Get status from all components
        network = get_network_status()
        firewall = get_firewall_status()
        breach = get_breach_status()
        
        print("\n📊 SYSTEM STATUS:")
        print(f"Firewall: {'ENABLED' if firewall['enabled'] else 'DISABLED'}")
        print(f"Active Rules: {firewall['rules_count']}")
        print(f"Packets Processed: {network['packets_total']}")
        print(f"Packets Blocked: {network['packets_blocked']}")
        print(f"Active Connections: {len(network['connections'])}")
        print(f"Security Status: {breach['status'].upper()}")
        
        # Show recent alerts if any
        if breach['alerts']:
            print("\n⚠️  RECENT ALERTS:")
            for alert in breach['alerts'][:5]:  # Show last 5 alerts
                print(f"  - [{alert['severity']}] {alert['message']}")
        
        print(f"\nLast Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to get system status: {e}")

def list_rules():
    """List all active firewall rules."""
    try:
        from app import db
        from models import FirewallRule
        
        rules = FirewallRule.query.filter_by(is_active=True).order_by(FirewallRule.priority).all()
        
        print("\n📜 ACTIVE FIREWALL RULES:")
        print("=" * 60)
        print(f"{'ID':<5} {'PRIORITY':<10} {'TYPE':<15} {'TARGET':<20} {'ACTION':<10}")
        print("-" * 60)
        
        for rule in rules:
            print(f"{rule.id:<5} {rule.priority:<10} {rule.rule_type:<15} {rule.target:<20} {rule.action:<10}")
        
        print("=" * 60)
        print(f"Total: {len(rules)} rules")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to list firewall rules: {e}")

def add_rule(args):
    """Add a new firewall rule."""
    try:
        from app import db
        from models import FirewallRule
        
        # Create a new rule
        rule = FirewallRule(
            rule_type=args.type,
            target=args.target,
            action=args.action,
            priority=args.priority,
            description=args.description or f"Rule for {args.target}"
        )
        
        db.session.add(rule)
        db.session.commit()
        
        # Apply the rule to the firewall
        from firewall import apply_rule
        apply_rule(rule)
        
        print(f"\n✅ Rule added successfully with ID: {rule.id}")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to add rule: {e}")

def delete_rule(args):
    """Delete a firewall rule."""
    try:
        from app import db
        from models import FirewallRule
        
        rule = FirewallRule.query.get(args.id)
        if not rule:
            print(f"\n❌ ERROR: Rule with ID {args.id} not found")
            return
        
        from firewall import remove_rule
        remove_rule(rule.id)
        
        db.session.delete(rule)
        db.session.commit()
        
        print(f"\n✅ Rule with ID {args.id} deleted successfully")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to delete rule: {e}")

def show_logs(args):
    """Show security logs."""
    try:
        from app import db
        from models import SecurityLog
        
        # Parse log type filter
        log_type = args.type.lower() if args.type else None
        severity = args.severity.lower() if args.severity else None
        limit = args.limit or 20
        
        # Build query
        query = SecurityLog.query
        
        if log_type:
            query = query.filter(SecurityLog.log_type == log_type)
        
        if severity:
            query = query.filter(SecurityLog.severity == severity)
        
        # Get logs
        logs = query.order_by(SecurityLog.timestamp.desc()).limit(limit).all()
        
        print(f"\n📋 SECURITY LOGS (Last {limit}):")
        print("=" * 80)
        print(f"{'TIMESTAMP':<25} {'TYPE':<10} {'SEVERITY':<10} {'MESSAGE':<35}")
        print("-" * 80)
        
        for log in logs:
            timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            message = log.message[:35] + "..." if len(log.message) > 35 else log.message
            print(f"{timestamp:<25} {log.log_type:<10} {log.severity:<10} {message:<35}")
        
        print("=" * 80)
        print(f"Total: {len(logs)} logs displayed")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to show logs: {e}")

def run_scan(args):
    """Run a malware scan."""
    try:
        from malware_scanner import perform_scan
        
        # Set default parameters
        scan_type = 'full'
        scan_path = None
        scan_depth = 3
        thorough_scan = False
        auto_quarantine = False
        
        # Parse command line arguments if provided
        if args and hasattr(args, 'scan_type'):
            scan_type = args.scan_type
            
        if args and hasattr(args, 'path'):
            scan_path = args.path
            
        if args and hasattr(args, 'depth'):
            scan_depth = args.depth
            
        if args and hasattr(args, 'thorough') and args.thorough:
            thorough_scan = True
            
        if args and hasattr(args, 'quarantine') and args.quarantine:
            auto_quarantine = True
        
        print(f"\n🔍 Starting {scan_type} malware scan...")
        if thorough_scan:
            print("Using thorough scan mode (this will take longer but provide better detection).")
        if auto_quarantine:
            print("Auto-quarantine is enabled for detected threats.")
        print("This may take some time depending on the number of files.")
        
        # Start the scan with options
        result = perform_scan(
            scan_type=scan_type,
            scan_path=scan_path,
            scan_depth=scan_depth,
            thorough_scan=thorough_scan,
            auto_quarantine=auto_quarantine
        )
        
        print(f"\n✅ Scan completed!")
        print(f"Scan type: {result.get('scan_type', 'full')}")
        print(f"Files scanned: {result['files_scanned']}")
        print(f"Threats found: {result['threats_found']}")
        print(f"Threats quarantined: {result.get('quarantined', 0)}")
        print(f"Duration: {result['duration_seconds']} seconds")
        
        # If threats were found, show details
        if result['threats_found'] > 0:
            print("\n⚠️  DETECTED THREATS:")
            
            # Load scan results from file
            result_file = os.path.join(get_termux_path('data'), 'scan_results', f"scan_{result['scan_id']}.json")
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    scan_data = json.load(f)
                    
                    for threat in scan_data.get('threats', []):
                        print(f"  - {threat.get('threat_name', 'Unknown threat')}")
                        print(f"    File: {threat.get('file_path', 'Unknown location')}")
                        print(f"    Type: {threat.get('threat_type', 'Unknown')}")
                        print(f"    Severity: {threat.get('severity', 'medium')}")
                        print(f"    Detection: {threat.get('detection_method', 'Unknown')}")
                        
                        if auto_quarantine and threat.get('action_taken') == 'quarantined':
                            print(f"    Action: Quarantined")
                        else:
                            print(f"    Action: {threat.get('action_taken', 'Detected')}")
                        print()
        
        # If auto-quarantine was enabled, show summary
        if auto_quarantine and result.get('quarantined', 0) > 0:
            print(f"\n🔒 {result.get('quarantined', 0)} threats have been quarantined.")
            print("Use the 'quarantine' command to manage quarantined files.")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to run scan: {e}")

def toggle_firewall(args):
    """Enable or disable the firewall."""
    try:
        from firewall import toggle_firewall_status
        
        # Enable or disable based on command
        if args.command == 'enable':
            enabled = True
        else:
            enabled = False
        
        # Toggle the firewall
        status = toggle_firewall_status(enabled)
        
        print(f"\n✅ Firewall {'enabled' if status else 'disabled'} successfully")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to toggle firewall: {e}")

def show_quarantine(args):
    """List and manage quarantined files."""
    try:
        from app import db
        from models import MalwareThreat
        from malware_scanner import restore_from_quarantine
        
        # Check if we need to restore a file
        if args and hasattr(args, 'restore') and args.restore:
            # Restore the file
            threat = MalwareThreat.query.get(args.restore)
            if not threat or threat.action_taken != 'quarantined' or not threat.can_restore:
                print(f"\n❌ ERROR: Threat with ID {args.restore} not found or cannot be restored")
                return
                
            print(f"\n⚠️  WARNING: You are about to restore a quarantined malware file:")
            print(f"  - {threat.threat_name}")
            print(f"  - Location: {threat.file_path}")
            print(f"  - Severity: {threat.severity}")
            
            confirm = input("\nAre you sure you want to restore this file? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Restoration cancelled.")
                return
                
            result = restore_from_quarantine(threat.quarantine_path)
            if result:
                # Update the threat record
                threat.action_taken = 'restored'
                threat.can_restore = False
                db.session.commit()
                
                print(f"\n✅ File restored successfully to: {threat.file_path}")
            else:
                print(f"\n❌ ERROR: Failed to restore file")
            return
            
        # List all quarantined files
        quarantined = MalwareThreat.query.filter_by(
            action_taken='quarantined',
            can_restore=True
        ).order_by(MalwareThreat.timestamp.desc()).all()
        
        if not quarantined:
            print("\n✅ No files are currently in quarantine")
            return
            
        print(f"\n🔒 QUARANTINED FILES ({len(quarantined)}):")
        print("=" * 80)
        print(f"{'ID':<5} {'TIMESTAMP':<20} {'THREAT':<25} {'SEVERITY':<10} {'FILE':<20}")
        print("-" * 80)
        
        for item in quarantined:
            timestamp = item.timestamp.strftime('%Y-%m-%d %H:%M:%S') if item.timestamp else 'Unknown'
            file_name = os.path.basename(item.file_path)[:20]
            threat_name = item.threat_name[:25] if item.threat_name else 'Unknown'
            print(f"{item.id:<5} {timestamp:<20} {threat_name:<25} {item.severity:<10} {file_name:<20}")
            
        print("=" * 80)
        print("To restore a file, use: quarantine --restore ID")
        print("⚠️  WARNING: Only restore files if you are absolutely sure they are safe!")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to list quarantined files: {e}")

def show_help():
    """Show the help menu."""
    print("\n📚 AVAILABLE COMMANDS:")
    print("  status      - Show system status")
    print("  rules       - List all firewall rules")
    print("  add-rule    - Add a new firewall rule")
    print("  delete-rule - Delete a firewall rule")
    print("  logs        - Show security logs")
    print("  scan        - Run a malware scan")
    print("  quarantine  - Manage quarantined files")
    print("  enable      - Enable the firewall")
    print("  disable     - Disable the firewall")
    print("  help        - Show this help menu")
    print("  exit        - Exit the CLI")
    print("\nType 'command --help' for more information on a command")

def interactive_mode():
    """Run the CLI in interactive mode."""
    print_header()
    print_status()
    print("\nType 'help' to see available commands, 'exit' to quit.")
    
    while True:
        try:
            cmd = input("\n> ").strip()
            
            if not cmd:
                continue
            
            if cmd.lower() == 'exit':
                print("Exiting CLI. Firewall and protection will continue running in the background.")
                break
            
            if cmd.lower() == 'help':
                show_help()
                continue
            
            # Parse the command
            args = cmd.split()
            command = args[0].lower()
            
            if command == 'status':
                print_status()
            elif command == 'rules':
                list_rules()
            elif command == 'add-rule':
                parser = argparse.ArgumentParser(description='Add a firewall rule')
                parser.add_argument('--type', required=True, choices=['ip', 'port', 'domain'], help='Rule type')
                parser.add_argument('--target', required=True, help='Target (IP, port, or domain)')
                parser.add_argument('--action', required=True, choices=['block', 'allow', 'log'], help='Action to take')
                parser.add_argument('--priority', type=int, default=5, help='Rule priority (1-10, lower is higher)')
                parser.add_argument('--description', help='Rule description')
                
                try:
                    args = parser.parse_args(args[1:])
                    add_rule(args)
                except SystemExit:
                    # Ignore the system exit from argparse
                    continue
            elif command == 'delete-rule':
                parser = argparse.ArgumentParser(description='Delete a firewall rule')
                parser.add_argument('id', type=int, help='Rule ID to delete')
                
                try:
                    args = parser.parse_args(args[1:])
                    delete_rule(args)
                except SystemExit:
                    continue
            elif command == 'logs':
                parser = argparse.ArgumentParser(description='Show security logs')
                parser.add_argument('--type', choices=['firewall', 'malware', 'breach', 'system'], help='Log type filter')
                parser.add_argument('--severity', choices=['info', 'warning', 'error', 'critical'], help='Severity filter')
                parser.add_argument('--limit', type=int, default=20, help='Maximum number of logs to show')
                
                try:
                    args = parser.parse_args(args[1:])
                    show_logs(args)
                except SystemExit:
                    continue
            elif command == 'scan':
                parser = argparse.ArgumentParser(description='Run a malware scan')
                parser.add_argument('--type', dest='scan_type', choices=['full', 'quick', 'targeted'], default='full')
                parser.add_argument('--path', help='Custom path to scan')
                parser.add_argument('--depth', type=int, default=3)
                parser.add_argument('--thorough', action='store_true')
                parser.add_argument('--quarantine', action='store_true')
                
                try:
                    args = parser.parse_args(args[1:])
                    run_scan(args)
                except SystemExit:
                    run_scan(None)  # Run with default options if parsing fails
            elif command == 'quarantine':
                parser = argparse.ArgumentParser(description='Manage quarantined files')
                parser.add_argument('--restore', type=int, help='ID of the threat to restore')
                
                try:
                    args = parser.parse_args(args[1:])
                    show_quarantine(args)
                except SystemExit:
                    show_quarantine(None)  # Run with default options if parsing fails
            elif command in ['enable', 'disable']:
                parser = argparse.ArgumentParser(description='Toggle firewall')
                parser.add_argument('command', help='Command')
                
                args = parser.parse_args([command])
                toggle_firewall(args)
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' to see available commands")
        except KeyboardInterrupt:
            print("\nExiting CLI. Firewall and protection will continue running in the background.")
            break
        except Exception as e:
            print(f"Error: {e}")

def start_cli():
    """Start the command-line interface."""
    parser = argparse.ArgumentParser(description='Termux Firewall & Anti-Malware CLI')
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Status command
    subparsers.add_parser('status', help='Show system status')
    
    # Rules command
    subparsers.add_parser('rules', help='List firewall rules')
    
    # Add rule command
    add_parser = subparsers.add_parser('add-rule', help='Add a firewall rule')
    add_parser.add_argument('--type', required=True, choices=['ip', 'port', 'domain'], help='Rule type')
    add_parser.add_argument('--target', required=True, help='Target (IP, port, or domain)')
    add_parser.add_argument('--action', required=True, choices=['block', 'allow', 'log'], help='Action to take')
    add_parser.add_argument('--priority', type=int, default=5, help='Rule priority (1-10, lower is higher)')
    add_parser.add_argument('--description', help='Rule description')
    
    # Delete rule command
    delete_parser = subparsers.add_parser('delete-rule', help='Delete a firewall rule')
    delete_parser.add_argument('id', type=int, help='Rule ID to delete')
    
    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Show security logs')
    logs_parser.add_argument('--type', choices=['firewall', 'malware', 'breach', 'system'], help='Log type filter')
    logs_parser.add_argument('--severity', choices=['info', 'warning', 'error', 'critical'], help='Severity filter')
    logs_parser.add_argument('--limit', type=int, default=20, help='Maximum number of logs to show')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a malware scan')
    scan_parser.add_argument('--type', dest='scan_type', choices=['full', 'quick', 'targeted'], default='full', 
                           help='Type of scan (full, quick, or targeted)')
    scan_parser.add_argument('--path', help='Custom path to scan (required for targeted scans)')
    scan_parser.add_argument('--depth', type=int, default=3, 
                           help='How many directory levels deep to scan for quick scans (default: 3)')
    scan_parser.add_argument('--thorough', action='store_true', 
                           help='Perform thorough scanning (more CPU intensive but better detection)')
    scan_parser.add_argument('--quarantine', action='store_true', 
                           help='Automatically quarantine detected threats')
    
    # Quarantine command
    quarantine_parser = subparsers.add_parser('quarantine', help='Manage quarantined files')
    quarantine_parser.add_argument('--restore', type=int, help='ID of the threat to restore')
    
    # Enable/disable commands
    subparsers.add_parser('enable', help='Enable the firewall')
    subparsers.add_parser('disable', help='Disable the firewall')
    
    # Interactive mode
    subparsers.add_parser('interactive', help='Run in interactive mode')
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no command specified or interactive mode requested, run in interactive mode
    if not args.command or args.command == 'interactive':
        interactive_mode()
        return
    
    # Run the specified command
    if args.command == 'status':
        print_header()
        print_status()
    elif args.command == 'rules':
        list_rules()
    elif args.command == 'add-rule':
        add_rule(args)
    elif args.command == 'delete-rule':
        delete_rule(args)
    elif args.command == 'logs':
        show_logs(args)
    elif args.command == 'scan':
        run_scan(args)
    elif args.command == 'quarantine':
        show_quarantine(args)
    elif args.command in ['enable', 'disable']:
        toggle_firewall(args)

if __name__ == '__main__':
    start_cli()
