import os
import re
import logging
import hashlib
import magic
import subprocess
import threading
from datetime import datetime
import glob

from app import db
from models import SecurityLog, ThreatSignature
from utils.security_utils import calculate_file_entropy, check_file_hash
from utils.ai_detection import predict_threat
import config

# Setup logger
logger = logging.getLogger(__name__)

# Global threat database
THREAT_SIGNATURES = {}

def load_threat_signatures():
    """Load threat signatures from database"""
    global THREAT_SIGNATURES
    try:
        signatures = ThreatSignature.query.all()
        for sig in signatures:
            THREAT_SIGNATURES[sig.name] = {
                'pattern': sig.pattern,
                'severity': sig.severity,
                'description': sig.description
            }
        logger.info(f"Loaded {len(THREAT_SIGNATURES)} threat signatures")
    except Exception as e:
        logger.error(f"Failed to load threat signatures: {str(e)}")

def is_clamav_available():
    """Check if ClamAV is available on the system"""
    try:
        result = subprocess.run(
            ["which", "clamscan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def get_file_mime_type(file_path):
    """Get the MIME type of a file"""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except:
        # Fallback to a simpler extension check if python-magic is not available
        _, ext = os.path.splitext(file_path)
        if ext:
            ext = ext.lower()[1:]  # Remove the dot
            if ext in ['jpg', 'jpeg', 'png', 'gif']:
                return f"image/{ext}"
            elif ext in ['mp3', 'wav']:
                return f"audio/{ext}"
            elif ext in ['mp4', 'avi', 'mov']:
                return f"video/{ext}"
            elif ext in ['txt', 'md']:
                return "text/plain"
            elif ext in ['html', 'htm']:
                return "text/html"
            elif ext in ['exe', 'dll']:
                return "application/x-dosexec"
            elif ext == 'apk':
                return "application/vnd.android.package-archive"
        return "application/octet-stream"

def is_excluded_directory(directory):
    """Check if a directory should be excluded from scanning"""
    for excluded_dir in config.SCAN_EXCLUDED_DIRS:
        if directory.startswith(excluded_dir):
            return True
    return False

def scan_file(file_path):
    """Scan a single file for threats"""
    result = {
        'file_path': file_path,
        'threats': [],
        'scan_time': datetime.now()
    }
    
    # Skip if file doesn't exist or is too large
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return result
        
    file_size = os.path.getsize(file_path)
    if file_size > config.SCAN_MAX_FILE_SIZE:
        logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
        return result
    
    try:
        # Get file information
        file_mime = get_file_mime_type(file_path)
        file_extension = os.path.splitext(file_path)[1].lower()[1:]
        
        # Check if file type is in risky list
        if file_extension in config.RISKY_FILE_TYPES or file_mime in config.RISKY_MIME_TYPES:
            result['threats'].append({
                'type': 'RISKY_FILE_TYPE',
                'details': f"Risky file type: {file_extension} ({file_mime})",
                'severity': 'MEDIUM'
            })
        
        # Scan with pattern matching
        scan_with_patterns(file_path, result)
        
        # Scan with ClamAV if available
        if is_clamav_available():
            scan_with_clamav(file_path, result)
            
        # Use AI detection if enabled
        if config.AI_DETECTION_ENABLED:
            ai_result = predict_threat(file_path)
            if ai_result['is_threat']:
                result['threats'].append({
                    'type': 'AI_DETECTED',
                    'details': f"AI detection: {ai_result['confidence']:.2f}% confidence",
                    'severity': 'HIGH' if ai_result['confidence'] > 90 else 'MEDIUM'
                })
                
        # Log high severity threats
        if result['threats']:
            for threat in result['threats']:
                if threat['severity'] == 'HIGH':
                    log_entry = SecurityLog(
                        event_type="THREAT_DETECTED",
                        description=f"High severity threat in {file_path}: {threat['details']}",
                        severity="HIGH",
                        timestamp=datetime.now()
                    )
                    db.session.add(log_entry)
            db.session.commit()
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
    
    return result

def scan_with_patterns(file_path, result):
    """Scan a file with pattern matching"""
    try:
        # Only read the first few KB for text scanning
        with open(file_path, 'rb') as f:
            content = f.read(50000)  # Read first 50KB
            
        # Try to decode as text
        try:
            text_content = content.decode('utf-8', errors='ignore')
            
            # Check against threat signatures
            for name, sig in THREAT_SIGNATURES.items():
                pattern = sig['pattern']
                if re.search(pattern, text_content, re.IGNORECASE):
                    result['threats'].append({
                        'type': 'SIGNATURE_MATCH',
                        'details': f"Matched signature: {name}",
                        'severity': sig['severity']
                    })
                    
            # Check for common malicious patterns
            malicious_patterns = [
                (r'eval\s*\(\s*base64_decode', 'PHP base64 code execution'),
                (r'system\s*\(\s*[\'"][^\']*rm\s', 'Command to remove files'),
                (r'<script[^>]*>[^<]*alert\s*\(', 'Potential XSS attack'),
                (r'wget\s+.+\s*\|\s*bash', 'Shell script download and execution')
            ]
            
            for pattern, description in malicious_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    result['threats'].append({
                        'type': 'MALICIOUS_PATTERN',
                        'details': f"Malicious pattern: {description}",
                        'severity': 'HIGH'
                    })
                    
        except UnicodeDecodeError:
            # Not a text file, check entropy for potential encryption
            entropy = calculate_file_entropy(file_path)
            if entropy > 7.8:  # Very high entropy suggests encryption or compression
                result['threats'].append({
                    'type': 'HIGH_ENTROPY',
                    'details': f"High entropy file: {entropy:.2f}/8.0",
                    'severity': 'MEDIUM'
                })
                
    except Exception as e:
        logger.error(f"Error in pattern scanning for {file_path}: {str(e)}")

def scan_with_clamav(file_path, result):
    """Scan a file with ClamAV"""
    try:
        clamscan_process = subprocess.run(
            ["clamscan", "--no-summary", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # ClamAV returns 1 if virus found, 0 if no virus
        if clamscan_process.returncode == 1:
            output = clamscan_process.stdout
            # Parse ClamAV output to extract virus name
            virus_match = re.search(r': ([^:]+) FOUND', output)
            virus_name = virus_match.group(1) if virus_match else "Unknown virus"
            
            result['threats'].append({
                'type': 'CLAMAV_DETECTED',
                'details': f"ClamAV detected: {virus_name}",
                'severity': 'HIGH'
            })
    except Exception as e:
        logger.error(f"Error in ClamAV scanning for {file_path}: {str(e)}")

def scan_directory(directory, recursive=True):
    """Scan a directory for threats"""
    # Demo implementation for testing
    import os
    import time
    import random
    from datetime import datetime
    from app import db
    from models import SecurityLog
    
    # Simulate scanning process
    time.sleep(1)  # Simulate processing time
    
    # Prepare result structure
    results = {
        'directory': directory,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_files': 0,
        'scanned_files': 0,
        'threats': []
    }
    
    # Check if directory exists
    if not os.path.exists(directory):
        return results
    
    # Check for excluded directory
    if is_excluded_directory(directory):
        logger.info(f"Skipping excluded directory: {directory}")
        return results
    
    # Count files
    file_count = 0
    scanned_files = 0
    threat_count = 0
    
    try:
        # Walk through directory
        for root, _, files in os.walk(directory):
            for file in files:
                file_count += 1
                file_path = os.path.join(root, file)
                
                # Skip files we wouldn't scan
                if not is_excluded_directory(root) and file_count <= 100:  # Limit to 100 files for demo
                    scanned_files += 1
                    
                    # Randomly simulate threats (for demo purposes)
                    if random.random() < 0.03:  # 3% chance of finding a threat
                        threat_type = random.choice(["Malware", "Suspicious Script", "Risky Permission"])
                        severity = random.choice(["LOW", "MEDIUM", "HIGH"])
                        
                        results['threats'].append({
                            'file_path': file_path,
                            'type': threat_type,
                            'severity': severity,
                            'details': f"Potential {threat_type.lower()} detected in file"
                        })
                        threat_count += 1
            
            # Don't recurse if not requested
            if not recursive:
                break
                
            # Limit directory traversal for demo
            if file_count > 100:
                break
    except Exception as e:
        logger.error(f"Error scanning directory: {str(e)}")
        # Log error
        try:
            log_entry = SecurityLog(
                event_type="SCAN_ERROR",
                description=f"Error scanning directory {directory}: {str(e)}",
                severity="HIGH",
                timestamp=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as db_error:
            logger.error(f"Error logging scan error: {str(db_error)}")
    
    # Update result
    results['total_files'] = file_count
    results['scanned_files'] = scanned_files
    
    # Log scan results
    try:
        log_entry = SecurityLog(
            event_type="SCAN_COMPLETED",
            description=f"Scanned {results['scanned_files']} files in {directory}, found {len(results['threats'])} threats",
            severity="INFO" if not results['threats'] else "MEDIUM",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as db_error:
        logger.error(f"Error logging scan completion: {str(db_error)}")
    
    return results

def quick_scan():
    """Perform a quick scan of important directories"""
    important_dirs = [
        os.path.join(config.TERMUX_HOME, "bin"),
        os.path.join(config.TERMUX_HOME, "usr/bin"),
        "/data/data/com.termux/files/usr/bin"
    ]
    
    results = {
        'threats': [],
        'total_files': 0,
        'scanned_files': 0,
        'scan_time': datetime.now()
    }
    
    for directory in important_dirs:
        if os.path.exists(directory):
            dir_results = scan_directory(directory, recursive=False)
            results['threats'].extend(dir_results['threats'])
            results['total_files'] += dir_results['total_files']
            results['scanned_files'] += dir_results['scanned_files']
    
    return results

def background_scan_thread():
    """Background scanning thread function"""
    import time
    while True:
        try:
            # Perform a quick scan every hour
            quick_scan()
            # Sleep for an hour
            time.sleep(3600)
        except Exception as e:
            logger.error(f"Error in background scan: {str(e)}")
            time.sleep(300)  # Sleep for 5 minutes on error

def start_background_scanning():
    """Start the background scanning thread"""
    if config.BACKGROUND_SERVICE_ENABLED:
        bg_thread = threading.Thread(target=background_scan_thread)
        bg_thread.daemon = True
        bg_thread.start()
        logger.info("Background scanning started")
        
        # Log event
        log_entry = SecurityLog(
            event_type="BACKGROUND_SCAN_STARTED",
            description="Background scanning service started",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
