import os
import secrets
import string
import hashlib
import time
import json
import logging
import math
from datetime import datetime
from app import db
from models import SecurityLog

# Setup logger
logger = logging.getLogger(__name__)

def generate_security_token(length=32):
    """Generate a secure random token for authentication and security checks."""
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    # Log token generation
    logger.debug(f"New security token generated: {token[:5]}...")
    
    return token

def verify_token(token, stored_token):
    """Verify if the provided token matches the stored token."""
    if not token or not stored_token:
        return False
    
    return secrets.compare_digest(token, stored_token)

def hash_password(password):
    """Generate a secure hash for the password."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt + key

def check_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    if not os.path.exists(file_path):
        return None
        
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {str(e)}")
        return None

def calculate_file_entropy(file_path):
    """Calculate the entropy of a file to help identify encrypted/compressed files."""
    if not os.path.exists(file_path):
        return 0
        
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0
            
        entropy = 0
        byte_counts = {}
        file_size = len(data)
        
        # Count occurrences of each byte
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            probability = count / file_size
            entropy -= probability * (math.log(probability, 2))
            
        return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
        return 0

def log_security_event(event_type, description, severity="INFO"):
    """Log a security event to the database."""
    try:
        from app import db
        from models import SecurityLog
        from datetime import datetime
        
        # Create and add log entry
        log_entry = SecurityLog(
            event_type=event_type,
            description=description,
            severity=severity,
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Log to console as well
        import logging
        logger = logging.getLogger(__name__)
        log_method = getattr(logger, severity.lower(), logger.info)
        log_method(f"Security event: {event_type} - {description}")
        
        return True
    except Exception as e:
        import logging
        logging.error(f"Error logging security event: {str(e)}")
        return False

def detect_breach_attempt(request_data, ip_address):
    """Detect potential breach attempts based on request patterns."""
    suspicious_patterns = [
        "eval(", "exec(", "system(", "; rm", "wget", "curl",
        "../", "../../", "/etc/passwd", "select ", "union ",
        "<script>", "alert(", "document.cookie", "onload=", "onerror="
    ]
    
    # Check if request contains suspicious patterns
    data_str = json.dumps(request_data).lower()
    for pattern in suspicious_patterns:
        if pattern.lower() in data_str:
            log_security_event(
                "BREACH_ATTEMPT",
                f"Suspicious pattern detected in request: {pattern} from IP: {ip_address}",
                "HIGH"
            )
            return True
            
    return False

def compute_signature(data):
    """Compute a signature for data integrity verification."""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    elif not isinstance(data, str):
        data = str(data)
        
    signature = hashlib.sha256(data.encode()).hexdigest()
    return signature
