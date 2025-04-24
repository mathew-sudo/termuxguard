"""
Termux AntiMalware Configuration Settings
"""
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'termux_antimalware.log'))
    ]
)

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs'), exist_ok=True)

# Application Settings
APP_NAME = "Termux AntiMalware"
APP_VERSION = "1.0.0"
DEBUG_MODE = True

# Security Settings
SECURITY_TOKEN_LIFETIME = 20  # seconds
PASSWORD_HASH_METHOD = "pbkdf2:sha256:260000"  # Werkzeug password hash method

# Feature Flags (can be toggled in settings page)
FIREWALL_ENABLED = True
CONTENT_FILTER_ENABLED = True
AI_DETECTION_ENABLED = True
BACKGROUND_SERVICE_ENABLED = False
NOTIFICATION_ENABLED = True

# Scan Settings
SCAN_EXCLUDED_DIRS = [
    "/proc",
    "/sys",
    "/dev",
    "/apex",
    "/vendor",
    "/system"
]
SCAN_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
SCAN_USE_CLAMAV = False  # Enable if ClamAV is installed

# Firewall Settings
FIREWALL_DEFAULT_POLICY = "ALLOW"  # ALLOW or BLOCK
FIREWALL_LOG_DROPPED = True
FIREWALL_AUTO_BLOCK_ATTEMPTS = True
FIREWALL_BLOCK_DURATION = 300  # seconds (5 minutes)

# Content Filter Settings
CONTENT_FILTER_DOWNLOAD_LISTS = True
CONTENT_FILTER_UPDATE_INTERVAL = 86400  # seconds (24 hours)
CONTENT_FILTER_BLACKLISTS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
]

# AI Model Settings
AI_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'data', 'ai_models', 'threat_model.pkl')
AI_TRAINING_INTERVAL = 604800  # seconds (1 week)
AI_THREAT_THRESHOLD = 0.75  # Probability threshold for threat detection

# Notification Settings
NOTIFICATION_MIN_SEVERITY = "MEDIUM"  # INFO, MEDIUM, HIGH
NOTIFICATION_USE_TERMUX_API = True

# Log Retention
LOG_RETENTION_DAYS = 30
MAX_LOGS_ENTRY = 1000

# API Endpoints
API_RATE_LIMIT = 60  # requests per minute

# Default paths (for Termux environment)
DEFAULT_SCAN_PATHS = [
    "/data/data/com.termux/files",
    "/sdcard/Download"
]

# Function to validate configuration
def validate_config():
    """Validates the configuration settings and returns a list of warnings"""
    warnings = []
    
    # Check if directories exist
    for path in DEFAULT_SCAN_PATHS:
        if not os.path.exists(path):
            warnings.append(f"Default scan path not found: {path}")
    
    # Check for required features
    if SCAN_USE_CLAMAV:
        # This would be replaced with actual check in production
        warnings.append("ClamAV support is enabled but may not be installed.")
    
    if NOTIFICATION_USE_TERMUX_API and not check_termux_api():
        warnings.append("Termux API is enabled but may not be installed.")
    
    return warnings

def check_termux_api():
    """Check if Termux API is installed and available"""
    # This is a mock implementation
    # In a real environment, would check for termux-* commands
    return os.path.exists("/data/data/com.termux.api")
