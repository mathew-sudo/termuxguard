import os
import logging
import pickle
import numpy as np
import math
import threading
import time
from datetime import datetime
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from app import db
from models import SecurityLog, AIModel
import config

# Setup logger
logger = logging.getLogger(__name__)

# Global AI model
AI_MODEL = None
SCALER = None
AI_MODEL_LOADED = False

def extract_features(file_path):
    """Extract features from a file for AI analysis"""
    features = {}
    
    try:
        # Basic file properties
        file_size = os.path.getsize(file_path)
        features['file_size'] = file_size
        
        # File entropy
        entropy = calculate_entropy(file_path)
        features['entropy'] = entropy
        
        # Extension and MIME type
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()[1:] if ext else ""
        features['is_executable'] = 1 if ext in ['exe', 'apk', 'sh', 'bat', 'jar'] else 0
        
        # Byte frequency distribution for first 4KB
        byte_freq = get_byte_frequency(file_path)
        features.update(byte_freq)
        
        # Strings features
        strings_features = extract_strings_features(file_path)
        features.update(strings_features)
        
        # Permission features (for APK files)
        if ext == 'apk':
            perm_features = extract_apk_permissions(file_path)
            features.update(perm_features)
        else:
            features['permissions_count'] = 0
            features['has_dangerous_permissions'] = 0
        
        return features
    except Exception as e:
        logger.error(f"Error extracting features from {file_path}: {str(e)}")
        # Return default features on error
        return {
            'file_size': 0,
            'entropy': 0,
            'is_executable': 0,
            'byte_freq_00_3f': 0,
            'byte_freq_40_7f': 0,
            'byte_freq_80_bf': 0,
            'byte_freq_c0_ff': 0,
            'strings_count': 0,
            'avg_string_length': 0,
            'has_suspicious_strings': 0,
            'permissions_count': 0,
            'has_dangerous_permissions': 0
        }

def calculate_entropy(file_path):
    """Calculate Shannon entropy of a file"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(8192)  # Read first 8KB
            
        if not data:
            return 0
            
        byte_counts = {}
        data_size = len(data)
        
        # Count byte frequencies
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_size
            entropy -= probability * math.log2(probability)
            
        return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy: {str(e)}")
        return 0

def get_byte_frequency(file_path):
    """Calculate byte frequency distribution in different ranges"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4096)  # Read first 4KB
            
        if not data:
            return {
                'byte_freq_00_3f': 0,
                'byte_freq_40_7f': 0,
                'byte_freq_80_bf': 0,
                'byte_freq_c0_ff': 0
            }
            
        # Count bytes in different ranges
        ranges = {
            'byte_freq_00_3f': 0,  # Control chars
            'byte_freq_40_7f': 0,  # ASCII letters, numbers
            'byte_freq_80_bf': 0,  # Extended ASCII
            'byte_freq_c0_ff': 0   # Extended ASCII and special chars
        }
        
        for byte in data:
            if 0x00 <= byte <= 0x3F:
                ranges['byte_freq_00_3f'] += 1
            elif 0x40 <= byte <= 0x7F:
                ranges['byte_freq_40_7f'] += 1
            elif 0x80 <= byte <= 0xBF:
                ranges['byte_freq_80_bf'] += 1
            else:
                ranges['byte_freq_c0_ff'] += 1
        
        # Convert to proportions
        data_len = len(data)
        for key in ranges:
            ranges[key] = ranges[key] / data_len
            
        return ranges
    except Exception as e:
        logger.error(f"Error calculating byte frequencies: {str(e)}")
        return {
            'byte_freq_00_3f': 0,
            'byte_freq_40_7f': 0,
            'byte_freq_80_bf': 0,
            'byte_freq_c0_ff': 0
        }

def extract_strings_features(file_path):
    """Extract features from strings in the file"""
    try:
        # Run 'strings' command to extract ASCII strings
        import subprocess
        result = subprocess.run(
            ['strings', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            return {
                'strings_count': 0,
                'avg_string_length': 0,
                'has_suspicious_strings': 0
            }
            
        strings = result.stdout.splitlines()
        strings_count = len(strings)
        
        if strings_count == 0:
            return {
                'strings_count': 0,
                'avg_string_length': 0,
                'has_suspicious_strings': 0
            }
            
        # Calculate average string length
        avg_length = sum(len(s) for s in strings) / strings_count
        
        # Check for suspicious strings
        suspicious_patterns = [
            'eval(', 'system(', 'exec(', 'shell_exec(',
            '/bin/sh', '/bin/bash', 'cmd.exe',
            'powershell', 'wget', 'curl', 'netcat', 'nc -',
            'chmod +x', 'sudo', 'setuid', 'setgid',
            'iptables', '/etc/passwd', '/etc/shadow',
            'decrypt', 'encrypt', 'backdoor', 'trojan'
        ]
        
        has_suspicious = 0
        for pattern in suspicious_patterns:
            if any(pattern.lower() in s.lower() for s in strings):
                has_suspicious = 1
                break
                
        return {
            'strings_count': strings_count,
            'avg_string_length': avg_length,
            'has_suspicious_strings': has_suspicious
        }
    except Exception as e:
        logger.error(f"Error extracting strings features: {str(e)}")
        return {
            'strings_count': 0,
            'avg_string_length': 0,
            'has_suspicious_strings': 0
        }

def extract_apk_permissions(file_path):
    """Extract permission features from APK files"""
    try:
        # Try to use aapt (Android Asset Packaging Tool)
        import subprocess
        result = subprocess.run(
            ['aapt', 'd', 'permissions', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            return {
                'permissions_count': 0,
                'has_dangerous_permissions': 0
            }
            
        permissions = []
        for line in result.stdout.splitlines():
            if line.startswith('uses-permission:'):
                perm = line.split(':', 1)[1].strip()
                permissions.append(perm)
        
        permissions_count = len(permissions)
        
        # Check for dangerous permissions
        dangerous_permissions = [
            'android.permission.SEND_SMS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CONTACTS',
            'android.permission.CAMERA',
            'android.permission.READ_SMS',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.RECEIVE_BOOT_COMPLETED'
        ]
        
        has_dangerous = 0
        for perm in dangerous_permissions:
            if any(perm.lower() in p.lower() for p in permissions):
                has_dangerous = 1
                break
                
        return {
            'permissions_count': permissions_count,
            'has_dangerous_permissions': has_dangerous
        }
    except Exception as e:
        logger.error(f"Error extracting APK permissions: {str(e)}")
        return {
            'permissions_count': 0,
            'has_dangerous_permissions': 0
        }

def prepare_features_for_model(features_dict):
    """Convert features dictionary to numpy array for model input"""
    # Define order of features expected by the model
    feature_order = [
        'file_size', 'entropy', 'is_executable',
        'byte_freq_00_3f', 'byte_freq_40_7f', 'byte_freq_80_bf', 'byte_freq_c0_ff',
        'strings_count', 'avg_string_length', 'has_suspicious_strings',
        'permissions_count', 'has_dangerous_permissions'
    ]
    
    # Create vector in correct order
    features_vector = [features_dict.get(feature, 0) for feature in feature_order]
    return np.array([features_vector])

def load_ai_model():
    """Load the AI model from disk"""
    global AI_MODEL, SCALER, AI_MODEL_LOADED
    
    model_path = os.path.join(config.AI_MODEL_PATH, 'malware_model.pkl')
    scaler_path = os.path.join(config.AI_MODEL_PATH, 'feature_scaler.pkl')
    
    try:
        # Check if model files exist
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            # Load model and scaler
            with open(model_path, 'rb') as f:
                AI_MODEL = pickle.load(f)
            with open(scaler_path, 'rb') as f:
                SCALER = pickle.load(f)
            
            AI_MODEL_LOADED = True
            logger.info("AI model loaded successfully")
            
            # Get model info from database
            model_info = AIModel.query.first()
            if model_info:
                logger.info(f"Loaded model: {model_info.model_name}, Accuracy: {model_info.accuracy}")
                
            return True
        else:
            logger.warning("AI model files not found, creating new model")
            train_ai_model()
            return AI_MODEL_LOADED
    except Exception as e:
        logger.error(f"Error loading AI model: {str(e)}")
        return False

def predict_threat(file_path):
    """Predict if a file is a threat using the AI model"""
    global AI_MODEL, SCALER, AI_MODEL_LOADED
    
    # Load model if not loaded
    if not AI_MODEL_LOADED:
        load_ai_model()
        
    # If still not loaded, return low confidence prediction
    if not AI_MODEL_LOADED:
        logger.warning("AI model not available, using basic heuristics")
        # Use basic heuristics
        features = extract_features(file_path)
        
        # Simple heuristic score based on suspicious factors
        score = 0
        if features['is_executable']:
            score += 30
        if features['entropy'] > 6.8:
            score += 20
        if features['has_suspicious_strings']:
            score += 30
        if features['has_dangerous_permissions']:
            score += 20
            
        is_threat = score >= 50
        confidence = score
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'features': features
        }
    
    try:
        # Extract features
        features = extract_features(file_path)
        
        # Prepare features for model
        X = prepare_features_for_model(features)
        
        # Scale features
        X_scaled = SCALER.transform(X)
        
        # Make prediction (get probability of malicious class)
        proba = AI_MODEL.predict_proba(X_scaled)[0]
        is_threat = proba[1] >= 0.5
        confidence = proba[1] * 100
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'features': features
        }
    except Exception as e:
        logger.error(f"Error predicting threat: {str(e)}")
        return {
            'is_threat': False,
            'confidence': 0,
            'features': {}
        }

def train_ai_model():
    """Train a new AI model with sample data"""
    # Simple mock implementation for demo
    global AI_MODEL, SCALER, AI_MODEL_LOADED
    
    try:
        logger.info("Starting AI model training (mock implementation)")
        
        # Create model directory if it doesn't exist
        os.makedirs(os.path.dirname(config.AI_MODEL_PATH), exist_ok=True)
        
        # Generate synthetic training data
        X, y = generate_training_data()
        
        # Scale features
        SCALER = StandardScaler()
        X_scaled = SCALER.fit_transform(X)
        
        # Train a simple model
        model = RandomForestClassifier(
            n_estimators=10,  # Reduced for demo
            max_depth=5,      # Reduced for demo
            random_state=42
        )
        model.fit(X_scaled, y)
        
        # Calculate accuracy on training data
        accuracy = model.score(X_scaled, y)
        
        # Store model info in database
        try:
            # Import app here to avoid circular imports
            from app import app
            
            with app.app_context():
                model_info = AIModel.query.filter_by(model_name="RandomForest (Demo)").first()
                if model_info:
                    model_info.accuracy = float(accuracy)
                    model_info.last_trained = datetime.now()
                    model_info.parameters = str(model.get_params())
                else:
                    model_info = AIModel(
                        model_name="RandomForest (Demo)",
                        accuracy=float(accuracy),
                        last_trained=datetime.now(),
                        parameters=str(model.get_params())
                    )
                    db.session.add(model_info)
                
                db.session.commit()
                logger.info("AI model info saved to database")
        except Exception as db_error:
            logger.error(f"Database error during model training: {str(db_error)}")
        
        # Set global variables
        AI_MODEL = model
        AI_MODEL_LOADED = True
        
        # Log training to security logs
        try:
            # Import app here to avoid circular imports
            from app import app
            
            with app.app_context():
                log_entry = SecurityLog(
                    event_type="AI_MODEL_TRAINED",
                    description=f"AI model trained with accuracy: {accuracy:.4f}",
                    severity="INFO",
                    timestamp=datetime.now()
                )
                db.session.add(log_entry)
                db.session.commit()
                logger.info("Training event logged to security logs")
        except Exception as log_error:
            logger.error(f"Error logging AI training: {str(log_error)}")
        
        logger.info(f"Demo AI model trained successfully with accuracy: {accuracy:.4f}")
        return True
    except Exception as e:
        logger.error(f"Error training AI model: {str(e)}")
        return False

def generate_training_data():
    """Generate synthetic training data for model"""
    # In a real system, this would use real malware/benign samples
    # This is a simplified version that generates synthetic data with patterns
    
    # Number of samples to generate
    n_benign = 500
    n_malicious = 500
    
    # Feature matrix (12 features)
    X = []
    # Labels (0: benign, 1: malicious)
    y = []
    
    # Generate benign samples
    for _ in range(n_benign):
        # Typical patterns for benign files
        file_size = random.randint(1000, 5000000)  # 1KB to 5MB
        entropy = random.uniform(3.5, 6.5)
        is_executable = random.randint(0, 1)
        
        # Byte frequency distribution
        byte_freq_00_3f = random.uniform(0.1, 0.3)
        byte_freq_40_7f = random.uniform(0.3, 0.6)
        byte_freq_80_bf = random.uniform(0.05, 0.2)
        byte_freq_c0_ff = random.uniform(0.05, 0.2)
        
        # String features
        strings_count = random.randint(10, 1000)
        avg_string_length = random.uniform(5, 20)
        has_suspicious_strings = 0  # Mostly benign
        
        # Permissions
        permissions_count = random.randint(0, 5)
        has_dangerous_permissions = 0
        
        # Sometimes benign files may have suspicious characteristics
        if random.random() < 0.05:
            has_suspicious_strings = 1
        if random.random() < 0.03:
            has_dangerous_permissions = 1
        
        X.append([
            file_size, entropy, is_executable,
            byte_freq_00_3f, byte_freq_40_7f, byte_freq_80_bf, byte_freq_c0_ff,
            strings_count, avg_string_length, has_suspicious_strings,
            permissions_count, has_dangerous_permissions
        ])
        y.append(0)  # Benign
    
    # Generate malicious samples
    for _ in range(n_malicious):
        # Typical patterns for malicious files
        file_size = random.randint(1000, 10000000)  # 1KB to 10MB
        entropy = random.uniform(6.0, 8.0)  # Higher entropy due to packing/encryption
        is_executable = random.randint(0, 1)
        
        # Byte frequency distribution
        byte_freq_00_3f = random.uniform(0.2, 0.4)
        byte_freq_40_7f = random.uniform(0.2, 0.4)
        byte_freq_80_bf = random.uniform(0.1, 0.3)
        byte_freq_c0_ff = random.uniform(0.1, 0.3)
        
        # String features
        strings_count = random.randint(5, 500)
        avg_string_length = random.uniform(8, 30)
        has_suspicious_strings = 1 if random.random() < 0.8 else 0  # Often suspicious
        
        # Permissions
        permissions_count = random.randint(3, 15)
        has_dangerous_permissions = 1 if random.random() < 0.7 else 0
        
        X.append([
            file_size, entropy, is_executable,
            byte_freq_00_3f, byte_freq_40_7f, byte_freq_80_bf, byte_freq_c0_ff,
            strings_count, avg_string_length, has_suspicious_strings,
            permissions_count, has_dangerous_permissions
        ])
        y.append(1)  # Malicious
    
    return np.array(X), np.array(y)

def ai_periodic_training_thread():
    """Background thread to periodically retrain the AI model"""
    import time
    while True:
        try:
            # Sleep for specified interval (default: 24 hours)
            time.sleep(config.AI_TRAINING_INTERVAL)
            
            # Retrain model
            train_ai_model()
        except Exception as e:
            logger.error(f"Error in AI training thread: {str(e)}")
            time.sleep(3600)  # Sleep for an hour on error

def start_ai_training_service():
    """Start the periodic AI training service"""
    if config.AI_DETECTION_ENABLED:
        # Make sure model directory exists
        os.makedirs(config.AI_MODEL_PATH, exist_ok=True)
        
        # Load existing model or train new one
        if not load_ai_model():
            train_ai_model()
        
        # Start periodic training thread
        bg_thread = threading.Thread(target=ai_periodic_training_thread)
        bg_thread.daemon = True
        bg_thread.start()
        logger.info("AI periodic training service started")
