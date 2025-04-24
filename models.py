from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    directory = db.Column(db.String(256), nullable=False)
    threats_found = db.Column(db.Integer, default=0)
    files_scanned = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<ScanResult {self.id}: {self.threats_found} threats in {self.directory}>"

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default="INFO")
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<SecurityLog {self.id}: {self.event_type} - {self.severity}>"

class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # tcp, udp, icmp
    source_ip = db.Column(db.String(64))
    destination_ip = db.Column(db.String(64))
    port = db.Column(db.Integer)
    action = db.Column(db.String(20), nullable=False)  # ALLOW, BLOCK
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<FirewallRule {self.id}: {self.name} - {self.action}>"

class ContentFilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)  # Extension or MIME type
    pattern = db.Column(db.String(256))  # Regex pattern for content
    action = db.Column(db.String(20), nullable=False)  # BLOCK, ALLOW, SCAN
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<ContentFilter {self.id}: {self.name} - {self.action}>"

class AIModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(64), nullable=False)
    accuracy = db.Column(db.Float)
    last_trained = db.Column(db.DateTime, default=datetime.now)
    parameters = db.Column(db.Text)  # JSON string of parameters
    
    def __repr__(self):
        return f"<AIModel {self.id}: {self.model_name} - {self.accuracy}>"

class ThreatSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="MEDIUM")
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<ThreatSignature {self.id}: {self.name} - {self.severity}>"
