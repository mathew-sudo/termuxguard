import os
import re
import logging
import urllib.parse
import requests
from datetime import datetime
import time
import threading

from app import db
from models import ContentFilter, SecurityLog
import config

# Setup logger
logger = logging.getLogger(__name__)

# Content filter cache
CONTENT_FILTERS = []
DOMAIN_BLACKLIST = set()
DOMAIN_WHITELIST = set()

def load_content_filters():
    """Load content filters from database"""
    global CONTENT_FILTERS
    try:
        filters = ContentFilter.query.filter_by(enabled=True).all()
        CONTENT_FILTERS = [
            {
                'id': f.id,
                'name': f.name,
                'file_type': f.file_type,
                'pattern': f.pattern if f.pattern else None,
                'action': f.action
            }
            for f in filters
        ]
        logger.info(f"Loaded {len(CONTENT_FILTERS)} content filters")
    except Exception as e:
        logger.error(f"Failed to load content filters: {str(e)}")

def load_domain_lists():
    """Load domain blacklist and whitelist"""
    global DOMAIN_BLACKLIST, DOMAIN_WHITELIST
    try:
        # Load blacklist from file
        blacklist_path = os.path.join(config.STORAGE_PATH, "domain_blacklist.txt")
        if os.path.exists(blacklist_path):
            with open(blacklist_path, 'r') as f:
                DOMAIN_BLACKLIST = set(line.strip() for line in f if line.strip())
        
        # Load whitelist from file
        whitelist_path = os.path.join(config.STORAGE_PATH, "domain_whitelist.txt")
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                DOMAIN_WHITELIST = set(line.strip() for line in f if line.strip())
                
        logger.info(f"Loaded {len(DOMAIN_BLACKLIST)} blacklisted domains and {len(DOMAIN_WHITELIST)} whitelisted domains")
    except Exception as e:
        logger.error(f"Failed to load domain lists: {str(e)}")

def update_content_filters():
    """Update content filters from database"""
    load_content_filters()
    load_domain_lists()
    
    # Log update
    log_entry = SecurityLog(
        event_type="CONTENT_FILTERS_UPDATED",
        description=f"Content filters updated: {len(CONTENT_FILTERS)} filters loaded",
        severity="INFO",
        timestamp=datetime.now()
    )
    db.session.add(log_entry)
    db.session.commit()

def check_file_against_filters(file_path):
    """Check if a file matches any content filters"""
    if not CONTENT_FILTERS:
        load_content_filters()
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return {'allowed': True, 'reason': None}
    
    # Get file extension
    _, ext = os.path.splitext(file_path)
    if ext:
        ext = ext.lower()[1:]  # Remove the dot
    
    # Check against filters
    for filter_rule in CONTENT_FILTERS:
        # Check if extension matches
        if filter_rule['file_type'] == ext:
            # If pattern is specified, check file content
            if filter_rule['pattern']:
                try:
                    # Only check first 100KB to avoid large files
                    with open(file_path, 'rb') as f:
                        content = f.read(102400)
                    
                    # Try to decode as text
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                        if re.search(filter_rule['pattern'], text_content, re.IGNORECASE):
                            return {
                                'allowed': filter_rule['action'] == 'ALLOW',
                                'reason': filter_rule['name'],
                                'action': filter_rule['action']
                            }
                    except:
                        pass  # Not a text file
                except Exception as e:
                    logger.error(f"Error checking file content: {str(e)}")
            else:
                # No pattern specified, apply action based on file type match
                return {
                    'allowed': filter_rule['action'] == 'ALLOW',
                    'reason': filter_rule['name'],
                    'action': filter_rule['action']
                }
    
    # Default allow if no filters match
    return {'allowed': True, 'reason': None}

def check_url_against_filters(url):
    """Check if a URL is allowed by content filters"""
    if not DOMAIN_BLACKLIST or not DOMAIN_WHITELIST:
        load_domain_lists()
    
    try:
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Check whitelist first
        if domain in DOMAIN_WHITELIST:
            return {'allowed': True, 'reason': 'Domain whitelisted'}
        
        # Check blacklist
        if domain in DOMAIN_BLACKLIST:
            # Log blocked URL
            log_entry = SecurityLog(
                event_type="URL_BLOCKED",
                description=f"Blocked access to blacklisted domain: {domain}",
                severity="MEDIUM",
                timestamp=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return {'allowed': False, 'reason': 'Domain blacklisted'}
        
        # If we have parent domains in blacklist, check those too
        domain_parts = domain.split('.')
        for i in range(1, len(domain_parts) - 1):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in DOMAIN_BLACKLIST:
                # Log blocked URL
                log_entry = SecurityLog(
                    event_type="URL_BLOCKED",
                    description=f"Blocked access to domain under blacklisted parent: {domain} (parent: {parent_domain})",
                    severity="MEDIUM",
                    timestamp=datetime.now()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                return {'allowed': False, 'reason': f'Parent domain {parent_domain} blacklisted'}
        
        # Default allow if not in any list
        return {'allowed': True, 'reason': None}
    except Exception as e:
        logger.error(f"Error checking URL against filters: {str(e)}")
        # Default to allow on error
        return {'allowed': True, 'reason': f'Error: {str(e)}'}

def add_to_blacklist(domain):
    """Add a domain to the blacklist"""
    global DOMAIN_BLACKLIST
    try:
        # Add to memory
        domain = domain.lower().strip()
        DOMAIN_BLACKLIST.add(domain)
        
        # Add to file
        blacklist_path = os.path.join(config.STORAGE_PATH, "domain_blacklist.txt")
        with open(blacklist_path, 'a') as f:
            f.write(f"{domain}\n")
        
        # Log addition
        log_entry = SecurityLog(
            event_type="DOMAIN_BLACKLISTED",
            description=f"Domain added to blacklist: {domain}",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"Added {domain} to blacklist")
        return True
    except Exception as e:
        logger.error(f"Failed to add domain to blacklist: {str(e)}")
        return False

def add_to_whitelist(domain):
    """Add a domain to the whitelist"""
    global DOMAIN_WHITELIST
    try:
        # Add to memory
        domain = domain.lower().strip()
        DOMAIN_WHITELIST.add(domain)
        
        # Add to file
        whitelist_path = os.path.join(config.STORAGE_PATH, "domain_whitelist.txt")
        with open(whitelist_path, 'a') as f:
            f.write(f"{domain}\n")
        
        # Log addition
        log_entry = SecurityLog(
            event_type="DOMAIN_WHITELISTED",
            description=f"Domain added to whitelist: {domain}",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"Added {domain} to whitelist")
        return True
    except Exception as e:
        logger.error(f"Failed to add domain to whitelist: {str(e)}")
        return False

def remove_from_blacklist(domain):
    """Remove a domain from the blacklist"""
    global DOMAIN_BLACKLIST
    try:
        # Remove from memory
        domain = domain.lower().strip()
        if domain in DOMAIN_BLACKLIST:
            DOMAIN_BLACKLIST.remove(domain)
        
        # Update file
        blacklist_path = os.path.join(config.STORAGE_PATH, "domain_blacklist.txt")
        if os.path.exists(blacklist_path):
            with open(blacklist_path, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            # Remove domain and write back
            if domain in domains:
                domains.remove(domain)
                with open(blacklist_path, 'w') as f:
                    for d in domains:
                        f.write(f"{d}\n")
        
        # Log removal
        log_entry = SecurityLog(
            event_type="DOMAIN_UNBLACKLISTED",
            description=f"Domain removed from blacklist: {domain}",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"Removed {domain} from blacklist")
        return True
    except Exception as e:
        logger.error(f"Failed to remove domain from blacklist: {str(e)}")
        return False

def setup_default_filters():
    """Set up default content filters if none exist"""
    try:
        count = ContentFilter.query.count()
        if count == 0:
            # Create default filters
            default_filters = [
                ContentFilter(
                    name="Block Executable Files",
                    file_type="exe",
                    pattern=None,
                    action="BLOCK",
                    enabled=True
                ),
                ContentFilter(
                    name="Block Shell Scripts",
                    file_type="sh",
                    pattern=None,
                    action="BLOCK",
                    enabled=True
                ),
                ContentFilter(
                    name="Scan APK Files",
                    file_type="apk",
                    pattern=None,
                    action="SCAN",
                    enabled=True
                ),
                ContentFilter(
                    name="Block JavaScript Files",
                    file_type="js",
                    pattern="eval\\(|document\\.cookie",
                    action="BLOCK",
                    enabled=True
                ),
                ContentFilter(
                    name="Block Python Scripts",
                    file_type="py",
                    pattern="os\\.system|subprocess",
                    action="SCAN",
                    enabled=True
                )
            ]
            
            for filter_rule in default_filters:
                db.session.add(filter_rule)
            
            db.session.commit()
            logger.info(f"Created {len(default_filters)} default content filters")
            
            # Load the filters
            load_content_filters()
    except Exception as e:
        logger.error(f"Failed to set up default filters: {str(e)}")

def download_blacklists():
    """Download and merge external blacklists"""
    try:
        # URLs of known malware/phishing domain lists
        blacklist_urls = [
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
        ]
        
        new_domains = set()
        
        for url in blacklist_urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    
                    # Parse hosts file format
                    if "hosts" in url:
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    domain = parts[1].lower()
                                    if domain != 'localhost' and '.' in domain:
                                        new_domains.add(domain)
                    # Parse domain list format
                    else:
                        for line in content.splitlines():
                            domain = line.strip().lower()
                            if domain and '.' in domain:
                                new_domains.add(domain)
            except Exception as e:
                logger.error(f"Error downloading blacklist from {url}: {str(e)}")
        
        # Add new domains to blacklist
        global DOMAIN_BLACKLIST
        old_count = len(DOMAIN_BLACKLIST)
        
        # Save domains to file
        blacklist_path = os.path.join(config.STORAGE_PATH, "domain_blacklist.txt")
        with open(blacklist_path, 'w') as f:
            for domain in sorted(DOMAIN_BLACKLIST.union(new_domains)):
                f.write(f"{domain}\n")
        
        # Update in-memory list
        DOMAIN_BLACKLIST = DOMAIN_BLACKLIST.union(new_domains)
        
        # Log update
        new_count = len(DOMAIN_BLACKLIST)
        log_entry = SecurityLog(
            event_type="BLACKLIST_UPDATED",
            description=f"Domain blacklist updated: {new_count - old_count} new domains added",
            severity="INFO",
            timestamp=datetime.now()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"Downloaded blacklists: {new_count - old_count} new domains added")
        return new_count - old_count
    except Exception as e:
        logger.error(f"Failed to download blacklists: {str(e)}")
        return 0

def blacklist_update_thread():
    """Background thread to update blacklists periodically"""
    while True:
        try:
            # Download updated blacklists
            download_blacklists()
            # Sleep for 24 hours
            time.sleep(86400)  # 24 hours
        except Exception as e:
            logger.error(f"Error in blacklist update thread: {str(e)}")
            time.sleep(3600)  # Sleep for 1 hour on error

def start_blacklist_updates():
    """Start the blacklist update thread"""
    if config.CONTENT_FILTER_ENABLED:
        # Make sure storage directory exists
        os.makedirs(config.STORAGE_PATH, exist_ok=True)
        
        # Set up default filters
        setup_default_filters()
        
        # Start update thread
        bg_thread = threading.Thread(target=blacklist_update_thread)
        bg_thread.daemon = True
        bg_thread.start()
        logger.info("Blacklist update service started")
