"""
Prix AI Security System Configuration
"""

import os
from pathlib import Path

# System Configuration
SYSTEM_CONFIG = {
    "monitoring": {
        "process_check_interval": 5,  # seconds
        "network_check_interval": 10,  # seconds
        "filesystem_monitoring": True,
        "real_time_protection": True,
        "auto_eliminate_high_priority": True,
        "auto_eliminate_critical": True
    },
    "threat_detection": {
        "suspicious_process_patterns": [
            r'.*keylogger.*',
            r'.*spy.*',
            r'.*hack.*',
            r'.*crack.*',
            r'.*backdoor.*',
            r'.*rootkit.*',
            r'.*trojan.*',
            r'.*malware.*',
            r'.*botnet.*',
            r'.*ransomware.*',
            r'.*cryptolocker.*',
            r'.*worm.*'
        ],
        "suspicious_file_extensions": [
            '.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.ps1',
            '.com', '.pif', '.msi', '.deb', '.rpm', '.dmg', '.app'
        ],
        "suspicious_network_ports": [
            4444, 5555, 6667, 9999, 31337, 12345, 54321, 19283
        ],
        "high_cpu_threshold": 90.0,  # percentage
        "high_memory_threshold": 80.0,  # percentage
        "max_connections_per_process": 100
    },
    "quarantine": {
        "quarantine_directory": "/tmp/prix_quarantine",
        "max_quarantine_size_mb": 1000,
        "auto_delete_after_days": 30
    },
    "logging": {
        "log_file": "prix_security.log",
        "max_log_size_mb": 50,
        "backup_count": 5,
        "log_level": "INFO"
    },
    "database": {
        "path": "prix_security.db",
        "backup_enabled": True,
        "backup_interval_hours": 24
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
        "auto_refresh_interval": 5  # seconds
    },
    "notifications": {
        "email_enabled": False,
        "email_smtp_server": "",
        "email_port": 587,
        "email_username": "",
        "email_password": "",
        "email_recipients": [],
        "desktop_notifications": True,
        "sound_alerts": True
    }
}

# Advanced Threat Intelligence
THREAT_INTELLIGENCE = {
    "malware_hashes": [
        # Example malware SHA256 hashes (in production, this would be much larger)
        "d41d8cd98f00b204e9800998ecf8427e",
        "e3b0c44298fc1c149afbf4c8996fb924",
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    ],
    "malicious_ips": [
        # Example malicious IP ranges
        "192.168.1.100",
        "10.0.0.50"
    ],
    "malicious_domains": [
        "malicious-site.com",
        "evil-domain.net"
    ]
}

# Security Policies
SECURITY_POLICIES = {
    "process_whitelist": [
        "chrome", "firefox", "safari", "systemd", "kernel", "python",
        "node", "npm", "docker", "kubectl", "git", "vim", "nano"
    ],
    "network_whitelist": [
        "google.com", "github.com", "stackoverflow.com", "python.org"
    ],
    "allowed_file_types": [
        ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".zip", ".tar.gz"
    ]
}

def get_config(key_path: str, default=None):
    """Get configuration value by key path (e.g., 'monitoring.process_check_interval')"""
    keys = key_path.split('.')
    value = SYSTEM_CONFIG
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value

def set_config(key_path: str, value):
    """Set configuration value by key path"""
    keys = key_path.split('.')
    config = SYSTEM_CONFIG
    
    for key in keys[:-1]:
        if key not in config:
            config[key] = {}
        config = config[key]
    
    config[keys[-1]] = value
    return True

def create_directories():
    """Create necessary directories"""
    dirs_to_create = [
        get_config("quarantine.quarantine_directory"),
        os.path.dirname(get_config("logging.log_file")),
        os.path.dirname(get_config("database.path"))
    ]
    
    for dir_path in dirs_to_create:
        if dir_path:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

# Initialize directories
create_directories()
