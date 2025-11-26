#!/usr/bin/env python3
"""
Prix AI Security System Setup Script
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def check_python_version():
    """Check Python version compatibility"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ Python 3.7+ is required")
        sys.exit(1)
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} compatible")

def check_system_requirements():
    """Check system requirements"""
    system = platform.system()
    print(f"🖥️  System: {system}")
    
    if system == "Linux":
        print("✅ Linux system detected")
    elif system == "Darwin":
        print("⚠️  macOS detected - some features may be limited")
    elif system == "Windows":
        print("⚠️  Windows detected - some features may be limited")
    else:
        print("⚠️  Unknown system - proceeding anyway")

def install_dependencies():
    """Install required Python packages"""
    print("📦 Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "data",
        "quarantine",
        "templates",
        "static/css",
        "static/js",
        "static/images"
    ]
    
    print("📁 Creating directories...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✅ Created {directory}")

def setup_database():
    """Initialize security database"""
    print("🗄️  Setting up database...")
    
    try:
        from main import DatabaseManager
        db = DatabaseManager()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        sys.exit(1)

def create_systemd_service():
    """Create systemd service file for Linux"""
    if platform.system() != "Linux":
        print("⚠️  Systemd service creation skipped (not Linux)")
        return
    
    service_content = """[Unit]
Description=Prix AI Security System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={}
ExecStart={} -m main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""".format(os.getcwd(), sys.executable)
    
    service_path = "/etc/systemd/system/prix-security.service"
    
    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
        print(f"✅ Systemd service created at {service_path}")
        print("💡 To enable: sudo systemctl enable prix-security")
        print("💡 To start: sudo systemctl start prix-security")
    except PermissionError:
        print("⚠️  Permission denied - run with sudo to create systemd service")

def create_desktop_entry():
    """Create desktop entry for dashboard"""
    if platform.system() != "Linux":
        print("⚠️  Desktop entry creation skipped (not Linux)")
        return
    
    desktop_content = """[Desktop Entry]
Version=1.0
Type=Application
Name=Prix Security Dashboard
Comment=AI Security System Dashboard
Exec={} -m dashboard
Icon=security-high
Terminal=false
Categories=System;Security;
""".format(sys.executable)
    
    desktop_path = os.path.expanduser("~/.local/share/applications/prix-security.desktop")
    
    try:
        os.makedirs(os.path.dirname(desktop_path), exist_ok=True)
        with open(desktop_path, 'w') as f:
            f.write(desktop_content)
        print(f"✅ Desktop entry created at {desktop_path}")
    except Exception as e:
        print(f"⚠️  Could not create desktop entry: {e}")

def set_permissions():
    """Set appropriate file permissions"""
    print("🔐 Setting permissions...")
    
    # Make scripts executable
    scripts = ["main.py", "dashboard.py", "setup.py"]
    for script in scripts:
        if os.path.exists(script):
            os.chmod(script, 0o755)
            print(f"  ✅ Made {script} executable")

def create_config_file():
    """Create user configuration file"""
    config_path = "user_config.py"
    
    if os.path.exists(config_path):
        print(f"⚠️  {config_path} already exists - skipping")
        return
    
    config_content = '''"""
User Configuration for Prix AI Security System
Override default settings here
"""

# Custom monitoring settings
CUSTOM_MONITORING = {
    "process_check_interval": 3,  # Check every 3 seconds
    "auto_eliminate_critical": True,
    "desktop_notifications": True
}

# Email notifications (optional)
EMAIL_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "recipients": ["admin@example.com"]
}

# Custom threat patterns
CUSTOM_PATTERNS = [
    r'.*custom-malware.*',
    r'.*suspicious-tool.*'
]
'''
    
    with open(config_path, 'w') as f:
        f.write(config_content)
    print(f"✅ Created {config_path}")

def run_tests():
    """Run basic system tests"""
    print("🧪 Running system tests...")
    
    try:
        # Test imports
        import psutil
        import sqlite3
        import flask
        print("  ✅ Core dependencies working")
        
        # Test database
        from main import DatabaseManager
        db = DatabaseManager()
        print("  ✅ Database connection working")
        
        # Test monitoring (without starting)
        from main import SystemMonitor
        monitor = SystemMonitor(db)
        print("  ✅ System monitor initialized")
        
        print("✅ All tests passed")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)

def print_completion_message():
    """Print setup completion message"""
    print("\n" + "="*60)
    print("🎉 Prix AI Security System setup completed!")
    print("="*60)
    print("\n📋 Next steps:")
    print("1. Start the security system:")
    print("   python3 main.py")
    print("\n2. Open the dashboard (in another terminal):")
    print("   python3 dashboard.py")
    print("   Then visit: http://localhost:5000")
    print("\n3. Configure settings:")
    print("   Edit user_config.py")
    print("\n4. View logs:")
    print("   tail -f prix_security.log")
    print("\n⚠️  Important:")
    print("- Run as root for full system access")
    print("- Configure firewall rules for network protection")
    print("- Set up email notifications for alerts")
    print("\n📚 For help, check the documentation or visit:")
    print("   https://github.com/prix-security/docs")
    print("="*60)

def main():
    """Main setup function"""
    print("🚀 Prix AI Security System Setup")
    print("="*40)
    
    # Check requirements
    check_python_version()
    check_system_requirements()
    
    # Install dependencies
    install_dependencies()
    
    # Setup system
    create_directories()
    setup_database()
    set_permissions()
    create_config_file()
    create_systemd_service()
    create_desktop_entry()
    
    # Run tests
    run_tests()
    
    # Complete
    print_completion_message()

if __name__ == "__main__":
    main()
