#!/usr/bin/env python3
"""
Cross-Platform Compatibility Module
Supports Linux, Windows, macOS, Android (Termux), and iOS deployment
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PlatformInfo:
    """Platform information and capabilities"""
    platform: str
    architecture: str
    version: str
    supported_features: List[str]
    installation_method: str
    shell_type: str
    package_manager: str
    service_manager: str

class CrossPlatformManager:
    """Cross-platform compatibility manager"""
    
    def __init__(self):
        self.platform_info = self._detect_platform()
        self.supported_platforms = {
            'linux': self._get_linux_config(),
            'windows': self._get_windows_config(),
            'darwin': self._get_macos_config(),
            'android': self._get_android_config(),
            'ios': self._get_ios_config()
        }
        
        logger.info(f"Detected platform: {self.platform_info.platform}")
        logger.info(f"Architecture: {self.platform_info.architecture}")
        logger.info(f"Shell type: {self.platform_info.shell_type}")
    
    def _detect_platform(self) -> PlatformInfo:
        """Detect current platform and capabilities"""
        system = platform.system().lower()
        architecture = platform.machine().lower()
        version = platform.version()
        
        # Determine platform-specific info
        if system == 'linux':
            return self._detect_linux_platform(architecture, version)
        elif system == 'windows':
            return self._detect_windows_platform(architecture, version)
        elif system == 'darwin':
            return self._detect_macos_platform(architecture, version)
        elif 'ANDROID_ROOT' in os.environ or 'termux' in os.environ.get('PREFIX', ''):
            return self._detect_android_platform(architecture, version)
        else:
            # Default to unknown
            return PlatformInfo(
                platform='unknown',
                architecture=architecture,
                version=version,
                supported_features=[],
                installation_method='manual',
                shell_type='unknown',
                package_manager='unknown',
                service_manager='none'
            )
    
    def _detect_linux_platform(self, architecture: str, version: str) -> PlatformInfo:
        """Detect Linux distribution and capabilities"""
        supported_features = [
            'kernel_monitoring', 'memory_protection', 'network_analysis',
            'process_monitoring', 'file_protection', 'tpm_support',
            'secure_boot', 'systemd_service', 'iptables_integration'
        ]
        
        # Check for specific distributions
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
                distro = 'unknown'
                
                if 'ubuntu' in os_release.lower():
                    distro = 'ubuntu'
                elif 'centos' in os_release.lower() or 'rhel' in os_release.lower():
                    distro = 'rhel'
                elif 'debian' in os_release.lower():
                    distro = 'debian'
                elif 'arch' in os_release.lower():
                    distro = 'arch'
                elif 'fedora' in os_release.lower():
                    distro = 'fedora'
        except:
            distro = 'unknown'
        
        # Determine package manager
        package_manager = 'apt'
        if distro in ['rhel', 'centos', 'fedora']:
            package_manager = 'yum' if distro in ['rhel', 'centos'] else 'dnf'
        elif distro == 'arch':
            package_manager = 'pacman'
        elif distro == 'debian':
            package_manager = 'apt'
        
        return PlatformInfo(
            platform='linux',
            architecture=architecture,
            version=version,
            supported_features=supported_features,
            installation_method='package_manager',
            shell_type='bash',
            package_manager=package_manager,
            service_manager='systemd'
        )
    
    def _detect_windows_platform(self, architecture: str, version: str) -> PlatformInfo:
        """Detect Windows version and capabilities"""
        supported_features = [
            'kernel_monitoring', 'memory_protection', 'network_analysis',
            'process_monitoring', 'file_protection', 'windows_defender_integration',
            'powershell_automation', 'windows_service', 'registry_protection',
            'wmi_integration', 'event_log_monitoring'
        ]
        
        return PlatformInfo(
            platform='windows',
            architecture=architecture,
            version=version,
            supported_features=supported_features,
            installation_method='installer',
            shell_type='powershell',
            package_manager='chocolatey',
            service_manager='windows_service'
        )
    
    def _detect_macos_platform(self, architecture: str, version: str) -> PlatformInfo:
        """Detect macOS version and capabilities"""
        supported_features = [
            'kernel_monitoring', 'memory_protection', 'network_analysis',
            'process_monitoring', 'file_protection', 'sip_protection',
            'launchd_service', 'keychain_integration', 'gatekeeper_bypass_detection',
            'xattr_protection', 'notarization_check'
        ]
        
        return PlatformInfo(
            platform='darwin',
            architecture=architecture,
            version=version,
            supported_features=supported_features,
            installation_method='package',
            shell_type='zsh',
            package_manager='homebrew',
            service_manager='launchd'
        )
    
    def _detect_android_platform(self, architecture: str, version: str) -> PlatformInfo:
        """Detect Android/Termux capabilities"""
        supported_features = [
            'process_monitoring', 'network_analysis', 'file_protection',
            'termux_integration', 'android_api_integration', 'app_monitoring',
            'permission_monitoring', 'root_detection'
        ]
        
        return PlatformInfo(
            platform='android',
            architecture=architecture,
            version=version,
            supported_features=supported_features,
            installation_method='termux_package',
            shell_type='bash',
            package_manager='pkg',
            service_manager='termux_service'
        )
    
    def _detect_ios_platform(self, architecture: str, version: str) -> PlatformInfo:
        """Detect iOS capabilities (limited due to sandboxing)"""
        supported_features = [
            'app_monitoring', 'network_analysis', 'jailbreak_detection',
            'certificate_monitoring', 'safari_protection', 'keychain_monitoring'
        ]
        
        return PlatformInfo(
            platform='ios',
            architecture=architecture,
            version=version,
            supported_features=supported_features,
            installation_method='app_store',
            shell_type='limited',
            package_manager='none',
            service_manager='ios_background'
        )
    
    def _get_linux_config(self) -> Dict:
        """Get Linux-specific configuration"""
        return {
            'install_commands': {
                'ubuntu': 'sudo apt update && sudo apt install python3 python3-pip',
                'debian': 'sudo apt update && sudo apt install python3 python3-pip',
                'rhel': 'sudo yum install python3 python3-pip',
                'centos': 'sudo yum install python3 python3-pip',
                'fedora': 'sudo dnf install python3 python3-pip',
                'arch': 'sudo pacman -S python python-pip'
            },
            'service_commands': {
                'start': 'sudo systemctl start prix-security',
                'stop': 'sudo systemctl stop prix-security',
                'status': 'sudo systemctl status prix-security',
                'enable': 'sudo systemctl enable prix-security'
            },
            'config_paths': {
                'config': '/etc/prix-security/',
                'logs': '/var/log/prix-security/',
                'data': '/var/lib/prix-security/',
                'binaries': '/usr/local/bin/'
            }
        }
    
    def _get_windows_config(self) -> Dict:
        """Get Windows-specific configuration"""
        return {
            'install_commands': {
                'powershell': 'Install-Package -Name python3',
                'chocolatey': 'choco install python3',
                'manual': 'Download python3 from python.org'
            },
            'service_commands': {
                'start': 'Start-Service -Name PrixSecurity',
                'stop': 'Stop-Service -Name PrixSecurity',
                'status': 'Get-Service -Name PrixSecurity',
                'install': 'New-Service -Name PrixSecurity -BinaryPathName "C:\\PrixSecurity\\prix.exe"'
            },
            'config_paths': {
                'config': 'C:\\ProgramData\\PrixSecurity\\config\\',
                'logs': 'C:\\ProgramData\\PrixSecurity\\logs\\',
                'data': 'C:\\ProgramData\\PrixSecurity\\data\\',
                'binaries': 'C:\\Program Files\\PrixSecurity\\'
            }
        }
    
    def _get_macos_config(self) -> Dict:
        """Get macOS-specific configuration"""
        return {
            'install_commands': {
                'homebrew': 'brew install python3',
                'manual': 'Download python3 from python.org'
            },
            'service_commands': {
                'start': 'sudo launchctl load /Library/LaunchDaemons/com.prix.security.plist',
                'stop': 'sudo launchctl unload /Library/LaunchDaemons/com.prix.security.plist',
                'status': 'sudo launchctl list | grep com.prix.security'
            },
            'config_paths': {
                'config': '/Library/Application Support/PrixSecurity/config/',
                'logs': '/Library/Logs/PrixSecurity/',
                'data': '/Library/Application Support/PrixSecurity/data/',
                'binaries': '/usr/local/bin/'
            }
        }
    
    def _get_android_config(self) -> Dict:
        """Get Android/Termux-specific configuration"""
        return {
            'install_commands': {
                'termux': 'pkg update && pkg install python'
            },
            'service_commands': {
                'start': 'termux-service start prix-security',
                'stop': 'termux-service stop prix-security',
                'status': 'ps aux | grep prix-security'
            },
            'config_paths': {
                'config': '~/../data/data/com.termux/files/usr/etc/prix-security/',
                'logs': '~/../data/data/com.termux/files/usr/var/log/prix-security/',
                'data': '~/../data/data/com.termux/files/usr/var/lib/prix-security/',
                'binaries': '~/../data/data/com.termux/files/usr/bin/'
            }
        }
    
    def _get_ios_config(self) -> Dict:
        """Get iOS-specific configuration"""
        return {
            'install_commands': {
                'app_store': 'Download from App Store',
                'enterprise': 'Install via MDM'
            },
            'service_commands': {
                'start': 'iOS Background Task',
                'stop': 'iOS Background Task',
                'status': 'iOS App Status'
            },
            'config_paths': {
                'config': 'App/Documents/config/',
                'logs': 'App/Documents/logs/',
                'data': 'App/Documents/data/',
                'binaries': 'App/Frameworks/'
            }
        }
    
    def generate_platform_scripts(self):
        """Generate platform-specific deployment scripts"""
        platform = self.platform_info.platform
        config = self.supported_platforms.get(platform, {})
        
        if platform == 'linux':
            self._generate_linux_scripts(config)
        elif platform == 'windows':
            self._generate_windows_scripts(config)
        elif platform == 'darwin':
            self._generate_macos_scripts(config)
        elif platform == 'android':
            self._generate_android_scripts(config)
        elif platform == 'ios':
            self._generate_ios_scripts(config)
    
    def _generate_linux_scripts(self, config: Dict):
        """Generate Linux deployment scripts"""
        # Generate installation script
        install_script = '''#!/bin/bash
# Prix AI Security System - Linux Installation Script

set -e

echo "Installing Prix AI Security System for Linux..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root for security reasons"
   echo "Please run as a regular user with sudo privileges"
   exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Cannot detect Linux distribution"
    exit 1
fi

# Install dependencies based on distribution
case $DISTRO in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        sudo apt update
        sudo apt install -y python3 python3-pip python3-venv git
        ;;
    rhel|centos)
        echo "Installing dependencies for RHEL/CentOS..."
        sudo yum install -y python3 python3-pip git
        ;;
    fedora)
        echo "Installing dependencies for Fedora..."
        sudo dnf install -y python3 python3-pip git
        ;;
    arch)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -S python python-pip git
        ;;
    *)
        echo "Unsupported distribution: $DISTRO"
        exit 1
        ;;
esac

# Create installation directory
INSTALL_DIR="/opt/prix-security"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

# Clone or copy the Prix Security System
if [ -d "prix" ]; then
    cp -r prix $INSTALL_DIR/
else
    git clone https://github.com/your-org/prix-security.git $INSTALL_DIR/prix
fi

cd $INSTALL_DIR/prix

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create configuration directories
sudo mkdir -p /etc/prix-security
sudo mkdir -p /var/log/prix-security
sudo mkdir -p /var/lib/prix-security

# Copy configuration files
sudo cp config/* /etc/prix-security/

# Create systemd service
sudo tee /etc/systemd/system/prix-security.service > /dev/null <<EOF
[Unit]
Description=Prix AI Security System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/prix
Environment=PATH=$INSTALL_DIR/prix/venv/bin
ExecStart=$INSTALL_DIR/prix/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable prix-security
sudo systemctl start prix-security

echo "Prix AI Security System installed successfully!"
echo "Service status: sudo systemctl status prix-security"
echo "Logs: sudo journalctl -u prix-security -f"
'''
        
        with open('install_linux.sh', 'w') as f:
            f.write(install_script)
        os.chmod('install_linux.sh', 0o755)
        
        # Generate control script
        control_script = '''#!/bin/bash
# Prix AI Security System - Linux Control Script

case "$1" in
    start)
        echo "Starting Prix Security System..."
        sudo systemctl start prix-security
        ;;
    stop)
        echo "Stopping Prix Security System..."
        sudo systemctl stop prix-security
        ;;
    restart)
        echo "Restarting Prix Security System..."
        sudo systemctl restart prix-security
        ;;
    status)
        sudo systemctl status prix-security
        ;;
    logs)
        sudo journalctl -u prix-security -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
'''
        
        with open('prix-control.sh', 'w') as f:
            f.write(control_script)
        os.chmod('prix-control.sh', 0o755)
        
        logger.info("Generated Linux deployment scripts")
    
    def _generate_windows_scripts(self, config: Dict):
        """Generate Windows deployment scripts"""
        # Generate PowerShell installation script
        install_script = '''# Prix AI Security System - Windows Installation Script
# Run as Administrator in PowerShell

Write-Host "Installing Prix AI Security System for Windows..." -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator" -ForegroundColor Red
    exit 1
}

# Create installation directory
$InstallDir = "C:\\Program Files\\PrixSecurity"
New-Item -ItemType Directory -Force -Path $InstallDir

# Create data directories
New-Item -ItemType Directory -Force -Path "C:\\ProgramData\\PrixSecurity\\config"
New-Item -ItemType Directory -Force -Path "C:\\ProgramData\\PrixSecurity\\logs"
New-Item -ItemType Directory -Force -Path "C:\\ProgramData\\PrixSecurity\\data"

# Copy Prix Security System files
if (Test-Path ".\\prix") {
    Copy-Item -Recurse -Force ".\\prix" "$InstallDir\\"
} else {
    Write-Host "Please ensure the prix directory is present" -ForegroundColor Red
    exit 1
}

Set-Location "$InstallDir\\prix"

# Create virtual environment
python -m venv venv
& ".\\venv\\Scripts\\Activate.ps1"

# Install Python dependencies
pip install -r requirements.txt

# Copy configuration files
Copy-Item -Force ".\\config\\*" "C:\\ProgramData\\PrixSecurity\\config\\"

# Create Windows service
$ServiceScript = @"
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
from main import PrixSecuritySystem
import time

system = PrixSecuritySystem()
system.start_monitoring()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    system.stop_monitoring()
"@

$ServiceScript | Out-File -FilePath "$InstallDir\\prix\\service.py" -Encoding UTF8

# Install service using NSSM (Non-Sucking Service Manager)
if (!(Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Host "Installing NSSM..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "nssm.zip"
    Expand-Archive -Path "nssm.zip" -DestinationPath "."
    Copy-Item ".\\nssm-2.24\\win64\\nssm.exe" "C:\\Windows\\System32\\"
    Remove-Item -Recurse -Force "nssm.zip", "nssm-2.24"
}

# Install service
nssm install PrixSecurity "C:\\Program Files\\PrixSecurity\\prix\\venv\\Scripts\\python.exe" "C:\\Program Files\\PrixSecurity\\prix\\service.py"
nssm set PrixSecurity DisplayName "Prix AI Security System"
nssm set PrixSecurity Description "Advanced AI-powered security monitoring system"
nssm set PrixSecurity Start SERVICE_AUTO_START

# Start service
nssm start PrixSecurity

Write-Host "Prix AI Security System installed successfully!" -ForegroundColor Green
Write-Host "Service status: Get-Service PrixSecurity" -ForegroundColor Cyan
Write-Host "To uninstall: nssm remove PrixSecurity" -ForegroundColor Cyan
'''
        
        with open('install_windows.ps1', 'w') as f:
            f.write(install_script)
        
        # Generate control script
        control_script = '''# Prix AI Security System - Windows Control Script

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "restart", "status", "logs", "uninstall")]
    [string]$Action
)

switch ($Action) {
    "start" {
        Write-Host "Starting Prix Security System..." -ForegroundColor Green
        nssm start PrixSecurity
    }
    "stop" {
        Write-Host "Stopping Prix Security System..." -ForegroundColor Yellow
        nssm stop PrixSecurity
    }
    "restart" {
        Write-Host "Restarting Prix Security System..." -ForegroundColor Yellow
        nssm restart PrixSecurity
    }
    "status" {
        Get-Service PrixSecurity
    }
    "logs" {
        Get-Content "C:\\ProgramData\\PrixSecurity\\logs\\prix.log" -Tail 50 -Wait
    }
    "uninstall" {
        Write-Host "Uninstalling Prix Security System..." -ForegroundColor Red
        nssm stop PrixSecurity
        nssm remove PrixSecurity confirm
        Remove-Item -Recurse -Force "C:\\Program Files\\PrixSecurity"
        Remove-Item -Recurse -Force "C:\\ProgramData\\PrixSecurity"
        Write-Host "Prix Security System uninstalled" -ForegroundColor Green
    }
}
'''
        
        with open('prix-control.ps1', 'w') as f:
            f.write(control_script)
        
        logger.info("Generated Windows deployment scripts")
    
    def _generate_macos_scripts(self, config: Dict):
        """Generate macOS deployment scripts"""
        # Generate installation script
        install_script = '''#!/bin/bash
# Prix AI Security System - macOS Installation Script

set -e

echo "Installing Prix AI Security System for macOS..."

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install Python 3
echo "Installing Python 3..."
brew install python3

# Create installation directory
INSTALL_DIR="/usr/local/prix-security"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:staff $INSTALL_DIR

# Clone or copy the Prix Security System
if [ -d "prix" ]; then
    cp -r prix $INSTALL_DIR/
else
    git clone https://github.com/your-org/prix-security.git $INSTALL_DIR/prix
fi

cd $INSTALL_DIR/prix

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create configuration directories
sudo mkdir -p "/Library/Application Support/PrixSecurity/config"
sudo mkdir -p "/Library/Logs/PrixSecurity"
sudo mkdir -p "/Library/Application Support/PrixSecurity/data"

# Copy configuration files
sudo cp config/* "/Library/Application Support/PrixSecurity/config/"

# Create launchd plist
sudo tee /Library/LaunchDaemons/com.prix.security.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.prix.security</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/prix/venv/bin/python</string>
        <string>$INSTALL_DIR/prix/main.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR/prix</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/PrixSecurity/prix.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/PrixSecurity/prix.error.log</string>
</dict>
</plist>
EOF

# Load and start service
sudo launchctl load /Library/LaunchDaemons/com.prix.security.plist

echo "Prix AI Security System installed successfully!"
echo "Service status: sudo launchctl list | grep com.prix.security"
echo "Logs: tail -f /Library/Logs/PrixSecurity/prix.log"
'''
        
        with open('install_macos.sh', 'w') as f:
            f.write(install_script)
        os.chmod('install_macos.sh', 0o755)
        
        # Generate control script
        control_script = '''#!/bin/bash
# Prix AI Security System - macOS Control Script

case "$1" in
    start)
        echo "Starting Prix Security System..."
        sudo launchctl load /Library/LaunchDaemons/com.prix.security.plist
        ;;
    stop)
        echo "Stopping Prix Security System..."
        sudo launchctl unload /Library/LaunchDaemons/com.prix.security.plist
        ;;
    restart)
        echo "Restarting Prix Security System..."
        sudo launchctl unload /Library/LaunchDaemons/com.prix.security.plist
        sleep 2
        sudo launchctl load /Library/LaunchDaemons/com.prix.security.plist
        ;;
    status)
        sudo launchctl list | grep com.prix.security
        ;;
    logs)
        tail -f /Library/Logs/PrixSecurity/prix.log
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
'''
        
        with open('prix-control.sh', 'w') as f:
            f.write(control_script)
        os.chmod('prix-control.sh', 0o755)
        
        logger.info("Generated macOS deployment scripts")
    
    def _generate_android_scripts(self, config: Dict):
        """Generate Android/Termux deployment scripts"""
        # Generate installation script
        install_script = '''#!/data/data/com.termux/files/usr/bin/bash
# Prix AI Security System - Android/Termux Installation Script

set -e

echo "Installing Prix AI Security System for Android/Termux..."

# Update packages
pkg update -y
pkg upgrade -y

# Install required packages
pkg install -y python git clang make libffi openssl-dev libjpeg-turbo-dev

# Create installation directory
INSTALL_DIR="$HOME/../data/data/com.termux/files/usr/opt/prix-security"
mkdir -p $INSTALL_DIR

# Clone or copy the Prix Security System
if [ -d "prix" ]; then
    cp -r prix $INSTALL_DIR/
else
    git clone https://github.com/your-org/prix-security.git $INSTALL_DIR/prix
fi

cd $INSTALL_DIR/prix

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create configuration directories
mkdir -p "$HOME/../data/data/com.termux/files/usr/etc/prix-security"
mkdir -p "$HOME/../data/data/com.termux/files/usr/var/log/prix-security"
mkdir -p "$HOME/../data/data/com.termux/files/usr/var/lib/prix-security"

# Copy configuration files
cp config/* "$HOME/../data/data/com.termux/files/usr/etc/prix-security/"

# Create Termux service script
cat > "$HOME/.termux/termux-service/prix-security" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
cd $INSTALL_DIR/prix
source venv/bin/activate
python main.py
EOF

chmod +x "$HOME/.termux/termux-service/prix-security"

# Create control script
cat > "$HOME/bin/prix-control" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
case "$1" in
    start)
        echo "Starting Prix Security System..."
        termux-service start prix-security
        ;;
    stop)
        echo "Stopping Prix Security System..."
        termux-service stop prix-security
        ;;
    restart)
        echo "Restarting Prix Security System..."
        termux-service restart prix-security
        ;;
    status)
        ps aux | grep prix-security | grep -v grep
        ;;
    logs)
        tail -f "$HOME/../data/data/com.termux/files/usr/var/log/prix-security/prix.log"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

chmod +x "$HOME/bin/prix-control"

echo "Prix AI Security System installed successfully!"
echo "Control: prix-control {start|stop|restart|status|logs}"
echo "Logs: prix-control logs"
'''
        
        with open('install_android.sh', 'w') as f:
            f.write(install_script)
        os.chmod('install_android.sh', 0o755)
        
        logger.info("Generated Android/Termux deployment scripts")
    
    def _generate_ios_scripts(self, config: Dict):
        """Generate iOS deployment configuration"""
        # iOS requires app packaging, not scripts
        ios_config = {
            'app_bundle': 'com.prix.security',
            'app_name': 'Prix Security',
            'version': '1.0.0',
            'minimum_ios_version': '13.0',
            'permissions': [
                'Network Monitoring',
                'File System Access',
                'Process Monitoring',
                'System Logs'
            ],
            'background_modes': [
                'Background Processing',
                'Network Monitoring',
                'File Protection'
            ]
        }
        
        with open('ios_config.json', 'w') as f:
            json.dump(ios_config, f, indent=2)
        
        logger.info("Generated iOS deployment configuration")
    
    def create_unified_launcher(self):
        """Create unified launcher script for all platforms"""
        launcher_script = '''#!/usr/bin/env python3
"""
Prix AI Security System - Unified Cross-Platform Launcher
Automatically detects platform and launches appropriate version
"""

import os
import sys
import platform
import subprocess
import logging
from pathlib import Path

def detect_platform():
    """Detect current platform"""
    system = platform.system().lower()
    
    if system == 'linux':
        return 'linux'
    elif system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'macos'
    elif 'ANDROID_ROOT' in os.environ or 'termux' in os.environ.get('PREFIX', ''):
        return 'android'
    elif 'iPhone' in platform.platform() or 'iPad' in platform.platform():
        return 'ios'
    else:
        return 'unknown'

def launch_prix_security():
    """Launch Prix Security System for detected platform"""
    platform_name = detect_platform()
    
    print(f"Detected platform: {platform_name}")
    
    if platform_name == 'linux':
        # Launch on Linux
        if os.path.exists('./main.py'):
            os.system('python3 main.py')
        else:
            print("Please navigate to the Prix Security directory")
            
    elif platform_name == 'windows':
        # Launch on Windows
        if os.path.exists('./main.py'):
            os.system('python main.py')
        else:
            print("Please navigate to the Prix Security directory")
            
    elif platform_name == 'macos':
        # Launch on macOS
        if os.path.exists('./main.py'):
            os.system('python3 main.py')
        else:
            print("Please navigate to the Prix Security directory")
            
    elif platform_name == 'android':
        # Launch on Android/Termux
        if os.path.exists('./main.py'):
            os.system('python main.py')
        else:
            print("Please navigate to the Prix Security directory")
            
    elif platform_name == 'ios':
        # iOS app launch (handled by app itself)
        print("Please launch the Prix Security app from your home screen")
        
    else:
        print(f"Unsupported platform: {platform_name}")
        print("Supported platforms: Linux, Windows, macOS, Android (Termux), iOS")

if __name__ == "__main__":
    launch_prix_security()
'''
        
        with open('prix-launcher.py', 'w') as f:
            f.write(launcher_script)
        os.chmod('prix-launcher.py', 0o755)
        
        logger.info("Created unified cross-platform launcher")
    
    def get_platform_compatibility_report(self) -> Dict:
        """Generate platform compatibility report"""
        report = {
            'current_platform': self.platform_info.platform,
            'architecture': self.platform_info.architecture,
            'supported_features': self.platform_info.supported_features,
            'installation_method': self.platform_info.installation_method,
            'shell_type': self.platform_info.shell_type,
            'package_manager': self.platform_info.package_manager,
            'service_manager': self.platform_info.service_manager,
            'all_supported_platforms': list(self.supported_platforms.keys())
        }
        
        return report


def main():
    """Main function for cross-platform management"""
    manager = CrossPlatformManager()
    
    print("Prix AI Security System - Cross-Platform Manager")
    print("=" * 50)
    
    # Generate platform-specific scripts
    manager.generate_platform_scripts()
    
    # Create unified launcher
    manager.create_unified_launcher()
    
    # Display platform information
    report = manager.get_platform_compatibility_report()
    print(f"Current Platform: {report['current_platform']}")
    print(f"Architecture: {report['architecture']}")
    print(f"Shell: {report['shell_type']}")
    print(f"Package Manager: {report['package_manager']}")
    print(f"Service Manager: {report['service_manager']}")
    print(f"Supported Features: {len(report['supported_features'])}")
    
    print("\nGenerated deployment scripts:")
    if report['current_platform'] == 'linux':
        print("- install_linux.sh (Linux installation)")
        print("- prix-control.sh (Linux control)")
    elif report['current_platform'] == 'windows':
        print("- install_windows.ps1 (Windows installation)")
        print("- prix-control.ps1 (Windows control)")
    elif report['current_platform'] == 'macos':
        print("- install_macos.sh (macOS installation)")
        print("- prix-control.sh (macOS control)")
    elif report['current_platform'] == 'android':
        print("- install_android.sh (Android/Termux installation)")
    elif report['current_platform'] == 'ios':
        print("- ios_config.json (iOS configuration)")
    
    print("- prix-launcher.py (Unified cross-platform launcher)")
    
    print(f"\nAll supported platforms: {', '.join(report['all_supported_platforms'])}")


if __name__ == "__main__":
    main()
