#!/bin/bash

# Prix AI Security System Installation Script
# This script automates the installation process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root - this is recommended for full system protection"
    else
        print_warning "Not running as root - some features may be limited"
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_success "pip3 found"
    else
        print_error "pip3 is required but not installed"
        exit 1
    fi
    
    # Check system type
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_success "Linux system detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_warning "macOS detected - some features may be limited"
    else
        print_warning "Unknown system - proceeding with caution"
    fi
}

# Install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Detect package manager
        if command -v apt-get &> /dev/null; then
            print_info "Using apt package manager..."
            sudo apt-get update
            sudo apt-get install -y python3-dev python3-pip sqlite3 libmagic1
        elif command -v yum &> /dev/null; then
            print_info "Using yum package manager..."
            sudo yum install -y python3-devel python3-pip sqlite libmagic
        elif command -v dnf &> /dev/null; then
            print_info "Using dnf package manager..."
            sudo dnf install -y python3-devel python3-pip sqlite libmagic
        else
            print_warning "Unknown package manager, skipping system dependencies"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            print_info "Using Homebrew..."
            brew install python3 sqlite libmagic
        else
            print_warning "Homebrew not found, please install system dependencies manually"
        fi
    fi
}

# Create directories
create_directories() {
    print_info "Creating directories..."
    
    directories=(
        "logs"
        "data"
        "quarantine"
        "templates"
        "static/css"
        "static/js"
        "static/images"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        print_success "Created directory: $dir"
    done
}

# Install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    if [[ -f "requirements.txt" ]]; then
        python3 -m pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Setup database
setup_database() {
    print_info "Setting up database..."
    
    python3 -c "
import sys
sys.path.append('.')
try:
    from main import DatabaseManager
    db = DatabaseManager()
    print('Database initialized successfully')
except Exception as e:
    print(f'Database setup failed: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        print_success "Database setup completed"
    else
        print_error "Database setup failed"
        exit 1
    fi
}

# Set permissions
set_permissions() {
    print_info "Setting permissions..."
    
    # Make scripts executable
    chmod +x *.py
    chmod +x install.sh
    
    # Set quarantine directory permissions
    if [[ -d "quarantine" ]]; then
        chmod 700 quarantine
        print_success "Quarantine directory secured"
    fi
    
    # Set log directory permissions
    if [[ -d "logs" ]]; then
        chmod 755 logs
        print_success "Log directory configured"
    fi
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_info "Skipping systemd service (not Linux)"
        return
    fi
    
    print_info "Creating systemd service..."
    
    SERVICE_CONTENT="[Unit]
Description=Prix AI Security System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=$(which python3) -m main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target"
    
    SERVICE_PATH="/etc/systemd/system/prix-security.service"
    
    if [[ $EUID -eq 0 ]]; then
        echo "$SERVICE_CONTENT" > "$SERVICE_PATH"
        print_success "Systemd service created: $SERVICE_PATH"
        print_info "To enable: systemctl enable prix-security"
        print_info "To start: systemctl start prix-security"
    else
        print_warning "Root access required for systemd service"
        print_info "To create manually, run: sudo ./install.sh"
    fi
}

# Create desktop entry
create_desktop_entry() {
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_info "Skipping desktop entry (not Linux)"
        return
    fi
    
    print_info "Creating desktop entry..."
    
    DESKTOP_DIR="$HOME/.local/share/applications"
    DESKTOP_FILE="$DESKTOP_DIR/prix-security.desktop"
    
    mkdir -p "$DESKTOP_DIR"
    
    DESKTOP_CONTENT="[Desktop Entry]
Version=1.0
Type=Application
Name=Prix Security Dashboard
Comment=AI Security System Dashboard
Exec=$(which python3) -m dashboard
Icon=security-high
Terminal=false
Categories=System;Security;"
    
    echo "$DESKTOP_CONTENT" > "$DESKTOP_FILE"
    print_success "Desktop entry created: $DESKTOP_FILE"
}

# Run tests
run_tests() {
    print_info "Running system tests..."
    
    python3 -c "
import sys
try:
    import psutil
    import sqlite3
    import flask
    print('✅ Core dependencies working')
    
    from main import DatabaseManager, SystemMonitor
    db = DatabaseManager()
    monitor = SystemMonitor(db)
    print('✅ Core components initialized')
    
    print('✅ All tests passed')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Test failed: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        print_success "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Create user config
create_user_config() {
    if [[ -f "user_config.py" ]]; then
        print_warning "user_config.py already exists"
        return
    fi
    
    print_info "Creating user configuration..."
    
    cat > user_config.py << 'EOF'
"""
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
EOF
    
    print_success "User configuration created: user_config.py"
}

# Print completion message
print_completion() {
    echo ""
    echo "============================================================"
    echo "🎉 Prix AI Security System Installation Complete!"
    echo "============================================================"
    echo ""
    echo "📋 Next Steps:"
    echo ""
    echo "1. Start the security system:"
    echo "   sudo python3 main.py"
    echo ""
    echo "2. Open the dashboard (in another terminal):"
    echo "   python3 dashboard.py"
    echo "   Then visit: http://localhost:5000"
    echo ""
    echo "3. Configure settings:"
    echo "   Edit user_config.py"
    echo ""
    echo "4. View logs:"
    echo "   tail -f prix_security.log"
    echo ""
    echo "⚠️  Important Notes:"
    echo "- Run as root for full system access"
    echo "- Configure firewall rules for network protection"
    echo "- Set up email notifications for alerts"
    echo ""
    echo "📚 Documentation: README.md"
    echo "🐛 Issues: https://github.com/prix-security/issues"
    echo ""
    echo "============================================================"
}

# Main installation process
main() {
    echo "🚀 Prix AI Security System Installation"
    echo "========================================"
    echo ""
    
    check_root
    check_requirements
    install_system_deps
    create_directories
    install_python_deps
    setup_database
    set_permissions
    create_systemd_service
    create_desktop_entry
    create_user_config
    run_tests
    print_completion
    
    echo ""
    print_success "Installation completed successfully!"
}

# Run installation
main "$@"
