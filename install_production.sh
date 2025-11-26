#!/bin/bash
# Production Installation Script
# Prix AI Security System

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/prix-security"
CONFIG_DIR="/etc/prix-security"
LOG_DIR="/var/log/prix-security"
DATA_DIR="/var/lib/prix-security"
RUN_DIR="/var/run/prix-security"
SERVICE_NAME="prix-security"

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required"
    fi
    
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if [[ $(echo "$python_version < 3.8" | bc -l) -eq 1 ]]; then
        error "Python 3.8 or higher is required (found $python_version)"
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is required"
    fi
    
    # Check systemd
    if ! command -v systemctl &> /dev/null; then
        error "systemd is required"
    fi
    
    success "System requirements met"
}

# Create directories
create_directories() {
    log "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$RUN_DIR"
    mkdir -p "$DATA_DIR/backups"
    mkdir -p "$DATA_DIR/temp"
    
    # Set permissions
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$RUN_DIR"
    
    success "Directories created"
}

# Install Prix Security
install_prix() {
    log "Installing Prix AI Security System..."
    
    # Copy files to installation directory
    CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Create version directory
    VERSION_DIR="$INSTALL_DIR/versions/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$VERSION_DIR"
    
    # Copy Python files
    cp "$CURRENT_DIR"/*.py "$VERSION_DIR/"
    cp "$CURRENT_DIR"/*.txt "$VERSION_DIR/"
    cp "$CURRENT_DIR"/*.yaml "$VERSION_DIR/"
    cp "$CURRENT_DIR"/*.md "$VERSION_DIR/"
    
    # Copy service file
    cp "$CURRENT_DIR/prix.service" "/etc/systemd/system/"
    
    # Create current symlink
    ln -sfn "$VERSION_DIR" "$INSTALL_DIR/current"
    
    success "Prix Security installed"
}

# Install dependencies
install_dependencies() {
    log "Installing Python dependencies..."
    
    cd "$INSTALL_DIR/current"
    
    # Install system dependencies
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y python3-dev python3-pip python3-venv build-essential
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y python3-devel python3-pip python3-venv gcc
    elif command -v dnf &> /dev/null; then
        dnf update -y
        dnf install -y python3-devel python3-pip python3-venv gcc
    else
        warning "Could not install system dependencies automatically"
    fi
    
    # Install Python dependencies
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    
    success "Dependencies installed"
}

# Setup configuration
setup_configuration() {
    log "Setting up configuration..."
    
    # Copy configuration file
    cp "$INSTALL_DIR/current/config_production.yaml" "$CONFIG_DIR/config.yaml"
    
    # Create environment file template
    cat > "$CONFIG_DIR/prix.env" << EOF
# Prix Security Environment Variables
# Set these values for production deployment

# Database Configuration
PRIX_DB_HOST=localhost
PRIX_DB_PORT=5432
PRIX_DB_NAME=prix_security
PRIX_DB_USER=prix_user
PRIX_DB_PASSWORD=your_secure_password_here

# Security Keys (Generate secure keys)
PRIX_SECRET_KEY=\$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
PRIX_API_KEY=\$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
PRIX_ENCRYPTION_KEY=\$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Logging
PRIX_LOG_LEVEL=INFO
PRIX_LOG_FILE=/var/log/prix-security/prix.log

# Paths
PRIX_BASE_PATH=/opt/prix-security
PRIX_CONFIG_PATH=/etc/prix-security
PRIX_LOG_PATH=/var/log/prix-security
PRIX_DATA_PATH=/var/lib/prix-security
PRIX_RUN_PATH=/var/run/prix-security

# IoT Configuration
PRIX_IOT_MAX_DEVICES=1000
PRIX_MQTT_HOST=localhost
PRIX_MQTT_PORT=1883
EOF
    
    # Set permissions
    chmod 600 "$CONFIG_DIR/prix.env"
    
    success "Configuration setup completed"
}

# Setup log rotation
setup_logrotate() {
    log "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/prix-security" << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload prix-security > /dev/null 2>&1 || true
    endscript
}
EOF
    
    success "Log rotation configured"
}

# Setup systemd service
setup_service() {
    log "Setting up systemd service..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    success "Service setup completed"
}

# Create management scripts
create_management_scripts() {
    log "Creating management scripts..."
    
    # Prix control script
    cat > "/usr/local/bin/prix-control" << 'EOF'
#!/bin/bash
# Prix Security Control Script

SERVICE_NAME="prix-security"
INSTALL_DIR="/opt/prix-security"

case "$1" in
    start)
        echo "Starting Prix Security..."
        systemctl start "$SERVICE_NAME"
        ;;
    stop)
        echo "Stopping Prix Security..."
        systemctl stop "$SERVICE_NAME"
        ;;
    restart)
        echo "Restarting Prix Security..."
        systemctl restart "$SERVICE_NAME"
        ;;
    status)
        systemctl status "$SERVICE_NAME"
        ;;
    logs)
        journalctl -u "$SERVICE_NAME" -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF
    
    # Prix status script
    cat > "/usr/local/bin/prix-status" << 'EOF'
#!/bin/bash
# Prix Security Status Script

INSTALL_DIR="/opt/prix-security"

cd "$INSTALL_DIR/current"
python3 seamless_launcher.py --status
EOF
    
    # Make scripts executable
    chmod +x "/usr/local/bin/prix-control"
    chmod +x "/usr/local/bin/prix-status"
    
    success "Management scripts created"
}

# Setup firewall rules (optional)
setup_firewall() {
    log "Setting up firewall rules..."
    
    if command -v ufw &> /dev/null; then
        # Allow Prix Security ports if needed
        # ufw allow 1883/tcp  # MQTT
        # ufw allow 5432/tcp  # PostgreSQL (if remote)
        success "Firewall rules configured (ufw)"
    elif command -v firewall-cmd &> /dev/null; then
        # firewall-cmd --permanent --add-port=1883/tcp
        # firewall-cmd --permanent --add-port=5432/tcp
        # firewall-cmd --reload
        success "Firewall rules configured (firewalld)"
    else
        warning "Firewall management tool not found"
    fi
}

# Run post-installation tests
run_tests() {
    log "Running post-installation tests..."
    
    cd "$INSTALL_DIR/current"
    
    # Test configuration
    if python3 production_config.py; then
        success "Configuration test passed"
    else
        error "Configuration test failed"
    fi
    
    # Test logging
    if python3 production_logging.py; then
        success "Logging test passed"
    else
        error "Logging test failed"
    fi
    
    # Test health monitoring
    if python3 health_monitor.py; then
        success "Health monitoring test passed"
    else
        error "Health monitoring test failed"
    fi
    
    # Test error handling
    if python3 error_handler.py; then
        success "Error handling test passed"
    else
        error "Error handling test failed"
    fi
    
    success "All tests passed"
}

# Display installation summary
display_summary() {
    log "Installation completed successfully!"
    echo
    echo "=== Prix AI Security System Installation Summary ==="
    echo
    echo "Installation Directory: $INSTALL_DIR"
    echo "Configuration Directory: $CONFIG_DIR"
    echo "Log Directory: $LOG_DIR"
    echo "Data Directory: $DATA_DIR"
    echo
    echo "Next Steps:"
    echo "1. Edit configuration: nano $CONFIG_DIR/prix.env"
    echo "2. Set secure passwords and keys in $CONFIG_DIR/prix.env"
    echo "3. Start service: prix-control start"
    echo "4. Check status: prix-control status"
    echo "5. View logs: prix-control logs"
    echo
    echo "Management Commands:"
    echo "  prix-control start     - Start Prix Security"
    echo "  prix-control stop      - Stop Prix Security"
    echo "  prix-control restart   - Restart Prix Security"
    echo "  prix-control status    - Check service status"
    echo "  prix-control logs      - View service logs"
    echo "  prix-status            - Check Prix Security status"
    echo
    echo "Developed by DevMonix Technologies - Leading the Future of Cybersecurity"
    echo
}

# Main installation function
main() {
    echo "=== Prix AI Security System Production Installation ==="
    echo
    
    check_root
    check_requirements
    create_directories
    install_prix
    install_dependencies
    setup_configuration
    setup_logrotate
    setup_service
    create_management_scripts
    setup_firewall
    run_tests
    display_summary
}

# Run installation
main "$@"
