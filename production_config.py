#!/usr/bin/env python3
"""
Production Configuration Management
Handles environment-based configuration for production deployment
"""

import os
import sys
import logging
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

@dataclass
class DatabaseConfig:
    """Database configuration"""
    host: str = "localhost"
    port: int = 5432
    name: str = "prix_security"
    user: str = "prix_user"
    password: str = ""
    ssl_mode: str = "require"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "/var/log/prix-security/prix.log"
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    backup_count: int = 10
    console_output: bool = True
    structured_logging: bool = True
    log_to_syslog: bool = False

@dataclass
class SecurityConfig:
    """Security configuration"""
    encryption_key_rotation_days: int = 90
    session_timeout_minutes: int = 30
    max_login_attempts: int = 5
    password_min_length: int = 12
    require_2fa: bool = True
    audit_log_retention_days: int = 365
    threat_intelligence_update_interval_minutes: int = 15

@dataclass
class MonitoringConfig:
    """Monitoring configuration"""
    health_check_interval_seconds: int = 30
    metrics_collection_interval_seconds: int = 60
    alert_threshold_cpu_percent: float = 80.0
    alert_threshold_memory_percent: float = 85.0
    alert_threshold_disk_percent: float = 90.0
    performance_metrics_retention_days: int = 30

@dataclass
class IoTConfig:
    """IoT configuration"""
    max_devices: int = 1000
    device_timeout_seconds: int = 300
    sensor_data_retention_days: int = 90
    mqtt_broker_host: str = "localhost"
    mqtt_broker_port: int = 1883
    mqtt_tls_enabled: bool = True
    device_discovery_interval_minutes: int = 5

@dataclass
class ProductionConfig:
    """Production configuration container"""
    environment: Environment = Environment.PRODUCTION
    debug: bool = False
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    iot: IoTConfig = field(default_factory=IoTConfig)
    
    # Paths
    base_path: str = "/opt/prix-security"
    config_path: str = "/etc/prix-security"
    log_path: str = "/var/log/prix-security"
    data_path: str = "/var/lib/prix-security"
    run_path: str = "/var/run/prix-security"
    
    # Performance
    worker_processes: int = 4
    max_connections: int = 1000
    request_timeout_seconds: int = 30
    
    # Security
    secret_key: str = ""
    api_key: str = ""
    encryption_key: str = ""

class ConfigManager:
    """Production configuration manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_file()
        self.config = ProductionConfig()
        self._load_configuration()
        self._validate_configuration()
    
    def _get_default_config_file(self) -> str:
        """Get default configuration file path"""
        env = os.environ.get('PRIX_ENV', 'production').lower()
        
        config_paths = [
            f"/etc/prix-security/config_{env}.yaml",
            f"/etc/prix-security/config.yaml",
            os.path.expanduser(f"~/.prix/config_{env}.yaml"),
            os.path.expanduser("~/.prix/config.yaml"),
            "config.yaml",
            f"config_{env}.yaml"
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                return path
        
        return config_paths[0]  # Return default path
    
    def _load_configuration(self):
        """Load configuration from file and environment"""
        # Load from file if exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
                    self._update_config_from_dict(file_config)
            except Exception as e:
                logging.warning(f"Failed to load config file {self.config_file}: {e}")
        
        # Override with environment variables
        self._load_from_environment()
    
    def _update_config_from_dict(self, config_dict: Dict[str, Any]):
        """Update configuration from dictionary"""
        if 'environment' in config_dict:
            self.config.environment = Environment(config_dict['environment'])
        
        if 'debug' in config_dict:
            self.config.debug = config_dict['debug']
        
        # Database config
        if 'database' in config_dict:
            db_config = config_dict['database']
            for key, value in db_config.items():
                if hasattr(self.config.database, key):
                    setattr(self.config.database, key, value)
        
        # Logging config
        if 'logging' in config_dict:
            log_config = config_dict['logging']
            for key, value in log_config.items():
                if hasattr(self.config.logging, key):
                    setattr(self.config.logging, key, value)
        
        # Security config
        if 'security' in config_dict:
            sec_config = config_dict['security']
            for key, value in sec_config.items():
                if hasattr(self.config.security, key):
                    setattr(self.config.security, key, value)
        
        # Monitoring config
        if 'monitoring' in config_dict:
            mon_config = config_dict['monitoring']
            for key, value in mon_config.items():
                if hasattr(self.config.monitoring, key):
                    setattr(self.config.monitoring, key, value)
        
        # IoT config
        if 'iot' in config_dict:
            iot_config = config_dict['iot']
            for key, value in iot_config.items():
                if hasattr(self.config.iot, key):
                    setattr(self.config.iot, key, value)
        
        # Paths
        path_keys = ['base_path', 'config_path', 'log_path', 'data_path', 'run_path']
        for key in path_keys:
            if key in config_dict:
                setattr(self.config, key, config_dict[key])
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        env_mappings = {
            # General
            'PRIX_ENV': ('environment', lambda x: Environment(x.lower())),
            'PRIX_DEBUG': ('debug', lambda x: x.lower() in ['true', '1', 'yes']),
            
            # Database
            'PRIX_DB_HOST': ('database.host', str),
            'PRIX_DB_PORT': ('database.port', int),
            'PRIX_DB_NAME': ('database.name', str),
            'PRIX_DB_USER': ('database.user', str),
            'PRIX_DB_PASSWORD': ('database.password', str),
            'PRIX_DB_SSL_MODE': ('database.ssl_mode', str),
            
            # Logging
            'PRIX_LOG_LEVEL': ('logging.level', str),
            'PRIX_LOG_FILE': ('logging.file_path', str),
            'PRIX_LOG_MAX_SIZE': ('logging.max_file_size', int),
            'PRIX_LOG_BACKUP_COUNT': ('logging.backup_count', int),
            
            # Security
            'PRIX_SECRET_KEY': ('secret_key', str),
            'PRIX_API_KEY': ('api_key', str),
            'PRIX_ENCRYPTION_KEY': ('encryption_key', str),
            'PRIX_SESSION_TIMEOUT': ('security.session_timeout_minutes', int),
            
            # IoT
            'PRIX_IOT_MAX_DEVICES': ('iot.max_devices', int),
            'PRIX_MQTT_HOST': ('iot.mqtt_broker_host', str),
            'PRIX_MQTT_PORT': ('iot.mqtt_broker_port', int),
            
            # Paths
            'PRIX_BASE_PATH': ('base_path', str),
            'PRIX_CONFIG_PATH': ('config_path', str),
            'PRIX_LOG_PATH': ('log_path', str),
            'PRIX_DATA_PATH': ('data_path', str),
        }
        
        for env_var, (config_path, converter) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    converted_value = converter(value)
                    self._set_nested_value(config_path, converted_value)
                except (ValueError, AttributeError) as e:
                    logging.warning(f"Invalid environment variable {env_var}={value}: {e}")
    
    def _set_nested_value(self, path: str, value: Any):
        """Set nested configuration value using dot notation"""
        parts = path.split('.')
        obj = self.config
        
        for part in parts[:-1]:
            obj = getattr(obj, part)
        
        setattr(obj, parts[-1], value)
    
    def _validate_configuration(self):
        """Validate configuration values"""
        errors = []
        
        # Validate paths exist or can be created
        path_attrs = ['base_path', 'config_path', 'log_path', 'data_path', 'run_path']
        for attr in path_attrs:
            path = getattr(self.config, attr)
            try:
                Path(path).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create path {attr}={path}: {e}")
        
        # Validate required security values
        if not self.config.secret_key and self.config.environment == Environment.PRODUCTION:
            errors.append("PRIX_SECRET_KEY is required in production")
        
        if not self.config.encryption_key and self.config.environment == Environment.PRODUCTION:
            errors.append("PRIX_ENCRYPTION_KEY is required in production")
        
        # Validate numeric ranges
        if self.config.monitoring.alert_threshold_cpu_percent < 0 or self.config.monitoring.alert_threshold_cpu_percent > 100:
            errors.append("CPU alert threshold must be between 0 and 100")
        
        if self.config.iot.max_devices <= 0:
            errors.append("Max IoT devices must be positive")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors)
            raise ValueError(error_msg)
    
    def get_config(self) -> ProductionConfig:
        """Get production configuration"""
        return self.config
    
    def create_directories(self):
        """Create necessary directories"""
        directories = [
            self.config.base_path,
            self.config.config_path,
            self.config.log_path,
            self.config.data_path,
            self.config.run_path,
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                logging.info(f"Created directory: {directory}")
            except Exception as e:
                logging.error(f"Failed to create directory {directory}: {e}")
                raise
    
    def save_config(self, file_path: Optional[str] = None):
        """Save configuration to file"""
        save_path = file_path or self.config_file
        
        config_dict = {
            'environment': self.config.environment.value,
            'debug': self.config.debug,
            'database': {
                'host': self.config.database.host,
                'port': self.config.database.port,
                'name': self.config.database.name,
                'user': self.config.database.user,
                'ssl_mode': self.config.database.ssl_mode,
                'pool_size': self.config.database.pool_size,
                'max_overflow': self.config.database.max_overflow,
                'pool_timeout': self.config.database.pool_timeout,
                'pool_recycle': self.config.database.pool_recycle,
            },
            'logging': {
                'level': self.config.logging.level,
                'format': self.config.logging.format,
                'file_path': self.config.logging.file_path,
                'max_file_size': self.config.logging.max_file_size,
                'backup_count': self.config.logging.backup_count,
                'console_output': self.config.logging.console_output,
                'structured_logging': self.config.logging.structured_logging,
                'log_to_syslog': self.config.logging.log_to_syslog,
            },
            'security': {
                'encryption_key_rotation_days': self.config.security.encryption_key_rotation_days,
                'session_timeout_minutes': self.config.security.session_timeout_minutes,
                'max_login_attempts': self.config.security.max_login_attempts,
                'password_min_length': self.config.security.password_min_length,
                'require_2fa': self.config.security.require_2fa,
                'audit_log_retention_days': self.config.security.audit_log_retention_days,
                'threat_intelligence_update_interval_minutes': self.config.security.threat_intelligence_update_interval_minutes,
            },
            'monitoring': {
                'health_check_interval_seconds': self.config.monitoring.health_check_interval_seconds,
                'metrics_collection_interval_seconds': self.config.monitoring.metrics_collection_interval_seconds,
                'alert_threshold_cpu_percent': self.config.monitoring.alert_threshold_cpu_percent,
                'alert_threshold_memory_percent': self.config.monitoring.alert_threshold_memory_percent,
                'alert_threshold_disk_percent': self.config.monitoring.alert_threshold_disk_percent,
                'performance_metrics_retention_days': self.config.monitoring.performance_metrics_retention_days,
            },
            'iot': {
                'max_devices': self.config.iot.max_devices,
                'device_timeout_seconds': self.config.iot.device_timeout_seconds,
                'sensor_data_retention_days': self.config.iot.sensor_data_retention_days,
                'mqtt_broker_host': self.config.iot.mqtt_broker_host,
                'mqtt_broker_port': self.config.iot.mqtt_broker_port,
                'mqtt_tls_enabled': self.config.iot.mqtt_tls_enabled,
                'device_discovery_interval_minutes': self.config.iot.device_discovery_interval_minutes,
            },
            'base_path': self.config.base_path,
            'config_path': self.config.config_path,
            'log_path': self.config.log_path,
            'data_path': self.config.data_path,
            'run_path': self.config.run_path,
            'worker_processes': self.config.worker_processes,
            'max_connections': self.config.max_connections,
            'request_timeout_seconds': self.config.request_timeout_seconds,
        }
        
        try:
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            logging.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logging.error(f"Failed to save configuration to {save_path}: {e}")
            raise

# Global configuration instance
_config_manager = None

def get_config() -> ProductionConfig:
    """Get global configuration instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.get_config()

def init_config(config_file: Optional[str] = None) -> ProductionConfig:
    """Initialize configuration"""
    global _config_manager
    _config_manager = ConfigManager(config_file)
    return _config_manager.get_config()

if __name__ == "__main__":
    # Test configuration loading
    try:
        config = get_config()
        print("✅ Configuration loaded successfully")
        print(f"Environment: {config.environment}")
        print(f"Debug: {config.debug}")
        print(f"Log level: {config.logging.level}")
        print(f"Database: {config.database.host}:{config.database.port}/{config.database.name}")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        sys.exit(1)
