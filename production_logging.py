#!/usr/bin/env python3
"""
Production-Grade Logging System
Structured logging with rotation, monitoring, and alerting
"""

import os
import sys
import json
import time
import logging
import logging.handlers
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import traceback
import socket
import psutil

class LogLevel(Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"

class LogCategory(Enum):
    SYSTEM = "system"
    SECURITY = "security"
    THREAT = "threat"
    IOT = "iot"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    NETWORK = "network"
    DATABASE = "database"

@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: str
    level: str
    category: str
    message: str
    module: str
    function: str
    line: int
    thread_id: int
    process_id: int
    hostname: str
    environment: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    device_id: Optional[str] = None
    threat_id: Optional[str] = None
    execution_time_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None
    network_bytes_sent: Optional[int] = None
    network_bytes_recv: Optional[int] = None
    error_code: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for production logging"""
    
    def __init__(self, include_extra_fields: bool = True):
        super().__init__()
        self.include_extra_fields = include_extra_fields
        self.hostname = socket.gethostname()
        self.environment = os.environ.get('PRIX_ENV', 'production')
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        # Basic log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'category': getattr(record, 'category', 'system'),
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread_id': record.thread,
            'process_id': record.process,
            'hostname': self.hostname,
            'environment': self.environment,
        }
        
        # Add optional fields if they exist
        optional_fields = [
            'user_id', 'session_id', 'request_id', 'device_id', 'threat_id',
            'execution_time_ms', 'memory_usage_mb', 'cpu_usage_percent',
            'disk_usage_percent', 'network_bytes_sent', 'network_bytes_recv',
            'error_code', 'stack_trace', 'metadata'
        ]
        
        for field in optional_fields:
            if hasattr(record, field):
                value = getattr(record, field)
                if value is not None:
                    log_entry[field] = value
        
        # Add extra fields if enabled
        if self.include_extra_fields:
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                              'pathname', 'filename', 'module', 'lineno', 
                              'funcName', 'created', 'msecs', 'relativeCreated', 
                              'thread', 'threadName', 'processName', 'process',
                              'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                    if not key.startswith('_'):
                        log_entry[f'extra_{key}'] = value
        
        # Add stack trace for exceptions
        if record.exc_info:
            log_entry['stack_trace'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

class AlertHandler(logging.Handler):
    """Alert handler for critical log entries"""
    
    def __init__(self, alert_thresholds: Dict[str, int]):
        super().__init__()
        self.alert_thresholds = alert_thresholds
        self.alert_counts = {level: 0 for level in LogLevel}
        self.last_reset = time.time()
        self.reset_interval = 300  # 5 minutes
        self.alert_callbacks: List[callable] = []
    
    def emit(self, record: logging.LogRecord):
        """Emit log record and check alerts"""
        level_name = record.levelname
        
        if level_name in self.alert_thresholds:
            self.alert_counts[level_name] += 1
            
            # Check if threshold exceeded
            if self.alert_counts[level_name] >= self.alert_thresholds[level_name]:
                self._trigger_alert(level_name, record)
        
        # Reset counters periodically
        if time.time() - self.last_reset > self.reset_interval:
            self._reset_counters()
    
    def _trigger_alert(self, level: str, record: logging.LogRecord):
        """Trigger alert for threshold exceeded"""
        alert_data = {
            'level': level,
            'count': self.alert_counts[level],
            'threshold': self.alert_thresholds[level],
            'message': f"Alert: {level} threshold exceeded",
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
        }
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                print(f"Alert callback failed: {e}")
        
        # Log the alert
        print(json.dumps(alert_data))
    
    def _reset_counters(self):
        """Reset alert counters"""
        self.alert_counts = {level: 0 for level in LogLevel}
        self.last_reset = time.time()
    
    def add_alert_callback(self, callback: callable):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)

class MetricsCollector:
    """Collects performance metrics for logging"""
    
    def __init__(self):
        self.start_time = time.time()
        self.process = psutil.Process()
        self.initial_network = psutil.net_io_counters()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Disk
            disk = psutil.disk_usage('/')
            
            # Network
            network = psutil.net_io_counters()
            network_sent = network.bytes_sent - self.initial_network.bytes_sent
            network_recv = network.bytes_recv - self.initial_network.bytes_recv
            
            # Process-specific
            process_memory = self.process.memory_info()
            process_cpu = self.process.cpu_percent()
            
            return {
                'cpu_usage_percent': cpu_percent,
                'memory_usage_percent': memory.percent,
                'disk_usage_percent': disk.percent,
                'memory_usage_mb': process_memory.rss / (1024 * 1024),
                'process_cpu_percent': process_cpu,
                'network_bytes_sent': network_sent,
                'network_bytes_recv': network_recv,
                'uptime_seconds': time.time() - self.start_time,
            }
        except Exception as e:
            return {'error': str(e)}

class ProductionLogger:
    """Production-grade logging system"""
    
    def __init__(self, config):
        self.config = config
        self.loggers: Dict[str, logging.Logger] = {}
        self.metrics_collector = MetricsCollector()
        self.alert_handler = AlertHandler({
            'CRITICAL': 1,
            'ERROR': 5,
            'WARNING': 10,
        })
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create log directory
        log_dir = Path(self.config.logging.file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config.logging.level))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            filename=self.config.logging.file_path,
            maxBytes=self.config.logging.max_file_size,
            backupCount=self.config.logging.backup_count,
            encoding='utf-8'
        )
        
        if self.config.logging.structured_logging:
            file_handler.setFormatter(StructuredFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(self.config.logging.format))
        
        root_logger.addHandler(file_handler)
        
        # Console handler if enabled
        if self.config.logging.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            if self.config.logging.structured_logging:
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(logging.Formatter(self.config.logging.format))
            root_logger.addHandler(console_handler)
        
        # Syslog handler if enabled
        if self.config.logging.log_to_syslog:
            try:
                syslog_handler = logging.handlers.SysLogHandler('/dev/log')
                syslog_handler.setFormatter(logging.Formatter(
                    'prix-security[%(process)d]: %(name)s - %(levelname)s - %(message)s'
                ))
                root_logger.addHandler(syslog_handler)
            except Exception as e:
                print(f"Failed to setup syslog: {e}")
        
        # Alert handler
        root_logger.addHandler(self.alert_handler)
        
        # Create category-specific loggers
        for category in LogCategory:
            logger = logging.getLogger(f'prix.{category.value}')
            self.loggers[category.value] = logger
    
    def get_logger(self, category: str = 'system') -> logging.Logger:
        """Get logger for specific category"""
        return self.loggers.get(category, logging.getLogger('prix.system'))
    
    def log_with_context(self, level: str, category: str, message: str, **context):
        """Log with additional context"""
        logger = self.get_logger(category)
        
        # Add metrics to context
        metrics = self.metrics_collector.get_metrics()
        context.update(metrics)
        
        # Log the message
        log_method = getattr(logger, level.lower())
        log_method(message, extra=context)
    
    def log_security_event(self, event_type: str, severity: str, description: str, **context):
        """Log security event"""
        context.update({
            'event_type': event_type,
            'severity': severity,
            'category': 'security',
        })
        
        level = 'CRITICAL' if severity.upper() == 'CRITICAL' else 'ERROR'
        self.log_with_context(level, 'security', description, **context)
    
    def log_threat_detected(self, threat_type: str, threat_id: str, description: str, **context):
        """Log threat detection"""
        context.update({
            'threat_type': threat_type,
            'threat_id': threat_id,
            'category': 'threat',
        })
        
        self.log_with_context('WARNING', 'threat', description, **context)
    
    def log_iot_event(self, device_id: str, event_type: str, message: str, **context):
        """Log IoT event"""
        context.update({
            'device_id': device_id,
            'event_type': event_type,
            'category': 'iot',
        })
        
        self.log_with_context('INFO', 'iot', message, **context)
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str, **context):
        """Log performance metric"""
        context.update({
            'metric_name': metric_name,
            'metric_value': value,
            'metric_unit': unit,
            'category': 'performance',
        })
        
        self.log_with_context('INFO', 'performance', f"Performance: {metric_name} = {value} {unit}", **context)
    
    def log_audit_event(self, action: str, user_id: str, resource: str, result: str, **context):
        """Log audit event"""
        context.update({
            'action': action,
            'user_id': user_id,
            'resource': resource,
            'result': result,
            'category': 'audit',
        })
        
        self.log_with_context('INFO', 'audit', f"Audit: {user_id} {action} {resource} -> {result}", **context)
    
    def create_execution_logger(self, category: str = 'system'):
        """Create logger that tracks execution time"""
        class ExecutionLogger:
            def __init__(self, parent_logger, metrics_collector):
                self.parent_logger = parent_logger
                self.metrics_collector = metrics_collector
            
            def __enter__(self):
                self.start_time = time.time()
                return self
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                execution_time = (time.time() - self.start_time) * 1000
                
                if exc_type:
                    self.parent_logger.error(
                        f"Execution failed after {execution_time:.2f}ms",
                        extra={
                            'execution_time_ms': execution_time,
                            'error_type': exc_type.__name__ if exc_type else None,
                            'error_message': str(exc_val) if exc_val else None,
                            **self.metrics_collector.get_metrics()
                        },
                        exc_info=True
                    )
                else:
                    self.parent_logger.info(
                        f"Execution completed in {execution_time:.2f}ms",
                        extra={
                            'execution_time_ms': execution_time,
                            **self.metrics_collector.get_metrics()
                        }
                    )
        
        return ExecutionLogger(self.get_logger(category), self.metrics_collector)
    
    def add_alert_callback(self, callback: callable):
        """Add alert callback function"""
        self.alert_handler.add_alert_callback(callback)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        stats = {
            'alert_counts': self.alert_handler.alert_counts,
            'log_level': self.config.logging.level,
            'log_file': self.config.logging.file_path,
            'structured_logging': self.config.logging.structured_logging,
            'metrics': self.metrics_collector.get_metrics(),
        }
        
        # Log file size
        try:
            log_file = Path(self.config.logging.file_path)
            if log_file.exists():
                stats['log_file_size_mb'] = log_file.stat().st_size / (1024 * 1024)
        except Exception:
            pass
        
        return stats

# Global logger instance
_production_logger = None

def get_logger(category: str = 'system') -> logging.Logger:
    """Get production logger"""
    global _production_logger
    if _production_logger is None:
        from production_config import get_config
        config = get_config()
        _production_logger = ProductionLogger(config)
    return _production_logger.get_logger(category)

def init_logging(config):
    """Initialize production logging"""
    global _production_logger
    _production_logger = ProductionLogger(config)
    return _production_logger

if __name__ == "__main__":
    # Test logging system
    from production_config import get_config
    
    try:
        config = get_config()
        logger = init_logging(config)
        
        # Test different log types
        logger.log_with_context('INFO', 'system', 'Production logging system initialized')
        logger.log_security_event('login_attempt', 'INFO', 'User login successful', user_id='test_user')
        logger.log_threat_detected('malware', 'THREAT-001', 'Suspicious file detected', file_path='/tmp/suspicious.exe')
        logger.log_iot_event('device-001', 'connection', 'IoT device connected')
        logger.log_performance_metric('response_time', 150.5, 'ms')
        logger.log_audit_event('file_access', 'user-001', '/etc/passwd', 'success')
        
        # Test execution logger
        with logger.create_execution_logger('system') as exec_logger:
            time.sleep(0.1)  # Simulate work
        
        print("✅ Production logging test completed")
        print(f"Log stats: {json.dumps(logger.get_log_stats(), indent=2)}")
        
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        traceback.print_exc()
        sys.exit(1)
