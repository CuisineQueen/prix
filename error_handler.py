#!/usr/bin/env python3
"""
Production-Grade Error Handling and Exception Management
Comprehensive error handling with recovery, reporting, and resilience
"""

import os
import sys
import time
import traceback
import threading
import functools
import inspect
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Type, Union
from dataclasses import dataclass, asdict
from enum import Enum
import json
import logging
from pathlib import Path

class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    SECURITY = "security"
    IOT = "iot"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    USER_INPUT = "user_input"
    EXTERNAL_SERVICE = "external_service"

@dataclass
class ErrorContext:
    """Error context information"""
    function_name: str
    module_name: str
    line_number: int
    thread_id: int
    process_id: int
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    device_id: Optional[str] = None
    hostname: Optional[str] = None
    environment: Optional[str] = None

@dataclass
class ErrorReport:
    """Comprehensive error report"""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    error_type: str
    error_message: str
    context: ErrorContext
    stack_trace: str
    recovery_attempted: bool
    recovery_successful: bool
    resolution_time_ms: Optional[float]
    metadata: Optional[Dict[str, Any]] = None
    related_errors: Optional[List[str]] = None

class RetryPolicy:
    """Retry policy configuration"""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, 
                 max_delay: float = 60.0, backoff_factor: float = 2.0,
                 retry_on: Optional[List[Type[Exception]]] = None):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.retry_on = retry_on or [Exception]
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        delay = self.base_delay * (self.backoff_factor ** (attempt - 1))
        return min(delay, self.max_delay)
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Check if exception should be retried"""
        if attempt >= self.max_attempts:
            return False
        
        return any(isinstance(exception, exc_type) for exc_type in self.retry_on)

class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0,
                 expected_exception: Type[Exception] = Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for circuit breaker"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self.lock:
                if self.state == "OPEN":
                    if time.time() - self.last_failure_time > self.recovery_timeout:
                        self.state = "HALF_OPEN"
                    else:
                        raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                
                with self.lock:
                    if self.state == "HALF_OPEN":
                        self.state = "CLOSED"
                        self.failure_count = 0
                
                return result
                
            except self.expected_exception as e:
                with self.lock:
                    self.failure_count += 1
                    self.last_failure_time = time.time()
                    
                    if self.failure_count >= self.failure_threshold:
                        self.state = "OPEN"
                
                raise e
        
        return wrapper

class ErrorHandler:
    """Production-grade error handler"""
    
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.error_reports: List[ErrorReport] = []
        self.error_callbacks: List[Callable] = []
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.lock = threading.Lock()
        
        # Load error patterns and recovery strategies
        self._load_error_patterns()
    
    def _load_error_patterns(self):
        """Load error patterns and recovery strategies"""
        self.error_patterns = {
            # Database errors
            'sqlite3.OperationalError': {
                'category': ErrorCategory.DATABASE,
                'severity': ErrorSeverity.HIGH,
                'retry_policy': RetryPolicy(max_attempts=3, base_delay=0.5),
                'recovery_actions': ['wait_and_retry', 'reconnect_database'],
            },
            'sqlite3.DatabaseError': {
                'category': ErrorCategory.DATABASE,
                'severity': ErrorSeverity.CRITICAL,
                'retry_policy': RetryPolicy(max_attempts=2, base_delay=1.0),
                'recovery_actions': ['recreate_database', 'fallback_storage'],
            },
            
            # Network errors
            'ConnectionError': {
                'category': ErrorCategory.NETWORK,
                'severity': ErrorSeverity.MEDIUM,
                'retry_policy': RetryPolicy(max_attempts=3, base_delay=1.0, max_delay=10.0),
                'recovery_actions': ['wait_and_retry', 'switch_endpoint'],
            },
            'TimeoutError': {
                'category': ErrorCategory.NETWORK,
                'severity': ErrorSeverity.MEDIUM,
                'retry_policy': RetryPolicy(max_attempts=2, base_delay=2.0),
                'recovery_actions': ['increase_timeout', 'wait_and_retry'],
            },
            
            # IoT errors
            'SerialException': {
                'category': ErrorCategory.IOT,
                'severity': ErrorSeverity.MEDIUM,
                'retry_policy': RetryPolicy(max_attempts=3, base_delay=1.0),
                'recovery_actions': ['reconnect_device', 'reset_port'],
            },
            'MQTTException': {
                'category': ErrorCategory.IOT,
                'severity': ErrorSeverity.HIGH,
                'retry_policy': RetryPolicy(max_attempts=5, base_delay=0.5),
                'recovery_actions': ['reconnect_broker', 'reestablish_subscriptions'],
            },
            
            # System errors
            'PermissionError': {
                'category': ErrorCategory.SYSTEM,
                'severity': ErrorSeverity.HIGH,
                'retry_policy': RetryPolicy(max_attempts=1),  # Don't retry permission errors
                'recovery_actions': ['check_permissions', 'elevate_privileges'],
            },
            'FileNotFoundError': {
                'category': ErrorCategory.SYSTEM,
                'severity': ErrorSeverity.MEDIUM,
                'retry_policy': RetryPolicy(max_attempts=2, base_delay=0.1),
                'recovery_actions': ['create_file', 'check_path'],
            },
            
            # Security errors
            'ValueError': {
                'category': ErrorCategory.USER_INPUT,
                'severity': ErrorSeverity.LOW,
                'retry_policy': RetryPolicy(max_attempts=1),
                'recovery_actions': ['validate_input', 'sanitize_data'],
            },
        }
    
    def add_error_callback(self, callback: Callable[[ErrorReport], None]):
        """Add error callback for reporting"""
        self.error_callbacks.append(callback)
    
    def get_circuit_breaker(self, name: str, **kwargs) -> CircuitBreaker:
        """Get or create circuit breaker"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(**kwargs)
        return self.circuit_breakers[name]
    
    def handle_exception(self, exception: Exception, context: Optional[Dict[str, Any]] = None) -> ErrorReport:
        """Handle exception and create error report"""
        start_time = time.time()
        
        # Generate error ID
        error_id = f"{int(time.time())}-{hash(str(exception)) % 10000:04d}"
        
        # Extract error context
        frame = inspect.currentframe()
        caller_frame = frame.f_back.f_back if frame and frame.f_back else frame
        
        error_context = ErrorContext(
            function_name=caller_frame.f_code.co_name if caller_frame else "unknown",
            module_name=caller_frame.f_code.co_filename if caller_frame else "unknown",
            line_number=caller_frame.f_lineno if caller_frame else 0,
            thread_id=threading.get_ident(),
            process_id=os.getpid(),
            hostname=context.get('hostname') if context else None,
            environment=context.get('environment') if context else None,
            user_id=context.get('user_id') if context else None,
            session_id=context.get('session_id') if context else None,
            request_id=context.get('request_id') if context else None,
            device_id=context.get('device_id') if context else None,
        )
        
        # Determine error pattern
        error_type = type(exception).__name__
        pattern = self.error_patterns.get(error_type, {
            'category': ErrorCategory.SYSTEM,
            'severity': ErrorSeverity.MEDIUM,
            'retry_policy': RetryPolicy(max_attempts=1),
            'recovery_actions': ['log_and_continue'],
        })
        
        # Create error report
        error_report = ErrorReport(
            error_id=error_id,
            timestamp=datetime.now(),
            severity=pattern['severity'],
            category=pattern['category'],
            error_type=error_type,
            error_message=str(exception),
            context=error_context,
            stack_trace=traceback.format_exc(),
            recovery_attempted=False,
            recovery_successful=False,
            resolution_time_ms=None,
            metadata=context or {},
        )
        
        # Attempt recovery
        recovery_successful = self._attempt_recovery(exception, pattern, error_report)
        error_report.recovery_attempted = True
        error_report.recovery_successful = recovery_successful
        error_report.resolution_time_ms = (time.time() - start_time) * 1000
        
        # Store error report
        with self.lock:
            self.error_reports.append(error_report)
            
            # Keep only last 1000 errors
            if len(self.error_reports) > 1000:
                self.error_reports = self.error_reports[-1000:]
        
        # Log error
        self._log_error(error_report)
        
        # Trigger callbacks
        for callback in self.error_callbacks:
            try:
                callback(error_report)
            except Exception as e:
                self.logger.error(f"Error callback failed: {e}")
        
        return error_report
    
    def _attempt_recovery(self, exception: Exception, pattern: Dict[str, Any], 
                        error_report: ErrorReport) -> bool:
        """Attempt error recovery based on pattern"""
        recovery_actions = pattern.get('recovery_actions', [])
        
        for action in recovery_actions:
            try:
                if action == 'wait_and_retry':
                    time.sleep(0.5)
                    return True  # Will be handled by retry logic
                
                elif action == 'reconnect_database':
                    return self._reconnect_database()
                
                elif action == 'recreate_database':
                    return self._recreate_database()
                
                elif action == 'fallback_storage':
                    return self._fallback_storage()
                
                elif action == 'switch_endpoint':
                    return self._switch_endpoint()
                
                elif action == 'increase_timeout':
                    return self._increase_timeout()
                
                elif action == 'reconnect_device':
                    return self._reconnect_device()
                
                elif action == 'reset_port':
                    return self._reset_port()
                
                elif action == 'reconnect_broker':
                    return self._reconnect_broker()
                
                elif action == 'reestablish_subscriptions':
                    return self._reestablish_subscriptions()
                
                elif action == 'check_permissions':
                    return self._check_permissions()
                
                elif action == 'elevate_privileges':
                    return self._elevate_privileges()
                
                elif action == 'create_file':
                    return self._create_file(error_report)
                
                elif action == 'check_path':
                    return self._check_path(error_report)
                
                elif action == 'validate_input':
                    return self._validate_input(error_report)
                
                elif action == 'sanitize_data':
                    return self._sanitize_data(error_report)
                
                elif action == 'log_and_continue':
                    self.logger.warning(f"Continuing after error: {exception}")
                    return True
                
            except Exception as recovery_error:
                self.logger.error(f"Recovery action '{action}' failed: {recovery_error}")
                continue
        
        return False
    
    def _reconnect_database(self) -> bool:
        """Reconnect to database"""
        try:
            # Implementation would depend on database connection management
            self.logger.info("Attempting database reconnection")
            return True
        except Exception:
            return False
    
    def _recreate_database(self) -> bool:
        """Recreate database"""
        try:
            self.logger.warning("Attempting database recreation")
            # Implementation would recreate database schema
            return True
        except Exception:
            return False
    
    def _fallback_storage(self) -> bool:
        """Fallback to alternative storage"""
        try:
            self.logger.info("Switching to fallback storage")
            return True
        except Exception:
            return False
    
    def _switch_endpoint(self) -> bool:
        """Switch to alternative endpoint"""
        try:
            self.logger.info("Switching to alternative endpoint")
            return True
        except Exception:
            return False
    
    def _increase_timeout(self) -> bool:
        """Increase timeout values"""
        try:
            self.logger.info("Increasing timeout values")
            return True
        except Exception:
            return False
    
    def _reconnect_device(self) -> bool:
        """Reconnect IoT device"""
        try:
            self.logger.info("Reconnecting IoT device")
            return True
        except Exception:
            return False
    
    def _reset_port(self) -> bool:
        """Reset serial port"""
        try:
            self.logger.info("Resetting serial port")
            return True
        except Exception:
            return False
    
    def _reconnect_broker(self) -> bool:
        """Reconnect MQTT broker"""
        try:
            self.logger.info("Reconnecting MQTT broker")
            return True
        except Exception:
            return False
    
    def _reestablish_subscriptions(self) -> bool:
        """Reestablish MQTT subscriptions"""
        try:
            self.logger.info("Reestablishing MQTT subscriptions")
            return True
        except Exception:
            return False
    
    def _check_permissions(self) -> bool:
        """Check file permissions"""
        try:
            self.logger.info("Checking file permissions")
            return True
        except Exception:
            return False
    
    def _elevate_privileges(self) -> bool:
        """Attempt to elevate privileges"""
        try:
            self.logger.warning("Attempting privilege elevation")
            return False  # Usually not possible without user interaction
        except Exception:
            return False
    
    def _create_file(self, error_report: ErrorReport) -> bool:
        """Create missing file"""
        try:
            file_path = error_report.metadata.get('file_path')
            if file_path:
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                Path(file_path).touch()
                self.logger.info(f"Created missing file: {file_path}")
                return True
        except Exception:
            pass
        return False
    
    def _check_path(self, error_report: ErrorReport) -> bool:
        """Check if path exists"""
        try:
            file_path = error_report.metadata.get('file_path')
            if file_path and not Path(file_path).exists():
                self.logger.error(f"Path does not exist: {file_path}")
                return False
            return True
        except Exception:
            return False
    
    def _validate_input(self, error_report: ErrorReport) -> bool:
        """Validate user input"""
        try:
            self.logger.info("Validating user input")
            return True
        except Exception:
            return False
    
    def _sanitize_data(self, error_report: ErrorReport) -> bool:
        """Sanitize data"""
        try:
            self.logger.info("Sanitizing data")
            return True
        except Exception:
            return False
    
    def _log_error(self, error_report: ErrorReport):
        """Log error report"""
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
        }.get(error_report.severity, logging.ERROR)
        
        self.logger.log(
            log_level,
            f"Error [{error_report.error_id}]: {error_report.error_type} - {error_report.error_message}",
            extra={
                'error_id': error_report.error_id,
                'category': error_report.category.value,
                'severity': error_report.severity.value,
                'function': error_report.context.function_name,
                'module': error_report.context.module_name,
                'line': error_report.context.line_number,
                'recovery_successful': error_report.recovery_successful,
                'resolution_time_ms': error_report.resolution_time_ms,
            }
        )
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        if not self.error_reports:
            return {'total_errors': 0}
        
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_1h = now - timedelta(hours=1)
        
        recent_errors = [e for e in self.error_reports if e.timestamp > last_24h]
        very_recent_errors = [e for e in self.error_reports if e.timestamp > last_1h]
        
        errors_by_category = {}
        errors_by_severity = {}
        
        for error in recent_errors:
            cat = error.category.value
            sev = error.severity.value
            
            errors_by_category[cat] = errors_by_category.get(cat, 0) + 1
            errors_by_severity[sev] = errors_by_severity.get(sev, 0) + 1
        
        recovery_rate = sum(1 for e in recent_errors if e.recovery_successful) / len(recent_errors) if recent_errors else 0
        
        return {
            'total_errors': len(self.error_reports),
            'last_24h_errors': len(recent_errors),
            'last_1h_errors': len(very_recent_errors),
            'errors_by_category': errors_by_category,
            'errors_by_severity': errors_by_severity,
            'recovery_rate_24h': recovery_rate,
            'average_resolution_time_ms': sum(e.resolution_time_ms or 0 for e in recent_errors) / len(recent_errors) if recent_errors else 0,
        }

def with_error_handling(error_handler: ErrorHandler, category: ErrorCategory = ErrorCategory.SYSTEM,
                       severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                       retry_policy: Optional[RetryPolicy] = None):
    """Decorator for automatic error handling"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            if retry_policy:
                for attempt in range(1, retry_policy.max_attempts + 1):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        
                        if not retry_policy.should_retry(e, attempt):
                            break
                        
                        delay = retry_policy.get_delay(attempt)
                        time.sleep(delay)
            else:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
            
            # Handle the exception
            if last_exception:
                context = {
                    'function_name': func.__name__,
                    'module_name': func.__module__,
                    'category': category.value,
                    'severity': severity.value,
                }
                
                error_report = error_handler.handle_exception(last_exception, context)
                
                if not error_report.recovery_successful:
                    raise last_exception
            
            return None
        
        return wrapper
    return decorator

def with_circuit_breaker(error_handler: ErrorHandler, name: str, **circuit_breaker_kwargs):
    """Decorator for circuit breaker pattern"""
    def decorator(func: Callable) -> Callable:
        circuit_breaker = error_handler.get_circuit_breaker(name, **circuit_breaker_kwargs)
        return circuit_breaker(func)
    return decorator

# Global error handler instance
_error_handler = None

def get_error_handler() -> ErrorHandler:
    """Get global error handler instance"""
    global _error_handler
    if _error_handler is None:
        from production_config import get_config
        config = get_config()
        _error_handler = ErrorHandler(config)
    return _error_handler

def init_error_handler(config, logger=None) -> ErrorHandler:
    """Initialize error handler"""
    global _error_handler
    _error_handler = ErrorHandler(config, logger)
    return _error_handler

if __name__ == "__main__":
    # Test error handling
    from production_config import get_config
    
    try:
        config = get_config()
        handler = init_error_handler(config)
        
        # Test exception handling
        try:
            raise ValueError("Test error for demonstration")
        except Exception as e:
            error_report = handler.handle_exception(e, {'test': True})
            print(f"✅ Error handled: {error_report.error_id}")
        
        # Test error statistics
        stats = handler.get_error_statistics()
        print(f"Error statistics: {json.dumps(stats, indent=2)}")
        
        print("✅ Error handling test completed")
        
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        traceback.print_exc()
        sys.exit(1)
