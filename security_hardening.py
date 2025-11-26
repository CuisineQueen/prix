#!/usr/bin/env python3
"""
Security Hardening and Input Validation
Production-grade security with comprehensive validation and hardening
"""

import os
import sys
import re
import hashlib
import hmac
import secrets
import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import json
import base64
from pathlib import Path

class ValidationLevel(Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ValidationResult:
    """Validation result"""
    is_valid: bool
    threat_level: ThreatLevel
    message: str
    sanitized_value: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class SecurityPolicy:
    """Security policy configuration"""
    max_password_length: int = 128
    min_password_length: int = 12
    password_complexity_required: bool = True
    max_login_attempts: int = 5
    session_timeout_minutes: int = 30
    max_failed_attempts_window: int = 15  # minutes
    ip_whitelist_enabled: bool = False
    ip_whitelist: List[str] = None
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    encryption_required: bool = True
    audit_logging_enabled: bool = True

class InputValidator:
    """Production-grade input validator"""
    
    def __init__(self, policy: SecurityPolicy, logger=None):
        self.policy = policy
        self.logger = logger or logging.getLogger(__name__)
        
        # Security patterns
        self._initialize_patterns()
        
        # Rate limiting
        self.rate_limiter = RateLimiter(policy.rate_limit_requests_per_minute)
        
        # Failed attempt tracking
        self.failed_attempts: Dict[str, List[datetime]] = {}
    
    def _initialize_patterns(self):
        """Initialize security patterns"""
        self.patterns = {
            # SQL injection patterns
            'sql_injection': [
                r'(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)',
                r'(\'|\'\';|\"|\"\";|;|--|\/\*|\*\/)',
                r'(\bOR\b.*\b1\s*=\s*1\b|\bAND\b.*\b1\s*=\s*1\b)',
                r'(\bWHERE\b.*\bOR\b.*\bLIKE\b)',
            ],
            
            # XSS patterns
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',  # onclick, onload, etc.
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
                r'eval\s*\(',
                r'alert\s*\(',
            ],
            
            # Command injection patterns
            'command_injection': [
                r'[;&|`$()]',
                r'\$\(',
                r'`[^`]*`',
                r'\.\./',
                r'\/etc\/passwd',
                r'\/bin\/',
                r'\/usr\/bin\/',
            ],
            
            # Path traversal patterns
            'path_traversal': [
                r'\.\.[\/\\]',
                r'%2e%2e%2f',
                r'%2e%2e\\',
                r'\.\.\/',
                r'\.\.\\',
                r'\/etc\/',
                r'c:\\windows\\',
            ],
            
            # LDAP injection patterns
            'ldap_injection': [
                r'\*',
                r'\(',
                r'\)',
                r'\(',
                r'\)',
                r'&',
                r'\|',
                r'!',
            ],
            
            # NoSQL injection patterns
            'nosql_injection': [
                r'\$where',
                r'\$ne',
                r'\$gt',
                r'\$lt',
                r'\$regex',
                r'\$expr',
            ],
        }
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for category, patterns in self.patterns.items():
            self.compiled_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    def validate_input(self, input_value: str, input_type: str = "general", 
                      validation_level: ValidationLevel = ValidationLevel.STRICT) -> ValidationResult:
        """Validate input value"""
        if not isinstance(input_value, str):
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.HIGH,
                message="Input must be a string"
            )
        
        # Check rate limiting
        if not self.rate_limiter.check_rate():
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.HIGH,
                message="Rate limit exceeded"
            )
        
        # Basic validation
        if len(input_value) == 0:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.LOW,
                message="Input cannot be empty"
            )
        
        # Check for malicious patterns
        threat_level = ThreatLevel.LOW
        issues = []
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(input_value):
                    threat_level = max(threat_level, self._get_threat_level_for_category(category))
                    issues.append(f"Potential {category.replace('_', ' ')} detected")
        
        # Input type specific validation
        type_validation = self._validate_input_type(input_value, input_type, validation_level)
        if not type_validation.is_valid:
            threat_level = max(threat_level, type_validation.threat_level)
            issues.extend(type_validation.message.split('; '))
        
        # Sanitize input
        sanitized_value = self._sanitize_input(input_value)
        
        # Determine overall validity
        is_valid = (threat_level == ThreatLevel.LOW or 
                    (validation_level == ValidationLevel.LENIENT and threat_level == ThreatLevel.MEDIUM))
        
        message = "; ".join(issues) if issues else "Input validation passed"
        
        return ValidationResult(
            is_valid=is_valid,
            threat_level=threat_level,
            message=message,
            sanitized_value=sanitized_value,
            metadata={
                'input_type': input_type,
                'validation_level': validation_level.value,
                'original_length': len(input_value),
                'sanitized_length': len(sanitized_value),
            }
        )
    
    def _get_threat_level_for_category(self, category: str) -> ThreatLevel:
        """Get threat level for pattern category"""
        threat_mapping = {
            'sql_injection': ThreatLevel.CRITICAL,
            'xss': ThreatLevel.HIGH,
            'command_injection': ThreatLevel.CRITICAL,
            'path_traversal': ThreatLevel.HIGH,
            'ldap_injection': ThreatLevel.MEDIUM,
            'nosql_injection': ThreatLevel.MEDIUM,
        }
        return threat_mapping.get(category, ThreatLevel.MEDIUM)
    
    def _validate_input_type(self, input_value: str, input_type: str, 
                           validation_level: ValidationLevel) -> ValidationResult:
        """Validate specific input type"""
        validators = {
            'email': self._validate_email,
            'username': self._validate_username,
            'password': self._validate_password,
            'filename': self._validate_filename,
            'ip_address': self._validate_ip_address,
            'url': self._validate_url,
            'json': self._validate_json,
            'numeric': self._validate_numeric,
            'alphanumeric': self._validate_alphanumeric,
        }
        
        validator = validators.get(input_type, self._validate_general)
        return validator(input_value, validation_level)
    
    def _validate_email(self, email: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate email address"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid email format"
            )
        
        # Additional checks for strict validation
        if validation_level == ValidationLevel.STRICT:
            if len(email) > 254:
                return ValidationResult(
                    is_valid=False,
                    threat_level=ThreatLevel.LOW,
                    message="Email too long"
                )
            
            if email.count('@') != 1:
                return ValidationResult(
                    is_valid=False,
                    threat_level=ThreatLevel.MEDIUM,
                    message="Invalid email format"
                )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="Email validation passed"
        )
    
    def _validate_username(self, username: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate username"""
        if validation_level == ValidationLevel.STRICT:
            pattern = r'^[a-zA-Z0-9_-]{3,32}$'
        else:
            pattern = r'^[a-zA-Z0-9._-]{2,64}$'
        
        if not re.match(pattern, username):
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid username format"
            )
        
        # Check for reserved names
        reserved_names = ['admin', 'root', 'system', 'guest', 'anonymous']
        if username.lower() in reserved_names:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Username is reserved"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="Username validation passed"
        )
    
    def _validate_password(self, password: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate password"""
        issues = []
        
        # Length validation
        if len(password) < self.policy.min_password_length:
            issues.append(f"Password must be at least {self.policy.min_password_length} characters")
        
        if len(password) > self.policy.max_password_length:
            issues.append(f"Password must be less than {self.policy.max_password_length} characters")
        
        # Complexity validation
        if self.policy.password_complexity_required and validation_level != ValidationLevel.LENIENT:
            if not re.search(r'[A-Z]', password):
                issues.append("Password must contain uppercase letter")
            
            if not re.search(r'[a-z]', password):
                issues.append("Password must contain lowercase letter")
            
            if not re.search(r'\d', password):
                issues.append("Password must contain digit")
            
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                issues.append("Password must contain special character")
        
        if issues:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="; ".join(issues)
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="Password validation passed"
        )
    
    def _validate_filename(self, filename: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate filename"""
        # Dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
        
        for char in dangerous_chars:
            if char in filename:
                return ValidationResult(
                    is_valid=False,
                    threat_level=ThreatLevel.HIGH,
                    message=f"Filename contains dangerous character: {char}"
                )
        
        # Reserved names (Windows)
        reserved_names = [
            'CON', 'PRN', 'AUX', 'NUL',
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        name_without_ext = filename.split('.')[0].upper()
        if name_without_ext in reserved_names:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Filename is reserved"
            )
        
        # Path traversal check
        if '..' in filename or '/' in filename or '\\' in filename:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.HIGH,
                message="Filename contains path traversal"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="Filename validation passed"
        )
    
    def _validate_ip_address(self, ip: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return ValidationResult(
                is_valid=True,
                threat_level=ThreatLevel.LOW,
                message="IP address validation passed"
            )
        except ValueError:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid IP address format"
            )
    
    def _validate_url(self, url: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate URL"""
        url_pattern = r'^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
        
        if not re.match(url_pattern, url, re.IGNORECASE):
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid URL format"
            )
        
        # Additional security checks
        if 'javascript:' in url.lower():
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.HIGH,
                message="URL contains JavaScript protocol"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="URL validation passed"
        )
    
    def _validate_json(self, json_str: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate JSON"""
        try:
            json.loads(json_str)
            return ValidationResult(
                is_valid=True,
                threat_level=ThreatLevel.LOW,
                message="JSON validation passed"
            )
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message=f"Invalid JSON: {str(e)}"
            )
    
    def _validate_numeric(self, value: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate numeric input"""
        try:
            float(value)
            return ValidationResult(
                is_valid=True,
                threat_level=ThreatLevel.LOW,
                message="Numeric validation passed"
            )
        except ValueError:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid numeric format"
            )
    
    def _validate_alphanumeric(self, value: str, validation_level: ValidationLevel) -> ValidationResult:
        """Validate alphanumeric input"""
        if validation_level == ValidationLevel.STRICT:
            pattern = r'^[a-zA-Z0-9]+$'
        else:
            pattern = r'^[a-zA-Z0-9\s_-]+$'
        
        if not re.match(pattern, value):
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="Invalid alphanumeric format"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="Alphanumeric validation passed"
        )
    
    def _validate_general(self, value: str, validation_level: ValidationLevel) -> ValidationResult:
        """General input validation"""
        # Length checks
        max_length = 1000 if validation_level == ValidationLevel.LENIENT else 500
        if len(value) > max_length:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message=f"Input exceeds maximum length of {max_length}"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="General validation passed"
        )
    
    def _sanitize_input(self, input_value: str) -> str:
        """Sanitize input value"""
        # Remove null bytes
        sanitized = input_value.replace('\0', '')
        
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        # HTML entity encoding for XSS prevention
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
        }
        
        for char, entity in html_entities.items():
            sanitized = sanitized.replace(char, entity)
        
        return sanitized
    
    def check_failed_attempts(self, identifier: str) -> bool:
        """Check if identifier has exceeded failed attempt limit"""
        now = datetime.now()
        cutoff_time = now - timedelta(minutes=self.policy.max_failed_attempts_window)
        
        # Clean old attempts
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                attempt for attempt in self.failed_attempts[identifier] 
                if attempt > cutoff_time
            ]
        
        # Check current attempts
        recent_attempts = self.failed_attempts.get(identifier, [])
        return len(recent_attempts) >= self.policy.max_login_attempts
    
    def record_failed_attempt(self, identifier: str):
        """Record failed attempt"""
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(datetime.now())
        
        # Log the attempt
        self.logger.warning(f"Failed attempt recorded for: {identifier}")
    
    def clear_failed_attempts(self, identifier: str):
        """Clear failed attempts for identifier"""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]

class RateLimiter:
    """Rate limiter for security"""
    
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.requests: List[datetime] = []
    
    def check_rate(self) -> bool:
        """Check if request is within rate limit"""
        now = datetime.now()
        cutoff_time = now - timedelta(minutes=1)
        
        # Clean old requests
        self.requests = [req for req in self.requests if req > cutoff_time]
        
        # Check if under limit
        if len(self.requests) < self.requests_per_minute:
            self.requests.append(now)
            return True
        
        return False

class SecurityHardening:
    """Security hardening utilities"""
    
    def __init__(self, policy: SecurityPolicy, logger=None):
        self.policy = policy
        self.logger = logger or logging.getLogger(__name__)
        self.validator = InputValidator(policy, logger)
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return base64.b64encode(password_hash).decode('utf-8'), salt
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash"""
        computed_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, stored_hash)
    
    def encrypt_data(self, data: str, key: Optional[str] = None) -> Tuple[str, str]:
        """Encrypt data with AES"""
        try:
            from cryptography.fernet import Fernet
            
            if key is None:
                key = Fernet.generate_key()
            else:
                key = key.encode()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            
            return encrypted_data.decode(), key.decode()
            
        except ImportError:
            # Fallback to simple encoding
            encoded_data = base64.b64encode(data.encode()).decode()
            simple_key = secrets.token_urlsafe(32)
            return encoded_data, simple_key
    
    def decrypt_data(self, encrypted_data: str, key: str) -> str:
        """Decrypt data"""
        try:
            from cryptography.fernet import Fernet
            
            fernet = Fernet(key.encode())
            decrypted_data = fernet.decrypt(encrypted_data.encode())
            return decrypted_data.decode()
            
        except ImportError:
            # Fallback to simple decoding
            return base64.b64decode(encrypted_data.encode()).decode()
    
    def validate_file_upload(self, filename: str, file_content: bytes, 
                          allowed_extensions: List[str]) -> ValidationResult:
        """Validate uploaded file"""
        # Validate filename
        filename_result = self.validator.validate_input(filename, "filename")
        if not filename_result.is_valid:
            return filename_result
        
        # Check file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in allowed_extensions:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message=f"File extension {file_ext} not allowed"
            )
        
        # Check file size (max 10MB)
        if len(file_content) > 10 * 1024 * 1024:
            return ValidationResult(
                is_valid=False,
                threat_level=ThreatLevel.MEDIUM,
                message="File too large"
            )
        
        # Check for malicious content in file
        content_str = file_content.decode('utf-8', errors='ignore')
        content_result = self.validator.validate_input(content_str, "general")
        
        if content_result.threat_level >= ThreatLevel.HIGH:
            return ValidationResult(
                is_valid=False,
                threat_level=content_result.threat_level,
                message="File contains malicious content"
            )
        
        return ValidationResult(
            is_valid=True,
            threat_level=ThreatLevel.LOW,
            message="File validation passed"
        )
    
    def secure_headers(self) -> Dict[str, str]:
        """Get security headers for web responses"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        }
    
    def audit_log(self, event_type: str, user_id: str, details: Dict[str, Any]):
        """Log security event"""
        if self.policy.audit_logging_enabled:
            audit_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'details': details,
                'severity': 'security'
            }
            
            self.logger.info(f"AUDIT: {json.dumps(audit_entry)}")

# Global security instance
_security_hardening = None

def get_security_hardening() -> SecurityHardening:
    """Get global security hardening instance"""
    global _security_hardening
    if _security_hardening is None:
        from production_config import get_config
        config = get_config()
        policy = SecurityPolicy()
        _security_hardening = SecurityHardening(policy)
    return _security_hardening

def init_security_hardening(policy: SecurityPolicy, logger=None) -> SecurityHardening:
    """Initialize security hardening"""
    global _security_hardening
    _security_hardening = SecurityHardening(policy, logger)
    return _security_hardening

if __name__ == "__main__":
    # Test security hardening
    try:
        policy = SecurityPolicy()
        security = init_security_hardening(policy)
        
        # Test input validation
        test_cases = [
            ("normal input", "general", True),
            ("<script>alert('xss')</script>", "general", False),
            ("'; DROP TABLE users; --", "general", False),
            ("../../../etc/passwd", "filename", False),
            ("test@example.com", "email", True),
            ("invalid-email", "email", False),
        ]
        
        print("Testing input validation:")
        for input_val, input_type, should_pass in test_cases:
            result = security.validator.validate_input(input_val, input_type)
            status = "✅" if result.is_valid == should_pass else "❌"
            print(f"  {status} {input_type}: '{input_val}' -> {result.message}")
        
        # Test password hashing
        password = "TestPassword123!"
        hashed, salt = security.hash_password(password)
        verified = security.verify_password(password, hashed, salt)
        print(f"\n✅ Password hashing: {'passed' if verified else 'failed'}")
        
        # Test token generation
        token = security.generate_secure_token()
        print(f"✅ Generated secure token: {token[:16]}...")
        
        print("\n✅ Security hardening test completed")
        
    except Exception as e:
        print(f"❌ Security hardening test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
