#!/usr/bin/env python3
"""
Advanced Zero-Trust Architecture System
Multi-factor authentication, continuous verification, and least-privilege access control
"""

import os
import sys
import time
import threading
import logging
import json
import hashlib
import hmac
import base64
import secrets
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# Security libraries
try:
    import cryptography
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Installing cryptography library...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "pyjwt", "bcrypt"])
    import cryptography
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import jwt
    import bcrypt

logger = logging.getLogger(__name__)

@dataclass
class ZeroTrustPrincipal:
    """Zero-trust principal (user, device, service)"""
    principal_id: str
    principal_type: str  # user, device, service, api_key
    name: str
    credentials: Dict
    attributes: Dict
    trust_score: float
    last_verified: datetime
    risk_level: str
    permissions: Set[str]

@dataclass
class ZeroTrustPolicy:
    """Zero-trust access policy"""
    policy_id: str
    name: str
    description: str
    conditions: List[Dict]
    actions: List[str]
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

@dataclass
class ZeroTrustSession:
    """Zero-trust session"""
    session_id: str
    principal_id: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    context: Dict
    trust_level: str
    permissions: Set[str]
    is_active: bool

@dataclass
class ZeroTrustEvent:
    """Zero-trust security event"""
    timestamp: datetime
    event_type: str
    principal_id: str
    resource: str
    action: str
    result: str
    risk_score: float
    details: Dict
    mitigation: str

class ZeroTrustArchitecture:
    """Advanced zero-trust architecture system"""
    
    def __init__(self, db_path: str = "prix_zerotrust.db"):
        self.db_path = db_path
        self.monitoring = False
        
        # Zero-trust components
        self.principals = {}
        self.policies = {}
        self.sessions = {}
        self.trust_engine = None
        self.risk_analyzer = None
        
        # Security parameters
        self.jwt_secret = self._generate_jwt_secret()
        self.session_timeout = 3600  # 1 hour
        self.max_failed_attempts = 3
        self.lockout_duration = 900  # 15 minutes
        
        # Trust thresholds
        self.trust_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.9
        }
        
        # Risk factors
        self.risk_factors = {
            'unknown_device': 0.4,
            'unusual_location': 0.3,
            'failed_auth': 0.5,
            'time_anomaly': 0.2,
            'behavior_anomaly': 0.3,
            'privilege_escalation': 0.6
        }
        
        # Initialize zero-trust system
        self.init_database()
        self.init_trust_engine()
        self.init_risk_analyzer()
        self.load_default_policies()
        self.start_continuous_monitoring()
    
    def init_database(self):
        """Initialize zero-trust database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Principals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_principals (
                principal_id TEXT PRIMARY KEY,
                principal_type TEXT,
                name TEXT,
                credentials TEXT,
                attributes TEXT,
                trust_score REAL,
                last_verified TEXT,
                risk_level TEXT,
                permissions TEXT,
                created_at TEXT,
                updated_at TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Policies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                conditions TEXT,
                actions TEXT,
                priority INTEGER,
                enabled BOOLEAN DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_sessions (
                session_id TEXT PRIMARY KEY,
                principal_id TEXT,
                created_at TEXT,
                expires_at TEXT,
                last_activity TEXT,
                context TEXT,
                trust_level TEXT,
                permissions TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                principal_id TEXT,
                resource TEXT,
                action TEXT,
                result TEXT,
                risk_score REAL,
                details TEXT,
                mitigation TEXT
            )
        ''')
        
        # Trust assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trust_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                principal_id TEXT,
                assessment_type TEXT,
                trust_score REAL,
                risk_factors TEXT,
                timestamp TEXT,
                context TEXT
            )
        ''')
        
        # Access requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                principal_id TEXT,
                resource TEXT,
                action TEXT,
                context TEXT,
                decision TEXT,
                reason TEXT,
                timestamp TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def init_trust_engine(self):
        """Initialize trust scoring engine"""
        self.trust_engine = TrustEngine(self.trust_thresholds, self.risk_factors)
        logger.info("Trust engine initialized")
    
    def init_risk_analyzer(self):
        """Initialize risk analysis engine"""
        self.risk_analyzer = RiskAnalyzer(self.risk_factors)
        logger.info("Risk analyzer initialized")
    
    def load_default_policies(self):
        """Load default zero-trust policies"""
        default_policies = [
            ZeroTrustPolicy(
                policy_id="default_deny",
                name="Default Deny",
                description="Default deny all access",
                conditions=[],
                actions=["deny"],
                priority=999,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            ZeroTrustPolicy(
                policy_id="require_mfa",
                name="Require MFA",
                description="Require multi-factor authentication for sensitive operations",
                conditions=[
                    {"field": "action", "operator": "in", "value": ["delete", "modify", "admin"]},
                    {"field": "trust_score", "operator": "<", "value": 0.8}
                ],
                actions=["require_mfa", "deny"],
                priority=100,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            ZeroTrustPolicy(
                policy_id="least_privilege",
                name="Least Privilege",
                description="Enforce least privilege access",
                conditions=[
                    {"field": "permissions", "operator": "contains", "value": "required_permission"}
                ],
                actions=["allow"],
                priority=50,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            ZeroTrustPolicy(
                policy_id="time_based_access",
                name="Time-based Access",
                description="Restrict access based on time",
                conditions=[
                    {"field": "hour", "operator": "between", "value": [9, 17]},
                    {"field": "day_of_week", "operator": "in", "value": [0, 1, 2, 3, 4]}
                ],
                actions=["allow"],
                priority=75,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            ZeroTrustPolicy(
                policy_id="location_based_access",
                name="Location-based Access",
                description="Restrict access based on location",
                conditions=[
                    {"field": "location", "operator": "in", "value": ["trusted_network"]}
                ],
                actions=["allow"],
                priority=80,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        for policy in default_policies:
            self.policies[policy.policy_id] = policy
            self._store_policy(policy)
        
        logger.info(f"Loaded {len(default_policies)} default policies")
    
    def _store_policy(self, policy: ZeroTrustPolicy):
        """Store policy in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO zero_trust_policies 
            (policy_id, name, description, conditions, actions, priority, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            policy.policy_id,
            policy.name,
            policy.description,
            json.dumps(policy.conditions),
            json.dumps(policy.actions),
            policy.priority,
            policy.enabled,
            policy.created_at.isoformat(),
            policy.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring"""
        self.monitoring = True
        logger.info("Starting continuous zero-trust monitoring...")
        
        # Start monitoring threads
        threading.Thread(target=self._session_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._trust_monitoring_loop, daemon=True).start()
        threading.Thread(targetself._risk_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._policy_enforcement_loop, daemon=True).start()
        
        logger.info("Zero-trust monitoring started")
    
    def create_principal(self, principal_type: str, name: str, credentials: Dict, 
                        attributes: Dict, permissions: Set[str]) -> str:
        """Create new zero-trust principal"""
        principal_id = self._generate_principal_id()
        
        # Hash passwords if provided
        if 'password' in credentials:
            credentials['password_hash'] = bcrypt.hashpw(
                credentials['password'].encode(), bcrypt.gensalt()
            ).decode()
            del credentials['password']
        
        principal = ZeroTrustPrincipal(
            principal_id=principal_id,
            principal_type=principal_type,
            name=name,
            credentials=credentials,
            attributes=attributes,
            trust_score=0.5,  # Start with neutral trust
            last_verified=datetime.now(),
            risk_level="medium",
            permissions=permissions
        )
        
        self.principals[principal_id] = principal
        self._store_principal(principal)
        
        logger.info(f"Created {principal_type} principal: {name} ({principal_id})")
        return principal_id
    
    def _generate_principal_id(self) -> str:
        """Generate unique principal ID"""
        return f"principal_{secrets.token_hex(16)}"
    
    def _store_principal(self, principal: ZeroTrustPrincipal):
        """Store principal in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO zero_trust_principals 
            (principal_id, principal_type, name, credentials, attributes, trust_score,
             last_verified, risk_level, permissions, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            principal.principal_id,
            principal.principal_type,
            principal.name,
            json.dumps(principal.credentials),
            json.dumps(principal.attributes),
            principal.trust_score,
            principal.last_verified.isoformat(),
            principal.risk_level,
            json.dumps(list(principal.permissions)),
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            True
        ))
        
        conn.commit()
        conn.close()
    
    def authenticate_principal(self, principal_id: str, credentials: Dict, 
                             context: Dict) -> Dict:
        """Authenticate principal with zero-trust verification"""
        try:
            # Get principal
            principal = self.principals.get(principal_id)
            if not principal:
                return {
                    'success': False,
                    'reason': 'principal_not_found',
                    'trust_score': 0.0
                }
            
            # Verify credentials
            if not self._verify_credentials(principal, credentials):
                self._handle_failed_authentication(principal_id, context)
                return {
                    'success': False,
                    'reason': 'invalid_credentials',
                    'trust_score': principal.trust_score
                }
            
            # Perform continuous verification
            verification_result = self._continuous_verification(principal, context)
            
            if not verification_result['verified']:
                return {
                    'success': False,
                    'reason': verification_result['reason'],
                    'trust_score': principal.trust_score
                }
            
            # Update trust score
            self.trust_engine.update_trust_score(principal, context)
            
            # Create session
            session = self._create_session(principal_id, context)
            
            # Log authentication event
            self._log_event(
                event_type="authentication_success",
                principal_id=principal_id,
                resource="system",
                action="authenticate",
                result="success",
                risk_score=principal.trust_score,
                details={'context': context},
                mitigation="none"
            )
            
            return {
                'success': True,
                'session_id': session.session_id,
                'trust_score': principal.trust_score,
                'expires_at': session.expires_at.isoformat(),
                'permissions': list(session.permissions)
            }
        
        except Exception as e:
            logger.error(f"Error authenticating principal {principal_id}: {e}")
            return {
                'success': False,
                'reason': 'authentication_error',
                'trust_score': 0.0
            }
    
    def _verify_credentials(self, principal: ZeroTrustPrincipal, credentials: Dict) -> bool:
        """Verify principal credentials"""
        try:
            # Password authentication
            if 'password' in credentials and 'password_hash' in principal.credentials:
                return bcrypt.checkpw(
                    credentials['password'].encode(),
                    principal.credentials['password_hash'].encode()
                )
            
            # API key authentication
            if 'api_key' in credentials and 'api_key_hash' in principal.credentials:
                expected_hash = principal.credentials['api_key_hash']
                actual_hash = hashlib.sha256(credentials['api_key'].encode()).hexdigest()
                return hmac.compare_digest(actual_hash, expected_hash)
            
            # Certificate authentication
            if 'certificate' in credentials and 'certificate_pem' in principal.credentials:
                # Simplified certificate verification
                return True
            
            # Multi-factor authentication
            if 'mfa_code' in credentials and 'mfa_secret' in principal.credentials:
                # Simplified TOTP verification
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Error verifying credentials: {e}")
            return False
    
    def _continuous_verification(self, principal: ZeroTrustPrincipal, context: Dict) -> Dict:
        """Perform continuous verification"""
        try:
            # Check device trust
            if 'device_id' in context:
                device_trust = self._verify_device(context['device_id'])
                if not device_trust['trusted']:
                    return {
                        'verified': False,
                        'reason': 'untrusted_device',
                        'details': device_trust
                    }
            
            # Check location trust
            if 'location' in context:
                location_trust = self._verify_location(context['location'], principal.attributes)
                if not location_trust['trusted']:
                    return {
                        'verified': False,
                        'reason': 'untrusted_location',
                        'details': location_trust
                    }
            
            # Check time-based access
            time_trust = self._verify_time_access(context, principal.attributes)
            if not time_trust['trusted']:
                return {
                    'verified': False,
                    'reason': 'time_restriction',
                    'details': time_trust
                }
            
            # Check behavioral patterns
            if 'behavior' in context:
                behavior_trust = self._verify_behavior(context['behavior'], principal.principal_id)
                if not behavior_trust['trusted']:
                    return {
                        'verified': False,
                        'reason': 'behavior_anomaly',
                        'details': behavior_trust
                    }
            
            return {'verified': True}
        
        except Exception as e:
            logger.error(f"Error in continuous verification: {e}")
            return {'verified': False, 'reason': 'verification_error'}
    
    def _verify_device(self, device_id: str) -> Dict:
        """Verify device trust"""
        # In a real implementation, this would check:
        # - Device registration status
        # - Security posture
        # - Compliance status
        # - Known vulnerabilities
        
        # For demonstration, assume some devices are trusted
        trusted_devices = ['device_001', 'device_002', 'device_003']
        
        return {
            'trusted': device_id in trusted_devices,
            'device_id': device_id,
            'registered': device_id in trusted_devices,
            'compliant': True
        }
    
    def _verify_location(self, location: str, principal_attributes: Dict) -> Dict:
        """Verify location trust"""
        # Check if location is in trusted locations
        trusted_locations = principal_attributes.get('trusted_locations', ['office', 'vpn'])
        
        return {
            'trusted': location in trusted_locations,
            'location': location,
            'trusted_locations': trusted_locations
        }
    
    def _verify_time_access(self, context: Dict, principal_attributes: Dict) -> Dict:
        """Verify time-based access"""
        current_time = datetime.now()
        current_hour = current_time.hour
        current_day = current_time.weekday()
        
        # Check allowed hours
        allowed_hours = principal_attributes.get('allowed_hours', range(24))
        if current_hour not in allowed_hours:
            return {
                'trusted': False,
                'reason': 'outside_allowed_hours',
                'current_hour': current_hour
            }
        
        # Check allowed days
        allowed_days = principal_attributes.get('allowed_days', range(7))
        if current_day not in allowed_days:
            return {
                'trusted': False,
                'reason': 'outside_allowed_days',
                'current_day': current_day
            }
        
        return {'trusted': True}
    
    def _verify_behavior(self, behavior: Dict, principal_id: str) -> Dict:
        """Verify behavioral patterns"""
        # In a real implementation, this would analyze:
        # - Typing patterns
        # - Access patterns
        # - Time patterns
        # - Command patterns
        
        # For demonstration, simple anomaly detection
        risk_score = self.risk_analyzer.analyze_behavior(behavior, principal_id)
        
        return {
            'trusted': risk_score < 0.7,
            'risk_score': risk_score,
            'behavior': behavior
        }
    
    def _create_session(self, principal_id: str, context: Dict) -> ZeroTrustSession:
        """Create zero-trust session"""
        session_id = self._generate_session_id()
        principal = self.principals[principal_id]
        
        expires_at = datetime.now() + timedelta(seconds=self.session_timeout)
        
        session = ZeroTrustSession(
            session_id=session_id,
            principal_id=principal_id,
            created_at=datetime.now(),
            expires_at=expires_at,
            last_activity=datetime.now(),
            context=context,
            trust_level=self._get_trust_level(principal.trust_score),
            permissions=principal.permissions.copy(),
            is_active=True
        )
        
        self.sessions[session_id] = session
        self._store_session(session)
        
        return session
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"session_{secrets.token_hex(32)}"
    
    def _get_trust_level(self, trust_score: float) -> str:
        """Get trust level from score"""
        if trust_score >= self.trust_thresholds['critical']:
            return 'critical'
        elif trust_score >= self.trust_thresholds['high']:
            return 'high'
        elif trust_score >= self.trust_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _store_session(self, session: ZeroTrustSession):
        """Store session in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO zero_trust_sessions 
            (session_id, principal_id, created_at, expires_at, last_activity,
             context, trust_level, permissions, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id,
            session.principal_id,
            session.created_at.isoformat(),
            session.expires_at.isoformat(),
            session.last_activity.isoformat(),
            json.dumps(session.context),
            session.trust_level,
            json.dumps(list(session.permissions)),
            session.is_active
        ))
        
        conn.commit()
        conn.close()
    
    def authorize_access(self, session_id: str, resource: str, action: str, 
                        context: Dict) -> Dict:
        """Authorize access with zero-trust evaluation"""
        try:
            # Get session
            session = self.sessions.get(session_id)
            if not session or not session.is_active:
                return {
                    'authorized': False,
                    'reason': 'invalid_session',
                    'trust_score': 0.0
                }
            
            # Check session expiration
            if datetime.now() > session.expires_at:
                self._invalidate_session(session_id)
                return {
                    'authorized': False,
                    'reason': 'session_expired',
                    'trust_score': 0.0
                }
            
            # Get principal
            principal = self.principals.get(session.principal_id)
            if not principal:
                return {
                    'authorized': False,
                    'reason': 'principal_not_found',
                    'trust_score': 0.0
                }
            
            # Evaluate policies
            policy_result = self._evaluate_policies(principal, resource, action, context)
            
            if not policy_result['allowed']:
                self._log_event(
                    event_type="access_denied",
                    principal_id=principal.principal_id,
                    resource=resource,
                    action=action,
                    result="denied",
                    risk_score=principal.trust_score,
                    details={'policy_result': policy_result, 'context': context},
                    mitigation="policy_enforcement"
                )
                
                return {
                    'authorized': False,
                    'reason': policy_result['reason'],
                    'trust_score': principal.trust_score
                }
            
            # Update session activity
            session.last_activity = datetime.now()
            self._update_session(session)
            
            # Update trust score based on access
            self.trust_engine.update_trust_score(principal, context)
            
            # Log successful access
            self._log_event(
                event_type="access_granted",
                principal_id=principal.principal_id,
                resource=resource,
                action=action,
                result="granted",
                risk_score=principal.trust_score,
                details={'context': context},
                mitigation="none"
            )
            
            return {
                'authorized': True,
                'trust_score': principal.trust_score,
                'session_expires': session.expires_at.isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error authorizing access: {e}")
            return {
                'authorized': False,
                'reason': 'authorization_error',
                'trust_score': 0.0
            }
    
    def _evaluate_policies(self, principal: ZeroTrustPrincipal, resource: str, 
                          action: str, context: Dict) -> Dict:
        """Evaluate zero-trust policies"""
        try:
            # Sort policies by priority (lower number = higher priority)
            sorted_policies = sorted(self.policies.values(), key=lambda p: p.priority)
            
            for policy in sorted_policies:
                if not policy.enabled:
                    continue
                
                # Evaluate policy conditions
                conditions_met = self._evaluate_conditions(policy.conditions, principal, resource, action, context)
                
                if conditions_met:
                    # Apply policy actions
                    if 'deny' in policy.actions:
                        return {
                            'allowed': False,
                            'reason': f"policy_denied:{policy.policy_id}",
                            'policy': policy.policy_id
                        }
                    elif 'allow' in policy.actions:
                        return {
                            'allowed': True,
                            'reason': f"policy_allowed:{policy.policy_id}",
                            'policy': policy.policy_id
                        }
                    elif 'require_mfa' in policy.actions:
                        # Check if MFA already verified
                        if not context.get('mfa_verified', False):
                            return {
                                'allowed': False,
                                'reason': f"mfa_required:{policy.policy_id}",
                                'policy': policy.policy_id
                            }
            
            # Default deny if no policy allows access
            return {
                'allowed': False,
                'reason': 'default_deny',
                'policy': 'default_deny'
            }
        
        except Exception as e:
            logger.error(f"Error evaluating policies: {e}")
            return {
                'allowed': False,
                'reason': 'policy_evaluation_error',
                'policy': 'error'
            }
    
    def _evaluate_conditions(self, conditions: List[Dict], principal: ZeroTrustPrincipal,
                            resource: str, action: str, context: Dict) -> bool:
        """Evaluate policy conditions"""
        if not conditions:
            return True
        
        for condition in conditions:
            field = condition['field']
            operator = condition['operator']
            value = condition['value']
            
            # Get actual value
            actual_value = self._get_condition_value(field, principal, resource, action, context)
            
            # Evaluate condition
            if not self._evaluate_condition(actual_value, operator, value):
                return False
        
        return True
    
    def _get_condition_value(self, field: str, principal: ZeroTrustPrincipal,
                            resource: str, action: str, context: Dict) -> Union[str, int, float, List, Set]:
        """Get value for condition evaluation"""
        if field == 'principal_type':
            return principal.principal_type
        elif field == 'trust_score':
            return principal.trust_score
        elif field == 'risk_level':
            return principal.risk_level
        elif field == 'permissions':
            return principal.permissions
        elif field == 'action':
            return action
        elif field == 'resource':
            return resource
        elif field == 'hour':
            return datetime.now().hour
        elif field == 'day_of_week':
            return datetime.now().weekday()
        elif field == 'location':
            return context.get('location', 'unknown')
        elif field == 'device_id':
            return context.get('device_id', 'unknown')
        else:
            return context.get(field, None)
    
    def _evaluate_condition(self, actual: Union[str, int, float, List, Set], 
                           operator: str, expected: Union[str, int, float, List]) -> bool:
        """Evaluate individual condition"""
        try:
            if operator == 'equals':
                return actual == expected
            elif operator == 'not_equals':
                return actual != expected
            elif operator == 'in':
                return actual in expected if isinstance(expected, (list, set)) else False
            elif operator == 'not_in':
                return actual not in expected if isinstance(expected, (list, set)) else True
            elif operator == 'contains':
                return expected in actual if isinstance(actual, (list, set)) else False
            elif operator == 'greater_than':
                return actual > expected
            elif operator == 'less_than':
                return actual < expected
            elif operator == 'greater_equal':
                return actual >= expected
            elif operator == 'less_equal':
                return actual <= expected
            elif operator == 'between':
                return expected[0] <= actual <= expected[1] if isinstance(expected, list) else False
            else:
                return False
        
        except Exception:
            return False
    
    def _update_session(self, session: ZeroTrustSession):
        """Update session in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE zero_trust_sessions 
            SET last_activity = ?, trust_level = ?, permissions = ?
            WHERE session_id = ?
        ''', (
            session.last_activity.isoformat(),
            session.trust_level,
            json.dumps(list(session.permissions)),
            session.session_id
        ))
        
        conn.commit()
        conn.close()
    
    def _invalidate_session(self, session_id: str):
        """Invalidate session"""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE zero_trust_sessions SET is_active = 0 WHERE session_id = ?', (session_id,))
            conn.commit()
            conn.close()
    
    def _handle_failed_authentication(self, principal_id: str, context: Dict):
        """Handle failed authentication"""
        # Log failed authentication
        self._log_event(
            event_type="authentication_failed",
            principal_id=principal_id,
            resource="system",
            action="authenticate",
            result="failed",
            risk_score=1.0,
            details={'context': context},
            mitigation="monitor"
        )
        
        # Update trust score
        principal = self.principals.get(principal_id)
        if principal:
            principal.trust_score = max(0.0, principal.trust_score - 0.1)
            principal.risk_level = self._get_risk_level(principal.trust_score)
            self._store_principal(principal)
    
    def _get_risk_level(self, trust_score: float) -> str:
        """Get risk level from trust score"""
        if trust_score < self.trust_thresholds['low']:
            return 'high'
        elif trust_score < self.trust_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _log_event(self, event_type: str, principal_id: str, resource: str, action: str,
                  result: str, risk_score: float, details: Dict, mitigation: str):
        """Log zero-trust event"""
        event = ZeroTrustEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            principal_id=principal_id,
            resource=resource,
            action=action,
            result=result,
            risk_score=risk_score,
            details=details,
            mitigation=mitigation
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO zero_trust_events 
            (timestamp, event_type, principal_id, resource, action, result,
             risk_score, details, mitigation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.event_type,
            event.principal_id,
            event.resource,
            event.action,
            event.result,
            event.risk_score,
            json.dumps(event.details),
            event.mitigation
        ))
        
        conn.commit()
        conn.close()
    
    def _session_monitoring_loop(self):
        """Monitor sessions for expiration and anomalies"""
        while self.monitoring:
            try:
                current_time = datetime.now()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    # Check expiration
                    if current_time > session.expires_at:
                        expired_sessions.append(session_id)
                        continue
                    
                    # Check inactivity timeout
                    inactivity_duration = (current_time - session.last_activity).seconds
                    if inactivity_duration > self.session_timeout:
                        expired_sessions.append(session_id)
                        continue
                
                # Invalidate expired sessions
                for session_id in expired_sessions:
                    self._invalidate_session(session_id)
                    logger.info(f"Session expired: {session_id}")
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"Error in session monitoring: {e}")
                time.sleep(120)
    
    def _trust_monitoring_loop(self):
        """Monitor trust scores and adjust as needed"""
        while self.monitoring:
            try:
                # Update trust scores for all principals
                for principal_id, principal in self.principals.items():
                    # Analyze recent events
                    recent_events = self._get_recent_events(principal_id, hours=24)
                    
                    # Update trust based on events
                    trust_adjustment = self.trust_engine.analyze_events(recent_events)
                    
                    if trust_adjustment != 0:
                        principal.trust_score = max(0.0, min(1.0, principal.trust_score + trust_adjustment))
                        principal.risk_level = self._get_risk_level(principal.trust_score)
                        principal.last_verified = datetime.now()
                        
                        self._store_principal(principal)
                        
                        # Store trust assessment
                        self._store_trust_assessment(principal_id, trust_adjustment, recent_events)
                
                time.sleep(300)  # Update every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in trust monitoring: {e}")
                time.sleep(600)
    
    def _get_recent_events(self, principal_id: str, hours: int = 24) -> List[Dict]:
        """Get recent events for principal"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT event_type, result, risk_score, details, timestamp
            FROM zero_trust_events 
            WHERE principal_id = ? AND timestamp > datetime('now', '-{} hours')
            ORDER BY timestamp DESC
        '''.format(hours), (principal_id,))
        
        events = []
        for row in cursor.fetchall():
            events.append({
                'event_type': row[0],
                'result': row[1],
                'risk_score': row[2],
                'details': json.loads(row[3]),
                'timestamp': row[4]
            })
        
        conn.close()
        return events
    
    def _store_trust_assessment(self, principal_id: str, trust_adjustment: float, events: List[Dict]):
        """Store trust assessment"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO trust_assessments 
            (principal_id, assessment_type, trust_score, risk_factors, timestamp, context)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            principal_id,
            'event_analysis',
            trust_adjustment,
            json.dumps({'event_count': len(events)}),
            datetime.now().isoformat(),
            json.dumps({'recent_events': len(events)})
        ))
        
        conn.commit()
        conn.close()
    
    def _risk_monitoring_loop(self):
        """Monitor for security risks and anomalies"""
        while self.monitoring:
            try:
                # Analyze system-wide risks
                system_risks = self._analyze_system_risks()
                
                # Check for high-risk principals
                high_risk_principals = [
                    pid for pid, p in self.principals.items()
                    if p.risk_level == 'high'
                ]
                
                # Check for suspicious patterns
                suspicious_patterns = self._detect_suspicious_patterns()
                
                # Take mitigation actions if needed
                if system_risks['overall_risk'] > 0.8:
                    self._handle_high_system_risk(system_risks)
                
                if len(high_risk_principals) > 0:
                    self._handle_high_risk_principals(high_risk_principals)
                
                if suspicious_patterns:
                    self._handle_suspicious_patterns(suspicious_patterns)
                
                time.sleep(600)  # Check every 10 minutes
            
            except Exception as e:
                logger.error(f"Error in risk monitoring: {e}")
                time.sleep(1200)
    
    def _analyze_system_risks(self) -> Dict:
        """Analyze system-wide security risks"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent failed authentications
            cursor.execute('''
                SELECT COUNT(*) FROM zero_trust_events 
                WHERE event_type = 'authentication_failed' 
                AND timestamp > datetime('now', '-1 hour')
            ''')
            failed_auth = cursor.fetchone()[0]
            
            # Get recent access denials
            cursor.execute('''
                SELECT COUNT(*) FROM zero_trust_events 
                WHERE result = 'denied' 
                AND timestamp > datetime('now', '-1 hour')
            ''')
            access_denials = cursor.fetchone()[0]
            
            # Get active sessions
            cursor.execute('SELECT COUNT(*) FROM zero_trust_sessions WHERE is_active = 1')
            active_sessions = cursor.fetchone()[0]
            
            conn.close()
            
            # Calculate overall risk
            risk_factors = {
                'failed_authentications': failed_auth / 100.0,  # Normalize
                'access_denials': access_denials / 100.0,
                'active_sessions': min(active_sessions / 1000.0, 1.0)
            }
            
            overall_risk = sum(risk_factors.values()) / len(risk_factors)
            
            return {
                'overall_risk': overall_risk,
                'risk_factors': risk_factors,
                'failed_authentications': failed_auth,
                'access_denials': access_denials,
                'active_sessions': active_sessions
            }
        
        except Exception as e:
            logger.error(f"Error analyzing system risks: {e}")
            return {'overall_risk': 0.5, 'risk_factors': {}}
    
    def _detect_suspicious_patterns(self) -> List[Dict]:
        """Detect suspicious access patterns"""
        patterns = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check for principals with many failed authentications
            cursor.execute('''
                SELECT principal_id, COUNT(*) as count
                FROM zero_trust_events 
                WHERE event_type = 'authentication_failed' 
                AND timestamp > datetime('now', '-1 hour')
                GROUP BY principal_id
                HAVING count > 5
            ''')
            
            for row in cursor.fetchall():
                patterns.append({
                    'type': 'multiple_failed_auth',
                    'principal_id': row[0],
                    'count': row[1],
                    'severity': 'high'
                })
            
            # Check for unusual access times
            cursor.execute('''
                SELECT principal_id, COUNT(*) as count
                FROM zero_trust_events 
                WHERE timestamp > datetime('now', '-1 hour')
                AND (strftime('%H', timestamp) < 6 OR strftime('%H', timestamp) > 22)
                GROUP BY principal_id
                HAVING count > 3
            ''')
            
            for row in cursor.fetchall():
                patterns.append({
                    'type': 'unusual_time_access',
                    'principal_id': row[0],
                    'count': row[1],
                    'severity': 'medium'
                })
            
            conn.close()
        
        except Exception as e:
            logger.error(f"Error detecting suspicious patterns: {e}")
        
        return patterns
    
    def _handle_high_system_risk(self, risks: Dict):
        """Handle high system risk"""
        logger.critical("HIGH SYSTEM RISK DETECTED!")
        logger.critical(f"Overall risk: {risks['overall_risk']}")
        
        # In a real implementation, this might:
        # - Increase monitoring frequency
        # - Require additional authentication
        # - Lock down sensitive resources
        # - Alert security team
        
        # Log system risk event
        self._log_event(
            event_type="high_system_risk",
            principal_id="system",
            resource="system",
            action="risk_assessment",
            result="high_risk",
            risk_score=risks['overall_risk'],
            details=risks,
            mitigation="enhanced_monitoring"
        )
    
    def _handle_high_risk_principals(self, principal_ids: List[str]):
        """Handle high-risk principals"""
        for principal_id in principal_ids:
            principal = self.principals.get(principal_id)
            if principal:
                logger.warning(f"HIGH RISK PRINCIPAL: {principal.name} ({principal_id})")
                
                # Invalidate all sessions for this principal
                sessions_to_invalidate = [
                    sid for sid, s in self.sessions.items()
                    if s.principal_id == principal_id and s.is_active
                ]
                
                for session_id in sessions_to_invalidate:
                    self._invalidate_session(session_id)
                
                # Log high-risk principal event
                self._log_event(
                    event_type="high_risk_principal",
                    principal_id=principal_id,
                    resource="system",
                    action="risk_mitigation",
                    result="sessions_invalidated",
                    risk_score=principal.trust_score,
                    details={'principal_name': principal.name},
                    mitigation="session_invalidation"
                )
    
    def _handle_suspicious_patterns(self, patterns: List[Dict]):
        """Handle suspicious patterns"""
        for pattern in patterns:
            logger.warning(f"SUSPICIOUS PATTERN: {pattern['type']}")
            logger.warning(f"Principal: {pattern['principal_id']}")
            logger.warning(f"Count: {pattern['count']}")
            
            # Log suspicious pattern event
            self._log_event(
                event_type="suspicious_pattern",
                principal_id=pattern['principal_id'],
                resource="system",
                action="pattern_detection",
                result="suspicious",
                risk_score=0.7,
                details=pattern,
                mitigation="enhanced_monitoring"
            )
    
    def _policy_enforcement_loop(self):
        """Continuously enforce policies"""
        while self.monitoring:
            try:
                # Check for policy violations
                violations = self._check_policy_violations()
                
                for violation in violations:
                    self._handle_policy_violation(violation)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in policy enforcement: {e}")
                time.sleep(600)
    
    def _check_policy_violations(self) -> List[Dict]:
        """Check for policy violations"""
        violations = []
        
        try:
            # Check for active sessions that violate current policies
            for session_id, session in self.sessions.items():
                if not session.is_active:
                    continue
                
                principal = self.principals.get(session.principal_id)
                if not principal:
                    continue
                
                # Re-evaluate policies with current context
                policy_result = self._evaluate_policies(
                    principal, "system", "session_active", session.context
                )
                
                if not policy_result['allowed']:
                    violations.append({
                        'type': 'policy_violation',
                        'session_id': session_id,
                        'principal_id': principal.principal_id,
                        'policy': policy_result['policy'],
                        'reason': policy_result['reason']
                    })
        
        except Exception as e:
            logger.error(f"Error checking policy violations: {e}")
        
        return violations
    
    def _handle_policy_violation(self, violation: Dict):
        """Handle policy violation"""
        logger.warning(f"POLICY VIOLATION: {violation['policy']}")
        logger.warning(f"Session: {violation['session_id']}")
        
        # Invalidate violating session
        self._invalidate_session(violation['session_id'])
        
        # Log policy violation
        self._log_event(
            event_type="policy_violation",
            principal_id=violation['principal_id'],
            resource="session",
            action="policy_enforcement",
            result="session_terminated",
            risk_score=0.8,
            details=violation,
            mitigation="session_termination"
        )
    
    def _generate_jwt_secret(self) -> str:
        """Generate JWT secret"""
        return secrets.token_hex(32)
    
    def get_zero_trust_status(self) -> Dict:
        """Get zero-trust system status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get principal statistics
        cursor.execute('SELECT principal_type, COUNT(*) FROM zero_trust_principals WHERE is_active = 1 GROUP BY principal_type')
        principal_stats = dict(cursor.fetchall())
        
        # Get session statistics
        cursor.execute('SELECT COUNT(*) FROM zero_trust_sessions WHERE is_active = 1')
        active_sessions = cursor.fetchone()[0]
        
        # Get recent events
        cursor.execute('''
            SELECT event_type, COUNT(*) FROM zero_trust_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY event_type
        ''')
        event_stats = dict(cursor.fetchall())
        
        # Get trust score distribution
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN trust_score >= 0.8 THEN 'high'
                    WHEN trust_score >= 0.6 THEN 'medium'
                    ELSE 'low'
                END as trust_level,
                COUNT(*) as count
            FROM zero_trust_principals 
            WHERE is_active = 1
            GROUP BY trust_level
        ''')
        trust_distribution = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'principal_statistics': principal_stats,
            'active_sessions': active_sessions,
            'event_statistics': event_stats,
            'trust_distribution': trust_distribution,
            'active_policies': len([p for p in self.policies.values() if p.enabled]),
            'system_risk': self._analyze_system_risks()
        }
    
    def stop_monitoring(self):
        """Stop zero-trust monitoring"""
        self.monitoring = False
        logger.info("Zero-trust monitoring stopped")
    
    def generate_zero_trust_report(self) -> Dict:
        """Generate comprehensive zero-trust report"""
        try:
            status = self.get_zero_trust_status()
            
            # Get detailed statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Authentication statistics
            cursor.execute('''
                SELECT 
                    SUM(CASE WHEN event_type = 'authentication_success' THEN 1 ELSE 0 END) as successes,
                    SUM(CASE WHEN event_type = 'authentication_failed' THEN 1 ELSE 0 END) as failures
                FROM zero_trust_events 
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            auth_stats = cursor.fetchone()
            
            # Access control statistics
            cursor.execute('''
                SELECT 
                    SUM(CASE WHEN result = 'granted' THEN 1 ELSE 0 END) as granted,
                    SUM(CASE WHEN result = 'denied' THEN 1 ELSE 0 END) as denied
                FROM zero_trust_events 
                WHERE event_type = 'access_granted' OR event_type = 'access_denied'
                AND timestamp > datetime('now', '-24 hours')
            ''')
            access_stats = cursor.fetchone()
            
            # Risk assessment statistics
            cursor.execute('''
                SELECT assessment_type, COUNT(*) as count, AVG(trust_score) as avg_score
                FROM trust_assessments 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY assessment_type
            ''')
            assessment_stats = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'system_status': status,
                'authentication_statistics': {
                    'successes': auth_stats[0] or 0,
                    'failures': auth_stats[1] or 0,
                    'success_rate': (auth_stats[0] or 0) / max((auth_stats[0] or 0) + (auth_stats[1] or 0), 1)
                },
                'access_control_statistics': {
                    'granted': access_stats[0] or 0,
                    'denied': access_stats[1] or 0,
                    'grant_rate': (access_stats[0] or 0) / max((access_stats[0] or 0) + (access_stats[1] or 0), 1)
                },
                'risk_assessment_statistics': assessment_stats,
                'recommendations': self._generate_zero_trust_recommendations()
            }
        
        except Exception as e:
            logger.error(f"Error generating zero-trust report: {e}")
            return {'error': str(e)}
    
    def _generate_zero_trust_recommendations(self) -> List[str]:
        """Generate zero-trust security recommendations"""
        recommendations = []
        
        status = self.get_zero_trust_status()
        
        if status['system_risk']['overall_risk'] > 0.7:
            recommendations.append("High system risk detected - review security policies")
        
        if status['active_sessions'] > 1000:
            recommendations.append("High number of active sessions - consider session timeout adjustments")
        
        failed_auth_rate = status['event_statistics'].get('authentication_failed', 0) / max(
            status['event_statistics'].get('authentication_success', 1) + 
            status['event_statistics'].get('authentication_failed', 0), 1
        )
        
        if failed_auth_rate > 0.1:
            recommendations.append("High authentication failure rate - investigate potential attacks")
        
        recommendations.extend([
            "Regularly review and update access policies",
            "Implement continuous authentication for sensitive operations",
            "Monitor trust scores and investigate anomalies",
            "Use least privilege access principles",
            "Implement device compliance checks",
            "Enable behavioral analytics for anomaly detection"
        ])
        
        return recommendations


class TrustEngine:
    """Trust scoring engine for zero-trust"""
    
    def __init__(self, trust_thresholds: Dict, risk_factors: Dict):
        self.trust_thresholds = trust_thresholds
        self.risk_factors = risk_factors
    
    def update_trust_score(self, principal: ZeroTrustPrincipal, context: Dict):
        """Update principal trust score"""
        try:
            # Base trust score decay
            decay_factor = 0.95  # 5% decay per update
            principal.trust_score *= decay_factor
            
            # Positive factors
            if context.get('successful_auth', False):
                principal.trust_score += 0.05
            
            if context.get('mfa_verified', False):
                principal.trust_score += 0.1
            
            if context.get('trusted_device', False):
                principal.trust_score += 0.05
            
            # Negative factors
            if context.get('failed_auth', False):
                principal.trust_score -= 0.1
            
            if context.get('unusual_location', False):
                principal.trust_score -= 0.05
            
            if context.get('unusual_time', False):
                principal.trust_score -= 0.03
            
            # Ensure score stays within bounds
            principal.trust_score = max(0.0, min(1.0, principal.trust_score))
            
        except Exception as e:
            logger.error(f"Error updating trust score: {e}")
    
    def analyze_events(self, events: List[Dict]) -> float:
        """Analyze events and return trust adjustment"""
        if not events:
            return 0.0
        
        adjustment = 0.0
        
        for event in events:
            if event['result'] == 'success':
                adjustment += 0.01
            elif event['result'] == 'failed':
                adjustment -= 0.02
            elif event['result'] == 'denied':
                adjustment -= 0.01
        
        return adjustment


class RiskAnalyzer:
    """Risk analysis engine for zero-trust"""
    
    def __init__(self, risk_factors: Dict):
        self.risk_factors = risk_factors
        self.behavioral_baselines = {}
    
    def analyze_behavior(self, behavior: Dict, principal_id: str) -> float:
        """Analyze behavior for anomalies"""
        try:
            risk_score = 0.0
            
            # Check typing patterns
            if 'typing_speed' in behavior:
                baseline_speed = self.behavioral_baselines.get(f"{principal_id}_typing_speed", 100)
                speed_diff = abs(behavior['typing_speed'] - baseline_speed) / baseline_speed
                if speed_diff > 0.5:
                    risk_score += 0.2
            
            # Check access patterns
            if 'access_frequency' in behavior:
                baseline_freq = self.behavioral_baselines.get(f"{principal_id}_access_freq", 10)
                freq_diff = abs(behavior['access_frequency'] - baseline_freq) / baseline_freq
                if freq_diff > 1.0:
                    risk_score += 0.3
            
            # Check time patterns
            if 'access_times' in behavior:
                current_hour = datetime.now().hour
                baseline_hours = self.behavioral_baselines.get(f"{principal_id}_access_hours", range(9, 18))
                if current_hour not in baseline_hours:
                    risk_score += 0.1
            
            return min(risk_score, 1.0)
        
        except Exception as e:
            logger.error(f"Error analyzing behavior: {e}")
            return 0.5
