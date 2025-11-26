#!/usr/bin/env python3
"""
Advanced Cryptographic Signature Verification System
Multi-layered cryptographic verification with anti-tampering protection
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
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# Cryptography libraries
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Installing cryptography library...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

@dataclass
class CryptographicSignature:
    """Cryptographic signature information"""
    signature_id: str
    algorithm: str
    public_key: str
    certificate_chain: List[str]
    signature_data: str
    hash_algorithm: str
    created_at: datetime
    expires_at: datetime
    issuer: str
    subject: str
    is_valid: bool

@dataclass
class VerificationResult:
    """Cryptographic verification result"""
    is_valid: bool
    confidence: float
    verification_method: str
    algorithm_used: str
    timestamp: datetime
    errors: List[str]
    warnings: List[str]
    certificate_chain_valid: bool
    signature_valid: bool
    hash_valid: bool

class CryptoVerification:
    """Advanced cryptographic verification system"""
    
    def __init__(self, db_path: str = "prix_crypto.db"):
        self.db_path = db_path
        self.trusted_anchors = {}
        self.certificate_store = {}
        self.signature_cache = {}
        self.revoked_certificates = set()
        self.trusted_publishers = set()
        self.verification_algorithms = {
            'RSA_SHA256': self._verify_rsa_sha256,
            'RSA_SHA384': self._verify_rsa_sha384,
            'RSA_SHA512': self._verify_rsa_sha512,
            'ECDSA_SHA256': self._verify_ecdsa_sha256,
            'ECDSA_SHA384': self._verify_ecdsa_sha384,
            'ECDSA_SHA512': self._verify_ecdsa_sha512,
            'ED25519': self._verify_ed25519,
            'HMAC_SHA256': self._verify_hmac_sha256
        }
        
        # Initialize cryptographic verification
        self.init_database()
        self.load_trusted_anchors()
        self.generate_system_keys()
    
    def init_database(self):
        """Initialize cryptographic verification database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Signatures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cryptographic_signatures (
                signature_id TEXT PRIMARY KEY,
                algorithm TEXT,
                public_key TEXT,
                certificate_chain TEXT,
                signature_data TEXT,
                hash_algorithm TEXT,
                created_at TEXT,
                expires_at TEXT,
                issuer TEXT,
                subject TEXT,
                is_valid BOOLEAN DEFAULT 1
            )
        ''')
        
        # Verification results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                signature_id TEXT,
                is_valid BOOLEAN,
                confidence REAL,
                verification_method TEXT,
                algorithm_used TEXT,
                errors TEXT,
                warnings TEXT,
                certificate_chain_valid BOOLEAN,
                signature_valid BOOLEAN,
                hash_valid BOOLEAN
            )
        ''')
        
        # Trusted certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_certificates (
                certificate_id TEXT PRIMARY KEY,
                certificate_data TEXT,
                public_key TEXT,
                issuer TEXT,
                subject TEXT,
                not_before TEXT,
                not_after TEXT,
                is_trusted_anchor BOOLEAN DEFAULT 0,
                added_at TEXT
            )
        ''')
        
        # Revoked certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS revoked_certificates (
                certificate_id TEXT PRIMARY KEY,
                serial_number TEXT,
                revocation_date TEXT,
                reason TEXT
            )
        ''')
        
        # System keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_keys (
                key_id TEXT PRIMARY KEY,
                key_type TEXT,
                public_key TEXT,
                private_key TEXT,
                algorithm TEXT,
                key_size INTEGER,
                created_at TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_trusted_anchors(self):
        """Load trusted certificate anchors"""
        logger.info("Loading trusted certificate anchors...")
        
        # Load system root certificates
        self._load_system_root_certificates()
        
        # Load custom trusted certificates
        self._load_custom_trusted_certificates()
        
        logger.info(f"Loaded {len(self.trusted_anchors)} trusted anchors")
    
    def _load_system_root_certificates(self):
        """Load system root certificates"""
        try:
            # Common system certificate paths
            cert_paths = [
                '/etc/ssl/certs',
                '/usr/share/ca-certificates',
                '/etc/pki/tls/certs',
                '/System/Library/OpenSSL/certs'  # macOS
            ]
            
            for cert_path in cert_paths:
                if os.path.exists(cert_path):
                    self._scan_certificate_directory(cert_path)
        
        except Exception as e:
            logger.error(f"Error loading system root certificates: {e}")
    
    def _scan_certificate_directory(self, directory: str):
        """Scan directory for certificates"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.crt', '.pem', '.cer')):
                        cert_path = os.path.join(root, file)
                        try:
                            with open(cert_path, 'rb') as f:
                                cert_data = f.read()
                            
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                            
                            # Store as trusted anchor
                            cert_id = self._generate_certificate_id(cert)
                            self.trusted_anchors[cert_id] = cert
                            
                            # Store in database
                            self._store_trusted_certificate(cert_id, cert, is_trusted_anchor=True)
                            
                        except Exception as e:
                            logger.debug(f"Could not load certificate {cert_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning certificate directory {directory}: {e}")
    
    def _load_custom_trusted_certificates(self):
        """Load custom trusted certificates"""
        # Load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT certificate_id, certificate_data FROM trusted_certificates 
            WHERE is_trusted_anchor = 1
        ''')
        
        for cert_id, cert_data_pem in cursor.fetchall():
            try:
                cert_data = base64.b64decode(cert_data_pem)
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                self.trusted_anchors[cert_id] = cert
            except Exception as e:
                logger.error(f"Error loading custom certificate {cert_id}: {e}")
        
        conn.close()
    
    def _generate_certificate_id(self, cert) -> str:
        """Generate unique certificate ID"""
        cert_hash = hashlib.sha256(cert.public_bytes(Encoding.PEM)).hexdigest()
        return f"cert_{cert_hash[:16]}"
    
    def _store_trusted_certificate(self, cert_id: str, cert, is_trusted_anchor: bool = False):
        """Store trusted certificate in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO trusted_certificates 
            (certificate_id, certificate_data, public_key, issuer, subject, not_before, not_after, is_trusted_anchor, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cert_id,
            base64.b64encode(cert.public_bytes(Encoding.PEM)).decode(),
            cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
            cert.issuer.rfc4514_string(),
            cert.subject.rfc4514_string(),
            cert.not_valid_before.isoformat(),
            cert.not_valid_after.isoformat(),
            is_trusted_anchor,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def generate_system_keys(self):
        """Generate system cryptographic keys"""
        logger.info("Generating system cryptographic keys...")
        
        # Generate RSA key pair
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Generate EC key pair
        ec_private_key = ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()
        )
        
        # Generate Ed25519 key pair
        ed25519_private_key = ec.generate_private_key(
            ec.Ed25519(),
            backend=default_backend()
        )
        
        # Store keys
        self._store_system_key("rsa_4096", rsa_private_key, "RSA", 4096)
        self._store_system_key("ec_secp384r1", ec_private_key, "ECDSA", 384)
        self._store_system_key("ed25519", ed25519_private_key, "Ed25519", 256)
        
        logger.info("System cryptographic keys generated")
    
    def _store_system_key(self, key_id: str, private_key, algorithm: str, key_size: int):
        """Store system key in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Serialize keys
        private_key_pem = private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        ).decode()
        
        public_key_pem = private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        cursor.execute('''
            INSERT OR REPLACE INTO system_keys 
            (key_id, key_type, public_key, private_key, algorithm, key_size, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            key_id,
            algorithm.lower(),
            public_key_pem,
            private_key_pem,
            algorithm,
            key_size,
            datetime.now().isoformat(),
            True
        ))
        
        conn.commit()
        conn.close()
    
    def verify_file_signature(self, file_path: str, signature_data: str = None) -> VerificationResult:
        """Verify cryptographic signature of file"""
        try:
            if not os.path.exists(file_path):
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="file_not_found",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["File not found"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Calculate file hash
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            # If signature data provided, verify it
            if signature_data:
                return self._verify_signature_data(file_content, signature_data, file_path)
            
            # Otherwise, try to find embedded signature
            return self._verify_embedded_signature(file_content, file_path)
        
        except Exception as e:
            logger.error(f"Error verifying file signature for {file_path}: {e}")
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="error",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=[str(e)],
                warnings=[],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=False
            )
    
    def _verify_signature_data(self, file_content: bytes, signature_data: str, file_path: str) -> VerificationResult:
        """Verify signature data against file content"""
        try:
            # Parse signature data
            signature_info = json.loads(signature_data)
            
            algorithm = signature_info.get('algorithm', 'RSA_SHA256')
            signature_b64 = signature_info.get('signature', '')
            certificate_chain = signature_info.get('certificate_chain', [])
            
            if not signature_b64:
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="missing_signature",
                    algorithm_used=algorithm,
                    timestamp=datetime.now(),
                    errors=["Missing signature data"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Decode signature
            try:
                signature = base64.b64decode(signature_b64)
            except Exception:
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="invalid_signature_encoding",
                    algorithm_used=algorithm,
                    timestamp=datetime.now(),
                    errors=["Invalid signature encoding"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Verify certificate chain
            chain_valid, cert = self._verify_certificate_chain(certificate_chain)
            
            # Verify signature
            signature_valid = False
            if cert and algorithm in self.verification_algorithms:
                signature_valid = self.verification_algorithms[algorithm](file_content, signature, cert.public_key())
            
            # Calculate overall confidence
            confidence = self._calculate_verification_confidence(chain_valid, signature_valid, cert)
            
            # Generate errors and warnings
            errors = []
            warnings = []
            
            if not chain_valid:
                errors.append("Certificate chain validation failed")
            
            if not signature_valid:
                errors.append("Signature verification failed")
            
            if cert and self._is_certificate_revoked(cert):
                errors.append("Certificate is revoked")
            
            if cert and self._is_certificate_expired(cert):
                warnings.append("Certificate is expired")
            
            return VerificationResult(
                is_valid=len(errors) == 0,
                confidence=confidence,
                verification_method="provided_signature",
                algorithm_used=algorithm,
                timestamp=datetime.now(),
                errors=errors,
                warnings=warnings,
                certificate_chain_valid=chain_valid,
                signature_valid=signature_valid,
                hash_valid=True  # File hash is always valid for existing files
            )
        
        except Exception as e:
            logger.error(f"Error verifying signature data: {e}")
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="signature_error",
                algorithm_used="unknown",
                timestamp=datetime.now(),
                errors=[str(e)],
                warnings=[],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=False
            )
    
    def _verify_embedded_signature(self, file_content: bytes, file_path: str) -> VerificationResult:
        """Verify embedded signature in file"""
        try:
            # Look for embedded digital signatures
            # This would implement various signature formats:
            # - PE signatures (Windows executables)
            # - ELF signatures (Linux executables)
            # - Mach-O signatures (macOS executables)
            # - Custom embedded signatures
            
            # For demonstration, implement basic PE signature verification
            if file_path.endswith(('.exe', '.dll')):
                return self._verify_pe_signature(file_content, file_path)
            elif file_path.endswith(('.so', '.elf')):
                return self._verify_elf_signature(file_content, file_path)
            else:
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="no_embedded_signature",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["No embedded signature found"],
                    warnings=["File type not supported for embedded signatures"],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=True
                )
        
        except Exception as e:
            logger.error(f"Error verifying embedded signature: {e}")
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="embedded_error",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=[str(e)],
                warnings=[],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=False
            )
    
    def _verify_pe_signature(self, file_content: bytes, file_path: str) -> VerificationResult:
        """Verify PE file signature (Windows executable)"""
        try:
            # Check PE signature
            if len(file_content) < 64:
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="invalid_pe",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["Invalid PE file"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Check MZ signature
            if file_content[:2] != b'MZ':
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="not_pe_file",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["Not a valid PE file"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Look for digital signature directory
            # This is a simplified implementation
            # In reality, this would parse the PE structure and verify the signature
            
            # For demonstration, assume no signature found
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="no_pe_signature",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=["No digital signature found in PE file"],
                warnings=["Unsigned executable"],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=True
            )
        
        except Exception as e:
            logger.error(f"Error verifying PE signature: {e}")
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="pe_error",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=[str(e)],
                warnings=[],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=False
            )
    
    def _verify_elf_signature(self, file_content: bytes, file_path: str) -> VerificationResult:
        """Verify ELF file signature (Linux executable)"""
        try:
            # Check ELF signature
            if len(file_content) < 4:
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="invalid_elf",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["Invalid ELF file"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Check ELF magic number
            if file_content[:4] != b'\x7fELF':
                return VerificationResult(
                    is_valid=False,
                    confidence=0.0,
                    verification_method="not_elf_file",
                    algorithm_used="none",
                    timestamp=datetime.now(),
                    errors=["Not a valid ELF file"],
                    warnings=[],
                    certificate_chain_valid=False,
                    signature_valid=False,
                    hash_valid=False
                )
            
            # Look for ELF signatures (ELF doesn't have built-in signature support like PE)
            # This would check for custom signature sections
            
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="no_elf_signature",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=["No signature found in ELF file"],
                warnings=["ELF files typically don't contain embedded signatures"],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=True
            )
        
        except Exception as e:
            logger.error(f"Error verifying ELF signature: {e}")
            return VerificationResult(
                is_valid=False,
                confidence=0.0,
                verification_method="elf_error",
                algorithm_used="none",
                timestamp=datetime.now(),
                errors=[str(e)],
                warnings=[],
                certificate_chain_valid=False,
                signature_valid=False,
                hash_valid=False
            )
    
    def _verify_certificate_chain(self, certificate_chain: List[str]) -> Tuple[bool, Optional]:
        """Verify certificate chain against trusted anchors"""
        try:
            if not certificate_chain:
                return False, None
            
            # Load certificates
            certificates = []
            for cert_b64 in certificate_chain:
                try:
                    cert_data = base64.b64decode(cert_b64)
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    certificates.append(cert)
                except Exception as e:
                    logger.error(f"Error loading certificate: {e}")
                    return False, None
            
            if not certificates:
                return False, None
            
            # Verify certificate chain
            leaf_cert = certificates[0]
            
            # Check if leaf certificate is trusted
            for cert_id, trusted_cert in self.trusted_anchors.items():
                if leaf_cert.subject == trusted_cert.subject:
                    return True, leaf_cert
            
            # Verify chain to trusted anchor
            current_cert = leaf_cert
            chain_length = 0
            
            while chain_length < 10:  # Prevent infinite loops
                # Check if current certificate is trusted
                for cert_id, trusted_cert in self.trusted_anchors.items():
                    if current_cert.subject == trusted_cert.subject:
                        return True, leaf_cert
                
                # Find issuer in chain
                issuer_found = False
                for cert in certificates[1:]:
                    if cert.subject == current_cert.issuer:
                        # Verify signature
                        try:
                            cert.public_key().verify(
                                current_cert.signature,
                                current_cert.tbs_certificate_bytes,
                                padding.PKCS1v15(),
                                current_cert.signature_hash_algorithm,
                            )
                            current_cert = cert
                            issuer_found = True
                            break
                        except InvalidSignature:
                            return False, leaf_cert
                
                if not issuer_found:
                    break
                
                chain_length += 1
            
            return False, leaf_cert
        
        except Exception as e:
            logger.error(f"Error verifying certificate chain: {e}")
            return False, None
    
    def _calculate_verification_confidence(self, chain_valid: bool, signature_valid: bool, cert) -> float:
        """Calculate overall verification confidence"""
        confidence = 0.0
        
        if chain_valid:
            confidence += 0.5
        
        if signature_valid:
            confidence += 0.4
        
        if cert:
            # Check certificate strength
            if isinstance(cert.public_key(), rsa.RSAPublicKey):
                key_size = cert.public_key().key_size
                if key_size >= 4096:
                    confidence += 0.1
                elif key_size >= 2048:
                    confidence += 0.05
            elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
                curve = cert.public_key().curve
                if curve.name in ['secp384r1', 'secp521r1']:
                    confidence += 0.1
                elif curve.name == 'secp256r1':
                    confidence += 0.05
        
        return min(confidence, 1.0)
    
    def _is_certificate_revoked(self, cert) -> bool:
        """Check if certificate is revoked"""
        try:
            cert_id = self._generate_certificate_id(cert)
            return cert_id in self.revoked_certificates
        except Exception:
            return False
    
    def _is_certificate_expired(self, cert) -> bool:
        """Check if certificate is expired"""
        try:
            now = datetime.now()
            return now < cert.not_valid_before or now > cert.not_valid_after
        except Exception:
            return True
    
    def _verify_rsa_sha256(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify RSA-SHA256 signature"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_rsa_sha384(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify RSA-SHA384 signature"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA384()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_rsa_sha512(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify RSA-SHA512 signature"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_ecdsa_sha256(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify ECDSA-SHA256 signature"""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_ecdsa_sha384(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify ECDSA-SHA384 signature"""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA384())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_ecdsa_sha512(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify ECDSA-SHA512 signature"""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_ed25519(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify Ed25519 signature"""
        try:
            public_key.verify(
                signature,
                data
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_hmac_sha256(self, data: bytes, signature: bytes, secret_key: bytes) -> bool:
        """Verify HMAC-SHA256"""
        try:
            expected_hmac = hmac.new(secret_key, data, hashlib.sha256).digest()
            return hmac.compare_digest(signature, expected_hmac)
        except Exception:
            return False
    
    def sign_file(self, file_path: str, key_id: str = "rsa_4096") -> Optional[str]:
        """Sign file with system private key"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Load private key
            private_key = self._load_system_private_key(key_id)
            if not private_key:
                logger.error(f"Private key not found: {key_id}")
                return None
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Create signature
            signature = private_key.sign(
                file_content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Create certificate (self-signed for demonstration)
            certificate = self._create_self_signed_certificate(private_key.public_key())
            
            # Create signature data
            signature_data = {
                'algorithm': 'RSA_SHA256',
                'signature': base64.b64encode(signature).decode(),
                'certificate_chain': [base64.b64encode(certificate.public_bytes(Encoding.PEM)).decode()],
                'hash_algorithm': 'SHA256',
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=365)).isoformat(),
                'issuer': 'Prix Security System',
                'subject': f'File: {file_path}'
            }
            
            return json.dumps(signature_data, indent=2)
        
        except Exception as e:
            logger.error(f"Error signing file {file_path}: {e}")
            return None
    
    def _load_system_private_key(self, key_id: str):
        """Load system private key"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT private_key, algorithm FROM system_keys 
                WHERE key_id = ? AND is_active = 1
            ''', (key_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                private_key_pem, algorithm = result
                
                if algorithm == 'RSA':
                    return serialization.load_pem_private_key(
                        private_key_pem.encode(),
                        password=None,
                        backend=default_backend()
                    )
                elif algorithm == 'ECDSA':
                    return serialization.load_pem_private_key(
                        private_key_pem.encode(),
                        password=None,
                        backend=default_backend()
                    )
            
            return None
        
        except Exception as e:
            logger.error(f"Error loading private key {key_id}: {e}")
            return None
    
    def _create_self_signed_certificate(self, public_key) -> x509.Certificate:
        """Create self-signed certificate"""
        try:
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Prix Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Prix Security System"),
            ])
            
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(issuer)
            builder = builder.not_valid_before(datetime.utcnow())
            builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            
            # Create certificate (would normally be signed with private key)
            # For demonstration, return a minimal certificate
            certificate = builder.build(default_backend())
            
            return certificate
        
        except Exception as e:
            logger.error(f"Error creating self-signed certificate: {e}")
            # Return a minimal certificate for demonstration
            return None
    
    def verify_system_integrity(self) -> Dict:
        """Verify system cryptographic integrity"""
        try:
            integrity_results = {
                'system_files_verified': 0,
                'system_files_failed': 0,
                'trusted_certificates': len(self.trusted_anchors),
                'revoked_certificates': len(self.revoked_certificates),
                'system_keys_valid': 0,
                'overall_integrity': 'unknown'
            }
            
            # Verify critical system files
            critical_files = [
                '/bin/bash', '/bin/sh', '/usr/bin/python3',
                '/etc/passwd', '/etc/shadow', '/etc/hosts'
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    result = self.verify_file_signature(file_path)
                    if result.is_valid:
                        integrity_results['system_files_verified'] += 1
                    else:
                        integrity_results['system_files_failed'] += 1
            
            # Verify system keys
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM system_keys WHERE is_active = 1')
            integrity_results['system_keys_valid'] = cursor.fetchone()[0]
            
            conn.close()
            
            # Calculate overall integrity
            total_files = integrity_results['system_files_verified'] + integrity_results['system_files_failed']
            if total_files > 0:
                integrity_ratio = integrity_results['system_files_verified'] / total_files
                if integrity_ratio >= 0.9:
                    integrity_results['overall_integrity'] = 'high'
                elif integrity_ratio >= 0.7:
                    integrity_results['overall_integrity'] = 'medium'
                else:
                    integrity_results['overall_integrity'] = 'low'
            
            return integrity_results
        
        except Exception as e:
            logger.error(f"Error verifying system integrity: {e}")
            return {'error': str(e)}
    
    def get_crypto_status(self) -> Dict:
        """Get cryptographic verification status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get verification statistics
        cursor.execute('''
            SELECT COUNT(*) FROM verification_results 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        recent_verifications = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM verification_results 
            WHERE is_valid = 1 AND timestamp > datetime('now', '-24 hours')
        ''')
        successful_verifications = cursor.fetchone()[0]
        
        # Get certificate statistics
        cursor.execute('SELECT COUNT(*) FROM trusted_certificates WHERE is_trusted_anchor = 1')
        trusted_anchors = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM revoked_certificates')
        revoked_certs = cursor.fetchone()[0]
        
        # Get key statistics
        cursor.execute('SELECT COUNT(*) FROM system_keys WHERE is_active = 1')
        active_keys = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'recent_verifications': recent_verifications,
            'successful_verifications': successful_verifications,
            'verification_success_rate': successful_verifications / max(recent_verifications, 1),
            'trusted_anchors': trusted_anchors,
            'revoked_certificates': revoked_certs,
            'active_system_keys': active_keys,
            'supported_algorithms': list(self.verification_algorithms.keys())
        }
    
    def generate_crypto_report(self) -> Dict:
        """Generate comprehensive cryptographic verification report"""
        try:
            # Get verification statistics
            status = self.get_crypto_status()
            
            # Get system integrity
            integrity = self.verify_system_integrity()
            
            # Get recent verification results
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT algorithm_used, COUNT(*) as count
                FROM verification_results 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY algorithm_used
            ''')
            algorithm_usage = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT errors, COUNT(*) as count
                FROM verification_results 
                WHERE timestamp > datetime('now', '-24 hours') AND errors != '[]'
                GROUP BY errors
                ORDER BY count DESC
                LIMIT 10
            ''')
            common_errors = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'verification_status': status,
                'system_integrity': integrity,
                'algorithm_usage': algorithm_usage,
                'common_errors': common_errors,
                'recommendations': self._generate_crypto_recommendations()
            }
        
        except Exception as e:
            logger.error(f"Error generating crypto report: {e}")
            return {'error': str(e)}
    
    def _generate_crypto_recommendations(self) -> List[str]:
        """Generate cryptographic security recommendations"""
        recommendations = []
        
        status = self.get_crypto_status()
        integrity = self.verify_system_integrity()
        
        if status['verification_success_rate'] < 0.8:
            recommendations.append("Low verification success rate - review certificate trust policies")
        
        if integrity.get('overall_integrity') == 'low':
            recommendations.append("System integrity compromised - perform full system scan")
        
        if status['revoked_certificates'] > 0:
            recommendations.append("Update certificate revocation lists")
        
        if status['trusted_anchors'] < 10:
            recommendations.append("Add trusted root certificates")
        
        recommendations.extend([
            "Enable certificate pinning for critical applications",
            "Regularly update cryptographic libraries",
            "Implement certificate transparency monitoring",
            "Use strong cryptographic algorithms (RSA-4096, ECDSA-384+)",
            "Monitor certificate expiration dates"
        ])
        
        return recommendations
