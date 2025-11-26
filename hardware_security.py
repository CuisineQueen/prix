#!/usr/bin/env python3
"""
Advanced Hardware-Level Security Checks System
TPM, secure boot, hardware authentication, and physical security monitoring
"""

import os
import sys
import time
import threading
import logging
import json
import hashlib
import base64
import subprocess
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# Hardware security libraries
try:
    import psutil
    import platform
    import uuid
    import ctypes
    from ctypes import wintypes
except ImportError:
    print("Installing hardware security libraries...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil
    import platform
    import uuid
    import ctypes
    from ctypes import wintypes

logger = logging.getLogger(__name__)

@dataclass
class HardwareComponent:
    """Hardware component information"""
    component_id: str
    component_type: str
    manufacturer: str
    model: str
    serial_number: str
    firmware_version: str
    status: str
    security_features: Set[str]
    last_verified: datetime
    trust_level: float

@dataclass
class HardwareSecurityEvent:
    """Hardware security event"""
    timestamp: datetime
    event_type: str
    component_id: str
    severity: str
    description: str
    details: Dict
    risk_score: float
    mitigation: str

@dataclass
class TPMStatus:
    """TPM status information"""
    tpm_present: bool
    tpm_version: str
    tpm_enabled: bool
    tpm_activated: bool
    tpm_owned: bool
    endorsement_key: str
    attestation_identity_key: str
    storage_root_key: str
    pcr_values: Dict[str, str]
    security_level: str

@dataclass
class SecureBootStatus:
    """Secure boot status"""
    secure_boot_enabled: bool
    uefi_enabled: bool
    boot_mode: str
    signature_status: Dict[str, bool]
    certificate_chain: List[str]
    platform_key: str
    key_exchange_key: str
    signature_database: List[str]

@dataclass
class HardwareFingerprint:
    """Hardware fingerprint for device identification"""
    device_id: str
    cpu_id: str
    memory_signature: str
    disk_signature: str
    network_signature: str
    bios_signature: str
    tpm_signature: str
    created_at: datetime
    verified_at: datetime
    trust_score: float

class HardwareSecurity:
    """Advanced hardware-level security system"""
    
    def __init__(self, db_path: str = "prix_hardware.db"):
        self.db_path = db_path
        self.monitoring = False
        
        # Hardware security components
        self.hardware_components = {}
        self.tpm_status = None
        self.secure_boot_status = None
        self.hardware_fingerprint = None
        self.security_events = []
        
        # Security thresholds
        self.trust_thresholds = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3
        }
        
        # Hardware security features
        self.supported_features = {
            'tpm': False,
            'secure_boot': False,
            'virtualization': False,
            'encryption': False,
            'biometric': False,
            'trusted_execution': False
        }
        
        # Initialize hardware security
        self.init_database()
        self.detect_hardware_components()
        self.check_tpm_status()
        self.check_secure_boot_status()
        self.create_hardware_fingerprint()
        self.start_hardware_monitoring()
    
    def init_database(self):
        """Initialize hardware security database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Hardware components table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardware_components (
                component_id TEXT PRIMARY KEY,
                component_type TEXT,
                manufacturer TEXT,
                model TEXT,
                serial_number TEXT,
                firmware_version TEXT,
                status TEXT,
                security_features TEXT,
                last_verified TEXT,
                trust_level REAL,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # TPM status table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tpm_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tpm_present BOOLEAN,
                tpm_version TEXT,
                tpm_enabled BOOLEAN,
                tpm_activated BOOLEAN,
                tpm_owned BOOLEAN,
                endorsement_key TEXT,
                attestation_identity_key TEXT,
                storage_root_key TEXT,
                pcr_values TEXT,
                security_level TEXT,
                checked_at TEXT
            )
        ''')
        
        # Secure boot status table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secure_boot_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secure_boot_enabled BOOLEAN,
                uefi_enabled BOOLEAN,
                boot_mode TEXT,
                signature_status TEXT,
                certificate_chain TEXT,
                platform_key TEXT,
                key_exchange_key TEXT,
                signature_database TEXT,
                checked_at TEXT
            )
        ''')
        
        # Hardware fingerprints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardware_fingerprints (
                device_id TEXT PRIMARY KEY,
                cpu_id TEXT,
                memory_signature TEXT,
                disk_signature TEXT,
                network_signature TEXT,
                bios_signature TEXT,
                tpm_signature TEXT,
                created_at TEXT,
                verified_at TEXT,
                trust_score REAL,
                is_current BOOLEAN DEFAULT 1
            )
        ''')
        
        # Hardware security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardware_security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                component_id TEXT,
                severity TEXT,
                description TEXT,
                details TEXT,
                risk_score REAL,
                mitigation TEXT
            )
        ''')
        
        # Hardware baselines table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardware_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component_id TEXT,
                baseline_type TEXT,
                baseline_data TEXT,
                created_at TEXT,
                last_verified TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def detect_hardware_components(self):
        """Detect and catalog hardware components"""
        logger.info("Detecting hardware components...")
        
        # CPU
        cpu_info = self._detect_cpu()
        self.hardware_components['cpu'] = cpu_info
        
        # Memory
        memory_info = self._detect_memory()
        self.hardware_components['memory'] = memory_info
        
        # Storage
        storage_info = self._detect_storage()
        for i, storage in enumerate(storage_info):
            self.hardware_components[f'storage_{i}'] = storage
        
        # Network interfaces
        network_info = self._detect_network_interfaces()
        for i, interface in enumerate(network_info):
            self.hardware_components[f'network_{i}'] = interface
        
        # BIOS/UEFI
        bios_info = self._detect_bios()
        self.hardware_components['bios'] = bios_info
        
        # Graphics
        graphics_info = self._detect_graphics()
        for i, gpu in enumerate(graphics_info):
            self.hardware_components[f'graphics_{i}'] = gpu
        
        # Store components in database
        for component_id, component in self.hardware_components.items():
            self._store_hardware_component(component)
        
        logger.info(f"Detected {len(self.hardware_components)} hardware components")
    
    def _detect_cpu(self) -> HardwareComponent:
        """Detect CPU information"""
        try:
            cpu_info = platform.processor()
            cpu_freq = psutil.cpu_freq()
            cpu_count = psutil.cpu_count(logical=True)
            cpu_physical = psutil.cpu_count(logical=False)
            
            # Get CPU features
            cpu_features = set()
            if hasattr(psutil, 'cpu_freq'):
                cpu_features.add('frequency_scaling')
            
            # Check for virtualization support
            if self._check_virtualization_support():
                cpu_features.add('virtualization')
            
            # Check for security features
            if self._check_cpu_security_features():
                cpu_features.add('security_extensions')
            
            component = HardwareComponent(
                component_id='cpu',
                component_type='CPU',
                manufacturer=self._extract_cpu_manufacturer(cpu_info),
                model=cpu_info,
                serial_number=self._get_cpu_serial(),
                firmware_version=self._get_cpu_microcode(),
                status='active',
                security_features=cpu_features,
                last_verified=datetime.now(),
                trust_level=0.8
            )
            
            return component
        
        except Exception as e:
            logger.error(f"Error detecting CPU: {e}")
            return HardwareComponent(
                component_id='cpu',
                component_type='CPU',
                manufacturer='unknown',
                model='unknown',
                serial_number='unknown',
                firmware_version='unknown',
                status='error',
                security_features=set(),
                last_verified=datetime.now(),
                trust_level=0.0
            )
    
    def _detect_memory(self) -> HardwareComponent:
        """Detect memory information"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            # Get memory modules (simplified)
            memory_modules = []
            
            # Check for memory security features
            security_features = set()
            if virtual_memory.total > 8 * 1024**3:  # > 8GB
                security_features.add('ecc_capable')  # Assume ECC for large memory
            
            component = HardwareComponent(
                component_id='memory',
                component_type='Memory',
                manufacturer='unknown',
                model=f'{virtual_memory.total // (1024**3)}GB',
                serial_number='unknown',
                firmware_version='unknown',
                status='active',
                security_features=security_features,
                last_verified=datetime.now(),
                trust_level=0.7
            )
            
            return component
        
        except Exception as e:
            logger.error(f"Error detecting memory: {e}")
            return HardwareComponent(
                component_id='memory',
                component_type='Memory',
                manufacturer='unknown',
                model='unknown',
                serial_number='unknown',
                firmware_version='unknown',
                status='error',
                security_features=set(),
                last_verified=datetime.now(),
                trust_level=0.0
            )
    
    def _detect_storage(self) -> List[HardwareComponent]:
        """Detect storage devices"""
        storage_devices = []
        
        try:
            disk_partitions = psutil.disk_partitions()
            
            for partition in disk_partitions:
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    
                    # Get disk model (simplified)
                    disk_model = f"{partition.device} ({disk_usage.total // (1024**3)}GB)"
                    
                    # Check for encryption support
                    security_features = set()
                    if self._check_disk_encryption(partition.device):
                        security_features.add('encryption')
                    
                    component = HardwareComponent(
                        component_id=f"storage_{partition.device}",
                        component_type='Storage',
                        manufacturer='unknown',
                        model=disk_model,
                        serial_number='unknown',
                        firmware_version='unknown',
                        status='active',
                        security_features=security_features,
                        last_verified=datetime.now(),
                        trust_level=0.6
                    )
                    
                    storage_devices.append(component)
                
                except Exception as e:
                    logger.debug(f"Error detecting storage {partition.device}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting storage devices: {e}")
        
        return storage_devices
    
    def _detect_network_interfaces(self) -> List[HardwareComponent]:
        """Detect network interfaces"""
        network_interfaces = []
        
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                try:
                    stats = net_if_stats.get(interface_name)
                    
                    # Get MAC address
                    mac_address = None
                    for addr in addresses:
                        if addr.family == psutil.AF_LINK:
                            mac_address = addr.address
                            break
                    
                    # Check for security features
                    security_features = set()
                    if mac_address:
                        security_features.add('mac_address')
                    
                    if stats and stats.isup:
                        security_features.add('active')
                    
                    component = HardwareComponent(
                        component_id=f"network_{interface_name}",
                        component_type='Network',
                        manufacturer='unknown',
                        model=interface_name,
                        serial_number=mac_address or 'unknown',
                        firmware_version='unknown',
                        status='active' if (stats and stats.isup) else 'inactive',
                        security_features=security_features,
                        last_verified=datetime.now(),
                        trust_level=0.7
                    )
                    
                    network_interfaces.append(component)
                
                except Exception as e:
                    logger.debug(f"Error detecting network interface {interface_name}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting network interfaces: {e}")
        
        return network_interfaces
    
    def _detect_bios(self) -> HardwareComponent:
        """Detect BIOS/UEFI information"""
        try:
            # Get BIOS information (platform-specific)
            bios_info = {}
            
            if platform.system() == 'Linux':
                bios_info = self._get_linux_bios_info()
            elif platform.system() == 'Windows':
                bios_info = self._get_windows_bios_info()
            
            # Check for security features
            security_features = set()
            if bios_info.get('uefi', False):
                security_features.add('uefi')
            
            if bios_info.get('secure_boot', False):
                security_features.add('secure_boot')
            
            component = HardwareComponent(
                component_id='bios',
                component_type='BIOS',
                manufacturer=bios_info.get('vendor', 'unknown'),
                model=bios_info.get('version', 'unknown'),
                serial_number=bios_info.get('serial', 'unknown'),
                firmware_version=bios_info.get('release_date', 'unknown'),
                status='active',
                security_features=security_features,
                last_verified=datetime.now(),
                trust_level=0.8
            )
            
            return component
        
        except Exception as e:
            logger.error(f"Error detecting BIOS: {e}")
            return HardwareComponent(
                component_id='bios',
                component_type='BIOS',
                manufacturer='unknown',
                model='unknown',
                serial_number='unknown',
                firmware_version='unknown',
                status='error',
                security_features=set(),
                last_verified=datetime.now(),
                trust_level=0.0
            )
    
    def _detect_graphics(self) -> List[HardwareComponent]:
        """Detect graphics devices"""
        graphics_devices = []
        
        try:
            # Simplified graphics detection
            # In a real implementation, this would use platform-specific APIs
            
            # Assume basic graphics
            component = HardwareComponent(
                component_id='graphics_0',
                component_type='Graphics',
                manufacturer='unknown',
                model='integrated',
                serial_number='unknown',
                firmware_version='unknown',
                status='active',
                security_features=set(),
                last_verified=datetime.now(),
                trust_level=0.5
            )
            
            graphics_devices.append(component)
        
        except Exception as e:
            logger.error(f"Error detecting graphics devices: {e}")
        
        return graphics_devices
    
    def _extract_cpu_manufacturer(self, cpu_info: str) -> str:
        """Extract CPU manufacturer from CPU info"""
        cpu_lower = cpu_info.lower()
        if 'intel' in cpu_lower:
            return 'Intel'
        elif 'amd' in cpu_lower:
            return 'AMD'
        elif 'arm' in cpu_lower:
            return 'ARM'
        else:
            return 'Unknown'
    
    def _get_cpu_serial(self) -> str:
        """Get CPU serial number"""
        try:
            if platform.system() == 'Linux':
                # Try to read from /proc/cpuinfo
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if line.startswith('serial'):
                                return line.split(':')[1].strip()
                except:
                    pass
            
            # Fallback to system UUID
            return str(uuid.getnode())
        
        except Exception:
            return 'unknown'
    
    def _get_cpu_microcode(self) -> str:
        """Get CPU microcode version"""
        try:
            if platform.system() == 'Linux':
                try:
                    with open('/sys/devices/system/cpu/cpu0/microcode/version', 'r') as f:
                        return f.read().strip()
                except:
                    pass
            
            return 'unknown'
        
        except Exception:
            return 'unknown'
    
    def _check_virtualization_support(self) -> bool:
        """Check if CPU supports virtualization"""
        try:
            if platform.system() == 'Linux':
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                        return 'vmx' in cpuinfo or 'svm' in cpuinfo
                except:
                    pass
            
            return False
        
        except Exception:
            return False
    
    def _check_cpu_security_features(self) -> bool:
        """Check for CPU security features"""
        try:
            if platform.system() == 'Linux':
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                        return any(feature in cpuinfo.lower() 
                                 for feature in ['smep', 'smap', 'nx', 'pae'])
                except:
                    pass
            
            return False
        
        except Exception:
            return False
    
    def _check_disk_encryption(self, device: str) -> bool:
        """Check if disk is encrypted"""
        try:
            if platform.system() == 'Linux':
                # Check for LUKS encryption
                try:
                    result = subprocess.run(['cryptsetup', 'status', device], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
                except:
                    pass
            
            return False
        
        except Exception:
            return False
    
    def _get_linux_bios_info(self) -> Dict:
        """Get BIOS information on Linux"""
        bios_info = {}
        
        try:
            # Try to read from DMI tables
            try:
                result = subprocess.run(['dmidecode', '-s', 'system-manufacturer'], 
                                      capture_output=True, text=True)
                bios_info['vendor'] = result.stdout.strip()
            except:
                pass
            
            try:
                result = subprocess.run(['dmidecode', '-s', 'bios-version'], 
                                      capture_output=True, text=True)
                bios_info['version'] = result.stdout.strip()
            except:
                pass
            
            try:
                result = subprocess.run(['dmidecode', '-s', 'system-serial-number'], 
                                      capture_output=True, text=True)
                bios_info['serial'] = result.stdout.strip()
            except:
                pass
            
            # Check for UEFI
            try:
                if os.path.exists('/sys/firmware/efi'):
                    bios_info['uefi'] = True
                else:
                    bios_info['uefi'] = False
            except:
                bios_info['uefi'] = False
        
        except Exception as e:
            logger.error(f"Error getting Linux BIOS info: {e}")
        
        return bios_info
    
    def _get_windows_bios_info(self) -> Dict:
        """Get BIOS information on Windows"""
        bios_info = {}
        
        try:
            # Use WMI to get BIOS information
            try:
                result = subprocess.run(['wmic', 'bios', 'get', 'manufacturer', '/value'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key.strip() == 'Manufacturer':
                            bios_info['vendor'] = value.strip()
            except:
                pass
            
            try:
                result = subprocess.run(['wmic', 'bios', 'get', 'version', '/value'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key.strip() == 'SMBIOSBIOSVersion':
                            bios_info['version'] = value.strip()
            except:
                pass
            
            # Check for UEFI
            try:
                result = subprocess.run(['wmic', 'computersystem', 'get', 'systemtype', '/value'], 
                                      capture_output=True, text=True)
                bios_info['uefi'] = 'UEFI' in result.stdout
            except:
                bios_info['uefi'] = False
        
        except Exception as e:
            logger.error(f"Error getting Windows BIOS info: {e}")
        
        return bios_info
    
    def _store_hardware_component(self, component: HardwareComponent):
        """Store hardware component in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO hardware_components 
            (component_id, component_type, manufacturer, model, serial_number,
             firmware_version, status, security_features, last_verified, trust_level,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            component.component_id,
            component.component_type,
            component.manufacturer,
            component.model,
            component.serial_number,
            component.firmware_version,
            component.status,
            json.dumps(list(component.security_features)),
            component.last_verified.isoformat(),
            component.trust_level,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def check_tpm_status(self):
        """Check TPM status and capabilities"""
        logger.info("Checking TPM status...")
        
        try:
            tpm_info = self._get_tpm_info()
            
            self.tpm_status = TPMStatus(
                tpm_present=tpm_info.get('present', False),
                tpm_version=tpm_info.get('version', 'unknown'),
                tpm_enabled=tpm_info.get('enabled', False),
                tpm_activated=tpm_info.get('activated', False),
                tpm_owned=tpm_info.get('owned', False),
                endorsement_key=tpm_info.get('ek', ''),
                attestation_identity_key=tpm_info.get('aik', ''),
                storage_root_key=tpm_info.get('srk', ''),
                pcr_values=tpm_info.get('pcr', {}),
                security_level=self._calculate_tpm_security_level(tpm_info)
            )
            
            self.supported_features['tpm'] = self.tpm_status.tpm_present
            self._store_tpm_status()
            
            logger.info(f"TPM Status: Present={self.tpm_status.tpm_present}, "
                       f"Enabled={self.tpm_status.tpm_enabled}, "
                       f"Version={self.tpm_status.tpm_version}")
        
        except Exception as e:
            logger.error(f"Error checking TPM status: {e}")
            self.tpm_status = TPMStatus(
                tpm_present=False, tpm_version='unknown', tpm_enabled=False,
                tpm_activated=False, tpm_owned=False, endorsement_key='',
                attestation_identity_key='', storage_root_key='', pcr_values={},
                security_level='none'
            )
    
    def _get_tpm_info(self) -> Dict:
        """Get TPM information"""
        tpm_info = {}
        
        try:
            if platform.system() == 'Linux':
                tpm_info = self._get_linux_tpm_info()
            elif platform.system() == 'Windows':
                tpm_info = self._get_windows_tpm_info()
        
        except Exception as e:
            logger.error(f"Error getting TPM info: {e}")
        
        return tpm_info
    
    def _get_linux_tpm_info(self) -> Dict:
        """Get TPM information on Linux"""
        tpm_info = {'present': False}
        
        try:
            # Check for TPM device
            if os.path.exists('/dev/tpm0') or os.path.exists('/dev/tpm'):
                tpm_info['present'] = True
                
                # Try to get TPM version
                try:
                    result = subprocess.run(['tpm2_getcap', 'properties-fixed'], 
                                          capture_output=True, text=True)
                    if 'TPM2' in result.stdout:
                        tpm_info['version'] = '2.0'
                    else:
                        tpm_info['version'] = '1.2'
                except:
                    tpm_info['version'] = 'unknown'
                
                # Check if TPM is enabled
                tpm_info['enabled'] = True
                tpm_info['activated'] = True
                tpm_info['owned'] = True
        
        except Exception as e:
            logger.error(f"Error getting Linux TPM info: {e}")
        
        return tpm_info
    
    def _get_windows_tpm_info(self) -> Dict:
        """Get TPM information on Windows"""
        tpm_info = {'present': False}
        
        try:
            # Use PowerShell to get TPM info
            ps_command = '''
            Get-Tpm | ConvertTo-Json | Out-String
            '''
            
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                tpm_data = json.loads(result.stdout)
                
                tpm_info['present'] = tpm_data.get('TpmPresent', False)
                tpm_info['enabled'] = tpm_data.get('TpmEnabled', False)
                tpm_info['activated'] = tpm_data.get('TpmActivated', False)
                tpm_info['owned'] = tpm_data.get('TpmOwned', False)
                tpm_info['version'] = tpm_data.get('ManufacturerVersion', 'unknown')
        
        except Exception as e:
            logger.error(f"Error getting Windows TPM info: {e}")
        
        return tpm_info
    
    def _calculate_tpm_security_level(self, tpm_info: Dict) -> str:
        """Calculate TPM security level"""
        if not tpm_info.get('present', False):
            return 'none'
        
        if tpm_info.get('version') == '2.0':
            if tpm_info.get('enabled') and tpm_info.get('activated') and tpm_info.get('owned'):
                return 'high'
            else:
                return 'medium'
        else:
            return 'low'
    
    def _store_tpm_status(self):
        """Store TPM status in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO tpm_status 
            (tpm_present, tpm_version, tpm_enabled, tpm_activated, tpm_owned,
             endorsement_key, attestation_identity_key, storage_root_key,
             pcr_values, security_level, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.tpm_status.tpm_present,
            self.tpm_status.tpm_version,
            self.tpm_status.tpm_enabled,
            self.tpm_status.tpm_activated,
            self.tpm_status.tpm_owned,
            self.tpm_status.endorsement_key,
            self.tpm_status.attestation_identity_key,
            self.tpm_status.storage_root_key,
            json.dumps(self.tpm_status.pcr_values),
            self.tpm_status.security_level,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def check_secure_boot_status(self):
        """Check secure boot status"""
        logger.info("Checking secure boot status...")
        
        try:
            secure_boot_info = self._get_secure_boot_info()
            
            self.secure_boot_status = SecureBootStatus(
                secure_boot_enabled=secure_boot_info.get('enabled', False),
                uefi_enabled=secure_boot_info.get('uefi', False),
                boot_mode=secure_boot_info.get('boot_mode', 'unknown'),
                signature_status=secure_boot_info.get('signatures', {}),
                certificate_chain=secure_boot_info.get('certificates', []),
                platform_key=secure_boot_info.get('pk', ''),
                key_exchange_key=secure_boot_info.get('kek', ''),
                signature_database=secure_boot_info.get('db', [])
            )
            
            self.supported_features['secure_boot'] = self.secure_boot_status.secure_boot_enabled
            self._store_secure_boot_status()
            
            logger.info(f"Secure Boot: Enabled={self.secure_boot_status.secure_boot_enabled}, "
                       f"UEFI={self.secure_boot_status.uefi_enabled}")
        
        except Exception as e:
            logger.error(f"Error checking secure boot status: {e}")
            self.secure_boot_status = SecureBootStatus(
                secure_boot_enabled=False, uefi_enabled=False, boot_mode='unknown',
                signature_status={}, certificate_chain=[], platform_key='',
                key_exchange_key='', signature_database=[]
            )
    
    def _get_secure_boot_info(self) -> Dict:
        """Get secure boot information"""
        secure_boot_info = {}
        
        try:
            if platform.system() == 'Linux':
                secure_boot_info = self._get_linux_secure_boot_info()
            elif platform.system() == 'Windows':
                secure_boot_info = self._get_windows_secure_boot_info()
        
        except Exception as e:
            logger.error(f"Error getting secure boot info: {e}")
        
        return secure_boot_info
    
    def _get_linux_secure_boot_info(self) -> Dict:
        """Get secure boot information on Linux"""
        secure_boot_info = {'enabled': False, 'uefi': False}
        
        try:
            # Check if UEFI is being used
            if os.path.exists('/sys/firmware/efi'):
                secure_boot_info['uefi'] = True
                
                # Check secure boot status
                try:
                    with open('/sys/firmware/efi/vars/SecureBoot-*/data', 'rb') as f:
                        secure_boot_data = f.read()
                        secure_boot_info['enabled'] = secure_boot_data[0] == 1
                except:
                    pass
                
                secure_boot_info['boot_mode'] = 'uefi'
            else:
                secure_boot_info['boot_mode'] = 'bios'
        
        except Exception as e:
            logger.error(f"Error getting Linux secure boot info: {e}")
        
        return secure_boot_info
    
    def _get_windows_secure_boot_info(self) -> Dict:
        """Get secure boot information on Windows"""
        secure_boot_info = {'enabled': False, 'uefi': False}
        
        try:
            # Use PowerShell to get secure boot info
            ps_command = '''
            Confirm-SecureBootUEFI | ConvertTo-Json | Out-String
            '''
            
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                secure_boot_data = json.loads(result.stdout)
                secure_boot_info['enabled'] = secure_boot_data
                secure_boot_info['uefi'] = True
                secure_boot_info['boot_mode'] = 'uefi'
        
        except Exception as e:
            logger.error(f"Error getting Windows secure boot info: {e}")
        
        return secure_boot_info
    
    def _store_secure_boot_status(self):
        """Store secure boot status in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO secure_boot_status 
            (secure_boot_enabled, uefi_enabled, boot_mode, signature_status,
             certificate_chain, platform_key, key_exchange_key, signature_database, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.secure_boot_status.secure_boot_enabled,
            self.secure_boot_status.uefi_enabled,
            self.secure_boot_status.boot_mode,
            json.dumps(self.secure_boot_status.signature_status),
            json.dumps(self.secure_boot_status.certificate_chain),
            self.secure_boot_status.platform_key,
            self.secure_boot_status.key_exchange_key,
            json.dumps(self.secure_boot_status.signature_database),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def create_hardware_fingerprint(self):
        """Create unique hardware fingerprint"""
        logger.info("Creating hardware fingerprint...")
        
        try:
            # Generate device ID
            device_id = self._generate_device_id()
            
            # Collect hardware signatures
            cpu_id = self._generate_cpu_signature()
            memory_signature = self._generate_memory_signature()
            disk_signature = self._generate_disk_signature()
            network_signature = self._generate_network_signature()
            bios_signature = self._generate_bios_signature()
            tpm_signature = self._generate_tpm_signature()
            
            self.hardware_fingerprint = HardwareFingerprint(
                device_id=device_id,
                cpu_id=cpu_id,
                memory_signature=memory_signature,
                disk_signature=disk_signature,
                network_signature=network_signature,
                bios_signature=bios_signature,
                tpm_signature=tpm_signature,
                created_at=datetime.now(),
                verified_at=datetime.now(),
                trust_score=self._calculate_fingerprint_trust()
            )
            
            self._store_hardware_fingerprint()
            
            logger.info(f"Hardware fingerprint created: {device_id}")
        
        except Exception as e:
            logger.error(f"Error creating hardware fingerprint: {e}")
    
    def _generate_device_id(self) -> str:
        """Generate unique device ID"""
        try:
            # Combine multiple hardware identifiers
            components = []
            
            # CPU info
            cpu_info = platform.processor()
            if cpu_info:
                components.append(cpu_info)
            
            # System UUID
            system_uuid = str(uuid.getnode())
            components.append(system_uuid)
            
            # Hostname
            hostname = platform.node()
            components.append(hostname)
            
            # Create hash
            combined = ''.join(components)
            device_hash = hashlib.sha256(combined.encode()).hexdigest()
            
            return f"device_{device_hash[:16]}"
        
        except Exception:
            return f"device_{secrets.token_hex(8)}"
    
    def _generate_cpu_signature(self) -> str:
        """Generate CPU signature"""
        try:
            cpu_info = platform.processor()
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            signature_data = f"{cpu_info}:{cpu_count}:{cpu_freq}"
            return hashlib.sha256(signature_data.encode()).hexdigest()
        
        except Exception:
            return "unknown"
    
    def _generate_memory_signature(self) -> str:
        """Generate memory signature"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            signature_data = f"{virtual_memory.total}:{virtual_memory.available}:{swap_memory.total}"
            return hashlib.sha256(signature_data.encode()).hexdigest()
        
        except Exception:
            return "unknown"
    
    def _generate_disk_signature(self) -> str:
        """Generate disk signature"""
        try:
            disk_partitions = psutil.disk_partitions()
            signatures = []
            
            for partition in disk_partitions:
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    signature = f"{partition.device}:{disk_usage.total}"
                    signatures.append(signature)
                except:
                    continue
            
            combined = ':'.join(signatures)
            return hashlib.sha256(combined.encode()).hexdigest()
        
        except Exception:
            return "unknown"
    
    def _generate_network_signature(self) -> str:
        """Generate network signature"""
        try:
            net_if_addrs = psutil.net_if_addrs()
            signatures = []
            
            for interface_name, addresses in net_if_addrs.items():
                for addr in addresses:
                    if addr.family == psutil.AF_LINK:
                        signatures.append(f"{interface_name}:{addr.address}")
            
            combined = ':'.join(signatures)
            return hashlib.sha256(combined.encode()).hexdigest()
        
        except Exception:
            return "unknown"
    
    def _generate_bios_signature(self) -> str:
        """Generate BIOS signature"""
        try:
            bios_component = self.hardware_components.get('bios')
            if bios_component:
                signature_data = f"{bios_component.manufacturer}:{bios_component.model}:{bios_component.firmware_version}"
                return hashlib.sha256(signature_data.encode()).hexdigest()
        
        except Exception:
            pass
        
        return "unknown"
    
    def _generate_tpm_signature(self) -> str:
        """Generate TPM signature"""
        try:
            if self.tpm_status and self.tpm_status.tpm_present:
                signature_data = f"{self.tpm_status.tpm_version}:{self.tpm_status.endorsement_key}"
                return hashlib.sha256(signature_data.encode()).hexdigest()
        
        except Exception:
            pass
        
        return "none"
    
    def _calculate_fingerprint_trust(self) -> float:
        """Calculate trust score for fingerprint"""
        trust_score = 0.0
        
        try:
            # Base score
            trust_score += 0.3
            
            # TPM presence
            if self.tpm_status and self.tpm_status.tpm_present:
                trust_score += 0.2
                if self.tpm_status.tpm_enabled:
                    trust_score += 0.1
            
            # Secure boot
            if self.secure_boot_status and self.secure_boot_status.secure_boot_enabled:
                trust_score += 0.2
            
            # UEFI
            if self.secure_boot_status and self.secure_boot_status.uefi_enabled:
                trust_score += 0.1
            
            # Hardware diversity
            component_types = set(comp.component_type for comp in self.hardware_components.values())
            if len(component_types) >= 4:
                trust_score += 0.1
            
            return min(trust_score, 1.0)
        
        except Exception:
            return 0.0
    
    def _store_hardware_fingerprint(self):
        """Store hardware fingerprint in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO hardware_fingerprints 
            (device_id, cpu_id, memory_signature, disk_signature, network_signature,
             bios_signature, tpm_signature, created_at, verified_at, trust_score, is_current)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.hardware_fingerprint.device_id,
            self.hardware_fingerprint.cpu_id,
            self.hardware_fingerprint.memory_signature,
            self.hardware_fingerprint.disk_signature,
            self.hardware_fingerprint.network_signature,
            self.hardware_fingerprint.bios_signature,
            self.hardware_fingerprint.tpm_signature,
            self.hardware_fingerprint.created_at.isoformat(),
            self.hardware_fingerprint.verified_at.isoformat(),
            self.hardware_fingerprint.trust_score,
            True
        ))
        
        conn.commit()
        conn.close()
    
    def start_hardware_monitoring(self):
        """Start continuous hardware monitoring"""
        self.monitoring = True
        logger.info("Starting hardware security monitoring...")
        
        # Start monitoring threads
        threading.Thread(target=self._hardware_integrity_loop, daemon=True).start()
        threading.Thread(target=self._component_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._tpm_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._fingerprint_verification_loop, daemon=True).start()
        
        logger.info("Hardware security monitoring started")
    
    def _hardware_integrity_loop(self):
        """Monitor hardware integrity"""
        while self.monitoring:
            try:
                # Check for hardware changes
                changes = self._detect_hardware_changes()
                
                for change in changes:
                    self._handle_hardware_change(change)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in hardware integrity monitoring: {e}")
                time.sleep(600)
    
    def _detect_hardware_changes(self) -> List[Dict]:
        """Detect changes in hardware configuration"""
        changes = []
        
        try:
            # Re-detect hardware components
            current_components = {}
            
            # CPU
            current_cpu = self._detect_cpu()
            current_components['cpu'] = current_cpu
            
            # Memory
            current_memory = self._detect_memory()
            current_components['memory'] = current_memory
            
            # Network interfaces
            current_network = self._detect_network_interfaces()
            for i, interface in enumerate(current_network):
                current_components[f'network_{i}'] = interface
            
            # Compare with stored components
            for component_id, current_component in current_components.items():
                stored_component = self.hardware_components.get(component_id)
                
                if stored_component:
                    # Check for changes
                    if self._component_changed(stored_component, current_component):
                        changes.append({
                            'type': 'component_changed',
                            'component_id': component_id,
                            'old_component': stored_component,
                            'new_component': current_component
                        })
                else:
                    # New component detected
                    changes.append({
                        'type': 'component_added',
                        'component_id': component_id,
                        'component': current_component
                    })
            
            # Check for removed components
            for component_id, stored_component in self.hardware_components.items():
                if component_id not in current_components:
                    changes.append({
                        'type': 'component_removed',
                        'component_id': component_id,
                        'component': stored_component
                    })
        
        except Exception as e:
            logger.error(f"Error detecting hardware changes: {e}")
        
        return changes
    
    def _component_changed(self, old_component: HardwareComponent, new_component: HardwareComponent) -> bool:
        """Check if hardware component has changed"""
        try:
            # Check critical fields
            if old_component.manufacturer != new_component.manufacturer:
                return True
            
            if old_component.model != new_component.model:
                return True
            
            if old_component.serial_number != new_component.serial_number:
                return True
            
            if old_component.firmware_version != new_component.firmware_version:
                return True
            
            if old_component.status != new_component.status:
                return True
            
            return False
        
        except Exception:
            return True  # Assume changed if error
    
    def _handle_hardware_change(self, change: Dict):
        """Handle detected hardware change"""
        logger.warning(f"HARDWARE CHANGE DETECTED: {change['type']}")
        logger.warning(f"Component: {change['component_id']}")
        
        # Create security event
        event = HardwareSecurityEvent(
            timestamp=datetime.now(),
            event_type="hardware_change",
            component_id=change['component_id'],
            severity="medium",
            description=f"Hardware {change['type']}: {change['component_id']}",
            details=change,
            risk_score=0.6,
            mitigation="verify_integrity"
        )
        
        self._log_security_event(event)
        
        # Update hardware components if changed
        if change['type'] == 'component_changed':
            self.hardware_components[change['component_id']] = change['new_component']
            self._store_hardware_component(change['new_component'])
        elif change['type'] == 'component_added':
            self.hardware_components[change['component_id']] = change['component']
            self._store_hardware_component(change['component'])
        elif change['type'] == 'component_removed':
            del self.hardware_components[change['component_id']]
    
    def _component_monitoring_loop(self):
        """Monitor individual hardware components"""
        while self.monitoring:
            try:
                for component_id, component in self.hardware_components.items():
                    self._monitor_component(component)
                
                time.sleep(600)  # Check every 10 minutes
            
            except Exception as e:
                logger.error(f"Error in component monitoring: {e}")
                time.sleep(1200)
    
    def _monitor_component(self, component: HardwareComponent):
        """Monitor individual hardware component"""
        try:
            # Check component health
            health_issues = []
            
            if component.component_type == 'CPU':
                health_issues = self._check_cpu_health(component)
            elif component.component_type == 'Memory':
                health_issues = self._check_memory_health(component)
            elif component.component_type == 'Storage':
                health_issues = self._check_storage_health(component)
            elif component.component_type == 'Network':
                health_issues = self._check_network_health(component)
            
            # Handle health issues
            for issue in health_issues:
                event = HardwareSecurityEvent(
                    timestamp=datetime.now(),
                    event_type="component_health_issue",
                    component_id=component.component_id,
                    severity=issue['severity'],
                    description=issue['description'],
                    details=issue,
                    risk_score=issue['risk_score'],
                    mitigation=issue['mitigation']
                )
                
                self._log_security_event(event)
        
        except Exception as e:
            logger.error(f"Error monitoring component {component.component_id}: {e}")
    
    def _check_cpu_health(self, component: HardwareComponent) -> List[Dict]:
        """Check CPU health"""
        issues = []
        
        try:
            # Check CPU temperature (simplified)
            cpu_percent = psutil.cpu_percent(interval=1)
            
            if cpu_percent > 90:
                issues.append({
                    'severity': 'high',
                    'description': 'High CPU usage detected',
                    'risk_score': 0.7,
                    'mitigation': 'monitor_processes'
                })
            
            # Check CPU frequency
            cpu_freq = psutil.cpu_freq()
            if cpu_freq and cpu_freq.current < cpu_freq.min * 0.5:
                issues.append({
                    'severity': 'medium',
                    'description': 'CPU frequency below expected',
                    'risk_score': 0.5,
                    'mitigation': 'check_power_settings'
                })
        
        except Exception as e:
            logger.error(f"Error checking CPU health: {e}")
        
        return issues
    
    def _check_memory_health(self, component: HardwareComponent) -> List[Dict]:
        """Check memory health"""
        issues = []
        
        try:
            virtual_memory = psutil.virtual_memory()
            
            if virtual_memory.percent > 90:
                issues.append({
                    'severity': 'high',
                    'description': 'High memory usage detected',
                    'risk_score': 0.7,
                    'mitigation': 'monitor_processes'
                })
            
            if virtual_memory.available < 100 * 1024 * 1024:  # < 100MB
                issues.append({
                    'severity': 'critical',
                    'description': 'Very low available memory',
                    'risk_score': 0.9,
                    'mitigation': 'free_memory'
                })
        
        except Exception as e:
            logger.error(f"Error checking memory health: {e}")
        
        return issues
    
    def _check_storage_health(self, component: HardwareComponent) -> List[Dict]:
        """Check storage health"""
        issues = []
        
        try:
            if component.component_id.startswith('storage_'):
                device = component.component_id.replace('storage_', '')
                
                disk_usage = psutil.disk_usage(device)
                
                if disk_usage.percent > 95:
                    issues.append({
                        'severity': 'critical',
                        'description': 'Storage almost full',
                        'risk_score': 0.8,
                        'mitigation': 'free_disk_space'
                    })
                elif disk_usage.percent > 85:
                    issues.append({
                        'severity': 'medium',
                        'description': 'High disk usage',
                        'risk_score': 0.5,
                        'mitigation': 'monitor_storage'
                    })
        
        except Exception as e:
            logger.error(f"Error checking storage health: {e}")
        
        return issues
    
    def _check_network_health(self, component: HardwareComponent) -> List[Dict]:
        """Check network health"""
        issues = []
        
        try:
            if component.component_id.startswith('network_'):
                interface_name = component.component_id.replace('network_', '')
                
                net_if_stats = psutil.net_if_stats()
                stats = net_if_stats.get(interface_name)
                
                if stats and not stats.isup:
                    issues.append({
                        'severity': 'medium',
                        'description': 'Network interface down',
                        'risk_score': 0.4,
                        'mitigation': 'check_connection'
                    })
        
        except Exception as e:
            logger.error(f"Error checking network health: {e}")
        
        return issues
    
    def _tpm_monitoring_loop(self):
        """Monitor TPM status"""
        while self.monitoring:
            try:
                # Re-check TPM status
                old_tpm_status = self.tpm_status
                self.check_tpm_status()
                
                # Check for changes
                if old_tpm_status and self.tpm_status:
                    if self._tpm_status_changed(old_tpm_status, self.tpm_status):
                        event = HardwareSecurityEvent(
                            timestamp=datetime.now(),
                            event_type="tpm_status_change",
                            component_id="tpm",
                            severity="high",
                            description="TPM status changed",
                            details={'old_status': old_tpm_status, 'new_status': self.tpm_status},
                            risk_score=0.7,
                            mitigation="verify_tpm_integrity"
                        )
                        
                        self._log_security_event(event)
                
                time.sleep(1800)  # Check every 30 minutes
            
            except Exception as e:
                logger.error(f"Error in TPM monitoring: {e}")
                time.sleep(3600)
    
    def _tpm_status_changed(self, old_status: TPMStatus, new_status: TPMStatus) -> bool:
        """Check if TPM status has changed"""
        return (old_status.tpm_present != new_status.tpm_present or
                old_status.tpm_enabled != new_status.tpm_enabled or
                old_status.tpm_activated != new_status.tpm_activated or
                old_status.tpm_owned != new_status.tpm_owned)
    
    def _fingerprint_verification_loop(self):
        """Verify hardware fingerprint"""
        while self.monitoring:
            try:
                # Verify current fingerprint
                current_fingerprint = self._create_current_fingerprint()
                
                if self.hardware_fingerprint:
                    similarity = self._compare_fingerprints(self.hardware_fingerprint, current_fingerprint)
                    
                    if similarity < 0.8:  # Low similarity
                        event = HardwareSecurityEvent(
                            timestamp=datetime.now(),
                            event_type="fingerprint_mismatch",
                            component_id="system",
                            severity="critical",
                            description="Hardware fingerprint mismatch detected",
                            details={'similarity': similarity, 'expected': self.hardware_fingerprint, 'current': current_fingerprint},
                            risk_score=0.9,
                            mitigation="investigate_tampering"
                        )
                        
                        self._log_security_event(event)
                
                time.sleep(3600)  # Verify every hour
            
            except Exception as e:
                logger.error(f"Error in fingerprint verification: {e}")
                time.sleep(7200)
    
    def _create_current_fingerprint(self) -> HardwareFingerprint:
        """Create current hardware fingerprint"""
        device_id = self._generate_device_id()
        cpu_id = self._generate_cpu_signature()
        memory_signature = self._generate_memory_signature()
        disk_signature = self._generate_disk_signature()
        network_signature = self._generate_network_signature()
        bios_signature = self._generate_bios_signature()
        tpm_signature = self._generate_tpm_signature()
        
        return HardwareFingerprint(
            device_id=device_id,
            cpu_id=cpu_id,
            memory_signature=memory_signature,
            disk_signature=disk_signature,
            network_signature=network_signature,
            bios_signature=bios_signature,
            tpm_signature=tpm_signature,
            created_at=datetime.now(),
            verified_at=datetime.now(),
            trust_score=self._calculate_fingerprint_trust()
        )
    
    def _compare_fingerprints(self, expected: HardwareFingerprint, actual: HardwareFingerprint) -> float:
        """Compare two hardware fingerprints"""
        try:
            similarities = []
            
            # Compare CPU signature
            cpu_similarity = 1.0 if expected.cpu_id == actual.cpu_id else 0.0
            similarities.append(cpu_similarity)
            
            # Compare memory signature
            memory_similarity = 1.0 if expected.memory_signature == actual.memory_signature else 0.0
            similarities.append(memory_similarity)
            
            # Compare disk signature
            disk_similarity = 1.0 if expected.disk_signature == actual.disk_signature else 0.0
            similarities.append(disk_similarity)
            
            # Compare network signature
            network_similarity = 1.0 if expected.network_signature == actual.network_signature else 0.0
            similarities.append(network_similarity)
            
            # Compare BIOS signature
            bios_similarity = 1.0 if expected.bios_signature == actual.bios_signature else 0.0
            similarities.append(bios_similarity)
            
            # Compare TPM signature
            tpm_similarity = 1.0 if expected.tpm_signature == actual.tpm_signature else 0.0
            similarities.append(tpm_similarity)
            
            # Calculate overall similarity
            return sum(similarities) / len(similarities)
        
        except Exception:
            return 0.0
    
    def _log_security_event(self, event: HardwareSecurityEvent):
        """Log hardware security event"""
        self.security_events.append(event)
        
        # Keep only recent events
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO hardware_security_events 
            (timestamp, event_type, component_id, severity, description,
             details, risk_score, mitigation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.event_type,
            event.component_id,
            event.severity,
            event.description,
            json.dumps(event.details),
            event.risk_score,
            event.mitigation
        ))
        
        conn.commit()
        conn.close()
    
    def get_hardware_security_status(self) -> Dict:
        """Get hardware security status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get component statistics
        cursor.execute('SELECT component_type, COUNT(*) FROM hardware_components GROUP BY component_type')
        component_stats = dict(cursor.fetchall())
        
        # Get recent security events
        cursor.execute('''
            SELECT COUNT(*) FROM hardware_security_events 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        recent_events = cursor.fetchone()[0]
        
        # Get critical events
        cursor.execute('''
            SELECT COUNT(*) FROM hardware_security_events 
            WHERE severity = 'critical' AND timestamp > datetime('now', '-24 hours')
        ''')
        critical_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'total_components': len(self.hardware_components),
            'component_statistics': component_stats,
            'supported_features': self.supported_features,
            'tpm_status': {
                'present': self.tpm_status.tpm_present if self.tpm_status else False,
                'enabled': self.tpm_status.tpm_enabled if self.tpm_status else False,
                'version': self.tpm_status.tpm_version if self.tpm_status else 'unknown'
            },
            'secure_boot_status': {
                'enabled': self.secure_boot_status.secure_boot_enabled if self.secure_boot_status else False,
                'uefi': self.secure_boot_status.uefi_enabled if self.secure_boot_status else False
            },
            'fingerprint_trust': self.hardware_fingerprint.trust_score if self.hardware_fingerprint else 0.0,
            'recent_events': recent_events,
            'critical_events': critical_events
        }
    
    def stop_monitoring(self):
        """Stop hardware security monitoring"""
        self.monitoring = False
        logger.info("Hardware security monitoring stopped")
    
    def generate_hardware_security_report(self) -> Dict:
        """Generate comprehensive hardware security report"""
        try:
            status = self.get_hardware_security_status()
            
            # Get detailed statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Event statistics
            cursor.execute('''
                SELECT event_type, COUNT(*) FROM hardware_security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY event_type
            ''')
            event_stats = dict(cursor.fetchall())
            
            # Severity distribution
            cursor.execute('''
                SELECT severity, COUNT(*) FROM hardware_security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            ''')
            severity_stats = dict(cursor.fetchall())
            
            # Component trust levels
            cursor.execute('''
                SELECT component_type, AVG(trust_level) as avg_trust
                FROM hardware_components
                GROUP BY component_type
            ''')
            trust_levels = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'security_status': status,
                'event_statistics': event_stats,
                'severity_distribution': severity_stats,
                'component_trust_levels': trust_levels,
                'hardware_fingerprint': {
                    'device_id': self.hardware_fingerprint.device_id if self.hardware_fingerprint else 'unknown',
                    'trust_score': self.hardware_fingerprint.trust_score if self.hardware_fingerprint else 0.0,
                    'created_at': self.hardware_fingerprint.created_at.isoformat() if self.hardware_fingerprint else None
                },
                'recommendations': self._generate_hardware_security_recommendations()
            }
        
        except Exception as e:
            logger.error(f"Error generating hardware security report: {e}")
            return {'error': str(e)}
    
    def _generate_hardware_security_recommendations(self) -> List[str]:
        """Generate hardware security recommendations"""
        recommendations = []
        
        status = self.get_hardware_security_status()
        
        if not self.tpm_status or not self.tpm_status.tpm_present:
            recommendations.append("Consider implementing TPM for enhanced hardware security")
        
        if not self.secure_boot_status or not self.secure_boot_status.secure_boot_enabled:
            recommendations.append("Enable secure boot for bootloader protection")
        
        if status['critical_events'] > 0:
            recommendations.append("Critical hardware security events detected - investigate immediately")
        
        if self.hardware_fingerprint and self.hardware_fingerprint.trust_score < 0.5:
            recommendations.append("Hardware trust score is low - review hardware configuration")
        
        recommendations.extend([
            "Regularly verify hardware integrity",
            "Monitor for unauthorized hardware changes",
            "Implement hardware-based encryption",
            "Use hardware security modules for key protection",
            "Enable hardware virtualization features",
            "Regularly update firmware and BIOS"
        ])
        
        return recommendations
