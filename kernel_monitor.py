#!/usr/bin/env python3
"""
Advanced Kernel-Level Monitoring System
Deep system inspection with kernel-level threat detection
"""

import os
import sys
import ctypes
import struct
import subprocess
import threading
import time
import logging
import json
import hashlib
import socket
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import sqlite3

logger = logging.getLogger(__name__)

@dataclass
class KernelEvent:
    """Kernel-level security event"""
    timestamp: datetime
    event_type: str
    process_id: int
    process_name: str
    system_call: str
    parameters: Dict
    return_value: int
    stack_trace: List[str]
    kernel_module: str
    severity: str
    confidence: float

class KernelMonitor:
    """Advanced kernel-level monitoring system"""
    
    def __init__(self, db_path: str = "prix_kernel.db"):
        self.db_path = db_path
        self.monitoring = False
        self.kernel_modules = {}
        self.system_call_hooks = {}
        self.driver_signatures = {}
        self.kernel_integrity_hash = None
        self.suspicious_syscalls = {
            'ptrace', 'process_vm_writev', 'process_vm_readv',
            'mprotect', 'mmap', 'execve', 'fork', 'clone',
            'ptrace', 'kill', 'signal', 'sigaction'
        }
        self.privileged_operations = {
            'mount', 'umount', 'swapon', 'swapoff',
            'reboot', 'sethostname', 'setdomainname',
            'init_module', 'delete_module', 'iopl', 'ioperm'
        }
        
        # Initialize kernel monitoring
        self.init_database()
        self.load_kernel_signatures()
        self.establish_kernel_baseline()
    
    def init_database(self):
        """Initialize kernel monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kernel_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                process_id INTEGER,
                process_name TEXT,
                system_call TEXT,
                parameters TEXT,
                return_value INTEGER,
                stack_trace TEXT,
                kernel_module TEXT,
                severity TEXT,
                confidence REAL,
                investigated BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kernel_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT,
                module_path TEXT,
                hash_value TEXT,
                signature_valid BOOLEAN,
                loaded_at TEXT,
               卸载 BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kernel_integrity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                check_timestamp TEXT,
                kernel_hash TEXT,
                integrity_status TEXT,
                violations TEXT,
                baseline_hash TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_kernel_signatures(self):
        """Load trusted kernel module signatures"""
        # In a real implementation, this would load from secure storage
        self.driver_signatures = {
            'kernel': {
                'hash': 'trusted_kernel_hash',
                'signature': 'trusted_signature',
                'certificate': 'trusted_cert'
            }
        }
    
    def establish_kernel_baseline(self):
        """Establish kernel integrity baseline"""
        logger.info("Establishing kernel integrity baseline...")
        
        # Calculate kernel hash
        kernel_hash = self._calculate_kernel_hash()
        self.kernel_integrity_hash = kernel_hash
        
        # Store baseline
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO kernel_integrity 
            (check_timestamp, kernel_hash, integrity_status, violations, baseline_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            kernel_hash,
            'integrity_verified',
            json.dumps([]),
            kernel_hash
        ))
        conn.commit()
        conn.close()
        
        logger.info("Kernel baseline established")
    
    def _calculate_kernel_hash(self) -> str:
        """Calculate kernel integrity hash"""
        try:
            # Get kernel image path
            kernel_path = self._get_kernel_image_path()
            
            if kernel_path and os.path.exists(kernel_path):
                with open(kernel_path, 'rb') as f:
                    kernel_data = f.read()
                    return hashlib.sha256(kernel_data).hexdigest()
            
            # Fallback: hash running kernel modules
            return self._hash_kernel_modules()
            
        except Exception as e:
            logger.error(f"Error calculating kernel hash: {e}")
            return "unknown"
    
    def _get_kernel_image_path(self) -> Optional[str]:
        """Get kernel image path"""
        try:
            # Linux kernel path
            if os.path.exists('/boot/vmlinuz-$(uname -r)'):
                return f"/boot/vmlinuz-{subprocess.check_output(['uname', '-r']).decode().strip()}"
            
            # Alternative paths
            for path in ['/boot/vmlinuz', '/boot/kernel', '/usr/src/linux']:
                if os.path.exists(path):
                    return path
                    
        except Exception:
            pass
        
        return None
    
    def _hash_kernel_modules(self) -> str:
        """Hash loaded kernel modules"""
        try:
            modules = self._get_loaded_modules()
            combined_hash = hashlib.sha256()
            
            for module in modules:
                module_data = f"{module['name']}:{module['size']}:{module.get('hash', '')}"
                combined_hash.update(module_data.encode())
            
            return combined_hash.hexdigest()
            
        except Exception as e:
            logger.error(f"Error hashing kernel modules: {e}")
            return "fallback_hash"
    
    def _get_loaded_modules(self) -> List[Dict]:
        """Get loaded kernel modules"""
        modules = []
        
        try:
            # Read from /proc/modules
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        modules.append({
                            'name': parts[0],
                            'size': int(parts[1]),
                            'ref_count': int(parts[2]),
                            'dependencies': parts[3].strip(',').split(',') if parts[3] != '-' else []
                        })
            
        except Exception as e:
            logger.error(f"Error reading kernel modules: {e}")
        
        return modules
    
    def start_monitoring(self):
        """Start kernel-level monitoring"""
        if self.monitoring:
            logger.warning("Kernel monitoring already running")
            return
        
        self.monitoring = True
        logger.info("Starting kernel-level monitoring...")
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_kernel_integrity, daemon=True).start()
        threading.Thread(target=self._monitor_system_calls, daemon=True).start()
        threading.Thread(target=self._monitor_kernel_modules, daemon=True).start()
        threading.Thread(target=self._monitor_privileged_operations, daemon=True).start()
        threading.Thread(target=self._detect_rootkit_techniques, daemon=True).start()
    
    def _monitor_kernel_integrity(self):
        """Monitor kernel integrity continuously"""
        while self.monitoring:
            try:
                current_hash = self._calculate_kernel_hash()
                
                if current_hash != self.kernel_integrity_hash:
                    self._handle_kernel_integrity_violation(current_hash)
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in kernel integrity monitoring: {e}")
                time.sleep(60)
    
    def _handle_kernel_integrity_violation(self, current_hash: str):
        """Handle kernel integrity violation"""
        logger.critical("KERNEL INTEGRITY VIOLATION DETECTED!")
        
        event = KernelEvent(
            timestamp=datetime.now(),
            event_type="kernel_integrity_violation",
            process_id=0,
            process_name="kernel",
            system_call="integrity_check",
            parameters={
                'expected_hash': self.kernel_integrity_hash,
                'actual_hash': current_hash
            },
            return_value=-1,
            stack_trace=[],
            kernel_module="kernel",
            severity="critical",
            confidence=1.0
        )
        
        self._log_kernel_event(event)
        
        # Update baseline if this is expected (e.g., kernel update)
        if self._is_expected_kernel_change():
            self.kernel_integrity_hash = current_hash
            logger.info("Kernel change verified - baseline updated")
        else:
            logger.critical("UNEXPECTED KERNEL MODIFICATION - POTENTIAL ROOTKIT")
    
    def _is_expected_kernel_change(self) -> bool:
        """Check if kernel change is expected"""
        # In a real implementation, this would check:
        # - Recent system updates
        # - Authorized module loading
        # - System maintenance windows
        
        return False  # Conservative: assume unexpected
    
    def _monitor_system_calls(self):
        """Monitor system calls for suspicious activity"""
        while self.monitoring:
            try:
                # This would use eBPF, strace, or similar tools
                # For demonstration, we'll simulate syscall monitoring
                
                suspicious_calls = self._detect_suspicious_syscalls()
                
                for call_info in suspicious_calls:
                    event = KernelEvent(
                        timestamp=datetime.now(),
                        event_type="suspicious_syscall",
                        process_id=call_info.get('pid', 0),
                        process_name=call_info.get('process', 'unknown'),
                        system_call=call_info.get('syscall', 'unknown'),
                        parameters=call_info.get('params', {}),
                        return_value=call_info.get('retval', 0),
                        stack_trace=call_info.get('stack', []),
                        kernel_module=call_info.get('module', 'unknown'),
                        severity=call_info.get('severity', 'medium'),
                        confidence=call_info.get('confidence', 0.5)
                    )
                    
                    self._log_kernel_event(event)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in syscall monitoring: {e}")
                time.sleep(10)
    
    def _detect_suspicious_syscalls(self) -> List[Dict]:
        """Detect suspicious system calls"""
        suspicious_calls = []
        
        try:
            # Monitor processes for suspicious syscall patterns
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    # Check for processes making suspicious syscalls
                    if self._is_process_suspicious(proc_info):
                        suspicious_calls.append({
                            'pid': proc_info['pid'],
                            'process': proc_info['name'],
                            'syscall': 'suspicious_activity',
                            'params': {'cmdline': proc_info.get('cmdline', [])},
                            'severity': 'high',
                            'confidence': 0.7
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting suspicious syscalls: {e}")
        
        return suspicious_calls
    
    def _is_process_suspicious(self, proc_info: Dict) -> bool:
        """Check if process is suspicious based on syscall patterns"""
        name = proc_info.get('name', '').lower()
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        
        # Suspicious process names
        suspicious_names = [
            'strace', 'gdb', 'lldb', 'radare2', 'ida', 'x64dbg',
            'wireshark', 'tcpdump', 'nmap', 'masscan', 'metasploit'
        ]
        
        if any(susp in name for susp in suspicious_names):
            return True
        
        # Suspicious command line arguments
        suspicious_args = [
            '--ptrace', '--debug', '--inject', '--hook',
            '--shellcode', '--exploit', '--payload'
        ]
        
        if any(arg in cmdline for arg in suspicious_args):
            return True
        
        return False
    
    def _monitor_kernel_modules(self):
        """Monitor kernel module loading/unloading"""
        while self.monitoring:
            try:
                current_modules = self._get_loaded_modules()
                
                # Check for new modules
                for module in current_modules:
                    if module['name'] not in self.kernel_modules:
                        self._handle_module_load(module)
                
                # Check for unloaded modules
                for module_name in list(self.kernel_modules.keys()):
                    if module_name not in [m['name'] for m in current_modules]:
                        self._handle_module_unload(module_name)
                
                # Update module cache
                self.kernel_modules = {m['name']: m for m in current_modules}
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in kernel module monitoring: {e}")
                time.sleep(30)
    
    def _handle_module_load(self, module: Dict):
        """Handle kernel module loading"""
        logger.warning(f"Kernel module loaded: {module['name']}")
        
        # Verify module signature
        signature_valid = self._verify_module_signature(module)
        
        event = KernelEvent(
            timestamp=datetime.now(),
            event_type="module_load",
            process_id=0,
            process_name="kernel",
            system_call="init_module",
            parameters={
                'module_name': module['name'],
                'module_size': module['size'],
                'signature_valid': signature_valid
            },
            return_value=0,
            stack_trace=[],
            kernel_module=module['name'],
            severity="high" if not signature_valid else "medium",
            confidence=0.8 if signature_valid else 0.9
        )
        
        self._log_kernel_event(event)
        
        # Store module info
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO kernel_modules 
            (module_name, module_path, hash_value, signature_valid, loaded_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            module['name'],
            f"/sys/module/{module['name']}",
            hashlib.md5(module['name'].encode()).hexdigest(),
            signature_valid,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
    
    def _verify_module_signature(self, module: Dict) -> bool:
        """Verify kernel module signature"""
        # In a real implementation, this would:
        # - Check digital signatures
        # - Verify certificate chain
        # - Check against trusted module database
        
        # For demonstration, assume known modules are trusted
        trusted_modules = ['ext4', 'vfat', 'ntfs', 'snd', 'usb', 'net']
        return module['name'] in trusted_modules
    
    def _handle_module_unload(self, module_name: str):
        """Handle kernel module unloading"""
        logger.info(f"Kernel module unloaded: {module_name}")
        
        event = KernelEvent(
            timestamp=datetime.now(),
            event_type="module_unload",
            process_id=0,
            process_name="kernel",
            system_call="delete_module",
            parameters={'module_name': module_name},
            return_value=0,
            stack_trace=[],
            kernel_module=module_name,
            severity="medium",
            confidence=0.6
        )
        
        self._log_kernel_event(event)
        
        # Update database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE kernel_modules SET 卸载 = 1 WHERE module_name = ?
        ''', (module_name,))
        conn.commit()
        conn.close()
    
    def _monitor_privileged_operations(self):
        """Monitor privileged system operations"""
        while self.monitoring:
            try:
                # Monitor for privileged operations
                privileged_ops = self._detect_privileged_operations()
                
                for op_info in privileged_ops:
                    event = KernelEvent(
                        timestamp=datetime.now(),
                        event_type="privileged_operation",
                        process_id=op_info.get('pid', 0),
                        process_name=op_info.get('process', 'unknown'),
                        system_call=op_info.get('operation', 'unknown'),
                        parameters=op_info.get('params', {}),
                        return_value=op_info.get('retval', 0),
                        stack_trace=op_info.get('stack', []),
                        kernel_module=op_info.get('module', 'unknown'),
                        severity=op_info.get('severity', 'high'),
                        confidence=op_info.get('confidence', 0.7)
                    )
                    
                    self._log_kernel_event(event)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in privileged operations monitoring: {e}")
                time.sleep(15)
    
    def _detect_privileged_operations(self) -> List[Dict]:
        """Detect privileged operations"""
        operations = []
        
        try:
            # Check for processes with elevated privileges
            for proc in psutil.process_iter(['pid', 'name', 'uids', 'gids']):
                try:
                    proc_info = proc.info
                    
                    # Check if process is running as root
                    if proc_info['uids'] and proc_info['uids'].real == 0:
                        # Check if this is a suspicious process running as root
                        if self._is_suspicious_root_process(proc_info):
                            operations.append({
                                'pid': proc_info['pid'],
                                'process': proc_info['name'],
                                'operation': 'root_execution',
                                'params': {'uids': proc_info['uids']._asdict()},
                                'severity': 'high',
                                'confidence': 0.8
                            })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting privileged operations: {e}")
        
        return operations
    
    def _is_suspicious_root_process(self, proc_info: Dict) -> bool:
        """Check if root process is suspicious"""
        name = proc_info.get('name', '').lower()
        
        # Known legitimate root processes
        legitimate_root = [
            'systemd', 'init', 'kthreadd', 'ksoftirqd', 'migration',
            'rcu_', 'watchdog', 'sshd', 'cron', 'anacron'
        ]
        
        # If it's not a known legitimate root process, it's suspicious
        return not any(legit in name for legit in legitimate_root)
    
    def _detect_rootkit_techniques(self):
        """Detect advanced rootkit techniques"""
        while self.monitoring:
            try:
                # Check for various rootkit techniques
                self._check_hidden_processes()
                self._check_hidden_files()
                self._check_network_backdoors()
                self._check_system_call_hooks()
                self._check_kernel_memory_modifications()
                
                time.sleep(120)  # Check every 2 minutes
                
            except Exception as e:
                logger.error(f"Error in rootkit detection: {e}")
                time.sleep(120)
    
    def _check_hidden_processes(self):
        """Check for hidden processes"""
        try:
            # Compare /proc processes with psutil results
            proc_processes = set(psutil.pids())
            
            # Read /proc directly
            proc_dir_processes = set()
            for pid_dir in os.listdir('/proc'):
                if pid_dir.isdigit():
                    proc_dir_processes.add(int(pid_dir))
            
            # Look for discrepancies
            hidden_in_psutil = proc_dir_processes - proc_processes
            hidden_in_proc = proc_processes - proc_dir_processes
            
            if hidden_in_psutil or hidden_in_proc:
                logger.critical("HIDDEN PROCESSES DETECTED!")
                
                event = KernelEvent(
                    timestamp=datetime.now(),
                    event_type="hidden_processes",
                    process_id=0,
                    process_name="rootkit",
                    system_call="process_hiding",
                    parameters={
                        'hidden_in_psutil': list(hidden_in_psutil),
                        'hidden_in_proc': list(hidden_in_proc)
                    },
                    return_value=-1,
                    stack_trace=[],
                    kernel_module="unknown",
                    severity="critical",
                    confidence=0.9
                )
                
                self._log_kernel_event(event)
        
        except Exception as e:
            logger.error(f"Error checking hidden processes: {e}")
    
    def _check_hidden_files(self):
        """Check for hidden files and directories"""
        try:
            # Look for suspicious hidden files in system directories
            system_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/lib']
            
            for dir_path in system_dirs:
                if os.path.exists(dir_path):
                    for item in os.listdir(dir_path):
                        item_path = os.path.join(dir_path, item)
                        
                        # Check for suspicious files
                        if self._is_suspicious_hidden_file(item_path):
                            logger.warning(f"Suspicious hidden file: {item_path}")
                            
                            event = KernelEvent(
                                timestamp=datetime.now(),
                                event_type="hidden_file",
                                process_id=0,
                                process_name="rootkit",
                                system_call="file_hiding",
                                parameters={'file_path': item_path},
                                return_value=-1,
                                stack_trace=[],
                                kernel_module="unknown",
                                severity="high",
                                confidence=0.7
                            )
                            
                            self._log_kernel_event(event)
        
        except Exception as e:
            logger.error(f"Error checking hidden files: {e}")
    
    def _is_suspicious_hidden_file(self, file_path: str) -> bool:
        """Check if file is suspicious hidden file"""
        try:
            # Check file attributes
            stat_info = os.stat(file_path)
            
            # Hidden file (starts with .)
            if os.path.basename(file_path).startswith('.'):
                # Check if it's in a system directory
                if any(system_dir in file_path for system_dir in ['/bin', '/sbin', '/usr/bin', '/usr/sbin']):
                    return True
            
            # Check for suspicious file names
            suspicious_names = [
                '.rk', '.rootkit', '.backdoor', '.c2', '.bot',
                'kit', 'root', 'back', 'door', 'botnet'
            ]
            
            filename = os.path.basename(file_path).lower()
            if any(susp in filename for susp in suspicious_names):
                return True
            
            return False
        
        except Exception:
            return False
    
    def _check_network_backdoors(self):
        """Check for network backdoors"""
        try:
            # Check for suspicious listening ports
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    
                    # Check for suspicious ports
                    suspicious_ports = [4444, 5555, 6667, 9999, 31337, 12345, 54321]
                    
                    if port in suspicious_ports:
                        logger.critical(f"SUSPICIOUS LISTENING PORT: {port}")
                        
                        event = KernelEvent(
                            timestamp=datetime.now(),
                            event_type="network_backdoor",
                            process_id=conn.pid or 0,
                            process_name="unknown",
                            system_call="listen",
                            parameters={'port': port, 'address': conn.laddr.ip},
                            return_value=0,
                            stack_trace=[],
                            kernel_module="unknown",
                            severity="critical",
                            confidence=0.8
                        )
                        
                        self._log_kernel_event(event)
        
        except Exception as e:
            logger.error(f"Error checking network backdoors: {e}")
    
    def _check_system_call_hooks(self):
        """Check for system call hooks"""
        try:
            # This would use techniques to detect syscall table modifications
            # For demonstration, we'll check for common hooking indicators
            
            # Check /proc/kallsyms for suspicious symbols
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    symbols = f.read()
                    
                    # Look for suspicious symbols
                    suspicious_patterns = [
                        'hook', 'rootkit', 'backdoor', 'stealth',
                        'hidden', 'invisible', 'cloak'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in symbols.lower():
                            logger.warning(f"Suspicious kernel symbol detected: {pattern}")
                            
                            event = KernelEvent(
                                timestamp=datetime.now(),
                                event_type="syscall_hook",
                                process_id=0,
                                process_name="rootkit",
                                system_call="syscall_table_modification",
                                parameters={'symbol': pattern},
                                return_value=-1,
                                stack_trace=[],
                                kernel_module="unknown",
                                severity="critical",
                                confidence=0.7
                            )
                            
                            self._log_kernel_event(event)
        
        except Exception as e:
            logger.error(f"Error checking syscall hooks: {e}")
    
    def _check_kernel_memory_modifications(self):
        """Check for kernel memory modifications"""
        try:
            # This would use techniques to detect kernel memory patches
            # For demonstration, we'll check /dev/mem and /dev/kmem access
            
            # Check if /dev/mem is being accessed
            try:
                mem_stat = os.stat('/dev/mem')
                # Check recent access time
                access_time = datetime.fromtimestamp(mem_stat.st_atime)
                if (datetime.now() - access_time).seconds < 300:  # Accessed in last 5 minutes
                    logger.warning("Recent /dev/mem access detected")
                    
                    event = KernelEvent(
                        timestamp=datetime.now(),
                        event_type="kernel_memory_access",
                        process_id=0,
                        process_name="unknown",
                        system_call="mmap",
                        parameters={'device': '/dev/mem'},
                        return_value=0,
                        stack_trace=[],
                        kernel_module="unknown",
                        severity="high",
                        confidence=0.6
                    )
                    
                    self._log_kernel_event(event)
            
            except (FileNotFoundError, PermissionError):
                pass
        
        except Exception as e:
            logger.error(f"Error checking kernel memory modifications: {e}")
    
    def _log_kernel_event(self, event: KernelEvent):
        """Log kernel event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO kernel_events 
            (timestamp, event_type, process_id, process_name, system_call,
             parameters, return_value, stack_trace, kernel_module, severity, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.event_type,
            event.process_id,
            event.process_name,
            event.system_call,
            json.dumps(event.parameters),
            event.return_value,
            json.dumps(event.stack_trace),
            event.kernel_module,
            event.severity,
            event.confidence
        ))
        
        conn.commit()
        conn.close()
        
        # Log to system log
        log_level = {
            'critical': logging.CRITICAL,
            'high': logging.ERROR,
            'medium': logging.WARNING,
            'low': logging.INFO
        }.get(event.severity, logging.INFO)
        
        logger.log(log_level, f"KERNEL EVENT: {event.event_type} - {event.process_name} - {event.system_call}")
    
    def get_kernel_status(self) -> Dict:
        """Get current kernel monitoring status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent events
        cursor.execute('''
            SELECT COUNT(*) FROM kernel_events 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        recent_events = cursor.fetchone()[0]
        
        # Get critical events
        cursor.execute('''
            SELECT COUNT(*) FROM kernel_events 
            WHERE severity = 'critical' AND timestamp > datetime('now', '-24 hours')
        ''')
        critical_events = cursor.fetchone()[0]
        
        # Get loaded modules
        cursor.execute('SELECT COUNT(*) FROM kernel_modules WHERE 卸载 = 0')
        loaded_modules = cursor.fetchone()[0]
        
        # Get integrity status
        cursor.execute('''
            SELECT integrity_status FROM kernel_integrity 
            ORDER BY check_timestamp DESC LIMIT 1
        ''')
        integrity_result = cursor.fetchone()
        integrity_status = integrity_result[0] if integrity_result else 'unknown'
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'recent_events': recent_events,
            'critical_events': critical_events,
            'loaded_modules': loaded_modules,
            'kernel_integrity': integrity_status,
            'baseline_hash': self.kernel_integrity_hash
        }
    
    def stop_monitoring(self):
        """Stop kernel monitoring"""
        self.monitoring = False
        logger.info("Kernel monitoring stopped")
    
    def generate_kernel_report(self) -> Dict:
        """Generate comprehensive kernel security report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get event statistics
        cursor.execute('''
            SELECT event_type, COUNT(*) as count 
            FROM kernel_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY event_type
        ''')
        event_stats = dict(cursor.fetchall())
        
        # Get severity distribution
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM kernel_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        severity_stats = dict(cursor.fetchall())
        
        # Get top suspicious processes
        cursor.execute('''
            SELECT process_name, COUNT(*) as count 
            FROM kernel_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY process_name 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_processes = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'monitoring_status': 'active' if self.monitoring else 'inactive',
            'event_statistics': event_stats,
            'severity_distribution': severity_stats,
            'top_suspicious_processes': top_processes,
            'kernel_integrity': self.get_kernel_status()['kernel_integrity'],
            'recommendations': self._generate_kernel_recommendations()
        }
    
    def _generate_kernel_recommendations(self) -> List[str]:
        """Generate kernel security recommendations"""
        recommendations = []
        
        status = self.get_kernel_status()
        
        if status['critical_events'] > 0:
            recommendations.append("IMMEDIATE INVESTIGATION REQUIRED: Critical kernel events detected")
        
        if status['kernel_integrity'] != 'integrity_verified':
            recommendations.append("KERNEL INTEGRITY COMPROMISED: Perform system scan and reinstall")
        
        if status['loaded_modules'] > 50:  # Unusual number of modules
            recommendations.append("Review loaded kernel modules for unauthorized additions")
        
        recommendations.extend([
            "Enable secure boot if available",
            "Regularly update kernel and system packages",
            "Monitor /var/log/kern.log for suspicious activity",
            "Consider using kernel lockdown features"
        ])
        
        return recommendations
