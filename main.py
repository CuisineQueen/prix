#!/usr/bin/env python3
"""
Prix AI Security System
Advanced threat detection and elimination system
"""

import os
import sys
import time
import threading
import asyncio
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import json
import sqlite3
import hashlib
import subprocess
import psutil
import socket
import re
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('prix_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Threat:
    """Threat data structure"""
    id: str
    type: str  # malware, spyware, intrusion, suspicious
    severity: str  # low, medium, high, critical
    description: str
    source: str
    timestamp: datetime
    file_path: Optional[str] = None
    process_id: Optional[int] = None
    network_connection: Optional[Dict] = None
    eliminated: bool = False

class DatabaseManager:
    """Manage security database"""
    def __init__(self, db_path: str = "prix_security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize security database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                type TEXT,
                severity TEXT,
                description TEXT,
                source TEXT,
                timestamp TEXT,
                file_path TEXT,
                process_id INTEGER,
                network_connection TEXT,
                eliminated BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                message TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_threat(self, threat: Threat):
        """Log threat to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threats 
            (id, type, severity, description, source, timestamp, file_path, process_id, network_connection, eliminated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.id,
            threat.type,
            threat.severity,
            threat.description,
            threat.source,
            threat.timestamp.isoformat(),
            threat.file_path,
            threat.process_id,
            json.dumps(threat.network_connection) if threat.network_connection else None,
            threat.eliminated
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 100) -> List[Threat]:
        """Get recent threats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threats 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        threats = []
        for row in cursor.fetchall():
            threats.append(Threat(
                id=row[0],
                type=row[1],
                severity=row[2],
                description=row[3],
                source=row[4],
                timestamp=datetime.fromisoformat(row[5]),
                file_path=row[6],
                process_id=row[7],
                network_connection=json.loads(row[8]) if row[8] else None,
                eliminated=bool(row[9])
            ))
        
        conn.close()
        return threats

class SystemMonitor:
    """Real-time system monitoring"""
    def __init__(self, database: DatabaseManager):
        self.database = database
        self.running = False
        self.known_processes = set()
        self.suspicious_patterns = [
            r'.*keylogger.*',
            r'.*spy.*',
            r'.*hack.*',
            r'.*crack.*',
            r'.*backdoor.*',
            r'.*rootkit.*',
            r'.*trojan.*',
            r'.*malware.*'
        ]
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.running = True
        threading.Thread(target=self._monitor_processes, daemon=True).start()
        threading.Thread(target=self._monitor_network, daemon=True).start()
        threading.Thread(target=self._monitor_filesystem, daemon=True).start()
        logger.info("System monitoring started")
    
    def _monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        process_name = proc_info['name']
                        
                        if process_name and self._is_suspicious_process(process_name, proc_info.get('cmdline', [])):
                            threat = Threat(
                                id=f"proc_{proc_info['pid']}_{int(time.time())}",
                                type="malware",
                                severity="high",
                                description=f"Suspicious process detected: {process_name}",
                                source="process_monitor",
                                timestamp=datetime.now(),
                                process_id=proc_info['pid']
                            )
                            self.database.log_threat(threat)
                            logger.warning(f"Suspicious process detected: {process_name} (PID: {proc_info['pid']})")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in process monitoring: {e}")
                time.sleep(5)
    
    def _monitor_network(self):
        """Monitor network connections"""
        while self.running:
            try:
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        if self._is_suspicious_connection(conn):
                            threat = Threat(
                                id=f"net_{conn.pid}_{int(time.time())}",
                                type="intrusion",
                                severity="medium",
                                description=f"Suspicious network connection detected",
                                source="network_monitor",
                                timestamp=datetime.now(),
                                process_id=conn.pid,
                                network_connection={
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'status': conn.status
                                }
                            )
                            self.database.log_threat(threat)
                            logger.warning(f"Suspicious network connection: {conn.raddr.ip}:{conn.raddr.port}")
                
                time.sleep(10)
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                time.sleep(10)
    
    def _monitor_filesystem(self):
        """Monitor filesystem changes"""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        
        class SecurityFileHandler(FileSystemEventHandler):
            def __init__(self, database):
                self.database = database
                self.suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar']
            
            def on_created(self, event):
                if not event.is_directory:
                    file_path = event.src_path
                    if self._is_suspicious_file(file_path):
                        threat = Threat(
                            id=f"file_{hashlib.md5(file_path.encode()).hexdigest()}_{int(time.time())}",
                            type="malware",
                            severity="high",
                            description=f"Suspicious file created: {file_path}",
                            source="filesystem_monitor",
                            timestamp=datetime.now(),
                            file_path=file_path
                        )
                        self.database.log_threat(threat)
                        logger.warning(f"Suspicious file created: {file_path}")
            
            def _is_suspicious_file(self, file_path: str) -> bool:
                file_name = os.path.basename(file_path).lower()
                file_ext = os.path.splitext(file_name)[1]
                
                # Check suspicious extensions
                if file_ext in self.suspicious_extensions:
                    return True
                
                # Check suspicious patterns in filename
                for pattern in [
                    r'.*keylogger.*', r'.*spy.*', r'.*hack.*', 
                    r'.*crack.*', r'.*backdoor.*', r'.*rootkit.*'
                ]:
                    if re.match(pattern, file_name, re.IGNORECASE):
                        return True
                
                return False
        
        observer = Observer()
        handler = SecurityFileHandler(self.database)
        observer.schedule(handler, path='/', recursive=True)
        observer.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    
    def _is_suspicious_process(self, name: str, cmdline: List[str]) -> bool:
        """Check if process is suspicious"""
        name_lower = name.lower()
        cmdline_str = ' '.join(cmdline).lower() if cmdline else ''
        
        # Check against suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, name_lower, re.IGNORECASE) or re.match(pattern, cmdline_str, re.IGNORECASE):
                return True
        
        # Check for high resource usage
        try:
            proc = psutil.Process()
            if proc.cpu_percent() > 90 or proc.memory_percent() > 80:
                return True
        except:
            pass
        
        return False
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if network connection is suspicious"""
        if not conn.raddr:
            return False
        
        # Check for connections to known malicious IPs (simplified)
        suspicious_ports = [4444, 5555, 6667, 9999, 31337, 12345]
        
        if conn.raddr.port in suspicious_ports:
            return True
        
        # Check for connections to unusual countries (simplified)
        # In a real implementation, you'd use GeoIP databases
        
        return False
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.running = False
        logger.info("System monitoring stopped")

class ThreatEliminator:
    """Automated threat elimination"""
    def __init__(self, database: DatabaseManager):
        self.database = database
    
    def eliminate_threat(self, threat: Threat) -> bool:
        """Eliminate detected threat"""
        try:
            success = False
            
            if threat.type == "malware" and threat.process_id:
                success = self._terminate_process(threat.process_id)
            
            elif threat.type == "malware" and threat.file_path:
                success = self._quarantine_file(threat.file_path)
            
            elif threat.type == "intrusion" and threat.network_connection:
                success = self._block_connection(threat.network_connection)
            
            if success:
                threat.eliminated = True
                self.database.log_threat(threat)
                logger.info(f"Threat eliminated: {threat.id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error eliminating threat {threat.id}: {e}")
            return False
    
    def _terminate_process(self, pid: int) -> bool:
        """Terminate malicious process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            logger.info(f"Process {pid} terminated")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied when terminating process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False
    
    def _quarantine_file(self, file_path: str) -> bool:
        """Quarantine malicious file"""
        try:
            quarantine_dir = "/tmp/prix_quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{file_name}.quarantined")
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def _block_connection(self, connection_info: Dict) -> bool:
        """Block suspicious network connection"""
        try:
            # This would typically use iptables or firewall rules
            # For demonstration, we'll just log the action
            remote_ip = connection_info.get('remote_address', '').split(':')[0]
            logger.info(f"Would block connection to: {remote_ip}")
            return True
        except Exception as e:
            logger.error(f"Error blocking connection: {e}")
            return False

class PrixSecuritySystem:
    """Main AI Security System"""
    def __init__(self):
        self.database = DatabaseManager()
        self.monitor = SystemMonitor(self.database)
        self.eliminator = ThreatEliminator(self.database)
        self.running = False
    
    def start(self):
        """Start the security system"""
        logger.info("Starting Prix AI Security System...")
        self.running = True
        
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Start automated threat elimination
        threading.Thread(target=self._auto_eliminate_threats, daemon=True).start()
        
        logger.info("Prix AI Security System started successfully")
    
    def _auto_eliminate_threats(self):
        """Automatically eliminate high-priority threats"""
        while self.running:
            try:
                threats = self.database.get_recent_threats(limit=50)
                
                for threat in threats:
                    if not threat.eliminated and threat.severity in ['high', 'critical']:
                        self.eliminator.eliminate_threat(threat)
                
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in auto-elimination: {e}")
                time.sleep(30)
    
    def stop(self):
        """Stop the security system"""
        logger.info("Stopping Prix AI Security System...")
        self.running = False
        self.monitor.stop_monitoring()
        logger.info("Prix AI Security System stopped")
    
    def get_status(self) -> Dict:
        """Get system status"""
        recent_threats = self.database.get_recent_threats(limit=10)
        return {
            'status': 'running' if self.running else 'stopped',
            'recent_threats': len(recent_threats),
            'threats': [
                {
                    'id': t.id,
                    'type': t.type,
                    'severity': t.severity,
                    'description': t.description,
                    'timestamp': t.timestamp.isoformat(),
                    'eliminated': t.eliminated
                }
                for t in recent_threats
            ]
        }

def main():
    """Main entry point"""
    prix_system = PrixSecuritySystem()
    
    try:
        prix_system.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Prix AI Security System...")
        prix_system.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()
