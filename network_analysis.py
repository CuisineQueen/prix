#!/usr/bin/env python3
"""
Advanced Network Traffic Analysis System
Deep packet inspection, behavioral analysis, and threat detection
"""

import os
import sys
import time
import threading
import logging
import json
import hashlib
import socket
import struct
import subprocess
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# Network libraries
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    import netifaces
except ImportError:
    print("Installing network analysis libraries...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy", "netifaces"])
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    import netifaces

# ML libraries
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    import joblib
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn", "pandas", "numpy"])
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    import joblib

logger = logging.getLogger(__name__)

@dataclass
class NetworkPacket:
    """Network packet information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    payload_size: int
    flags: List[str]
    ttl: int
    packet_hash: str
    threat_score: float
    classification: str

@dataclass
class NetworkFlow:
    """Network flow information"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: datetime
    packet_count: int
    byte_count: int
    duration: float
    flags: Set[str]
    threat_score: float
    classification: str

@dataclass
class NetworkThreat:
    """Network threat detection"""
    timestamp: datetime
    threat_type: str
    severity: str
    source_ip: str
    dest_ip: str
    port: int
    protocol: str
    confidence: float
    details: Dict
    mitigation_action: str

class NetworkAnalysis:
    """Advanced network traffic analysis system"""
    
    def __init__(self, db_path: str = "prix_network.db"):
        self.db_path = db_path
        self.monitoring = False
        self.packet_capture_active = False
        self.flow_analysis_active = False
        self.threat_detection_active = False
        
        # Network analysis components
        self.packets = []
        self.flows = {}
        self.threats = []
        self.network_baselines = {}
        self.anomaly_models = {}
        self.traffic_patterns = {}
        
        # Threat signatures
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.c2_ports = {4444, 5555, 6667, 9999, 31337, 12345, 54321}
        self.suspicious_user_agents = set()
        
        # Protocol analysis
        self.protocol_analyzers = {
            'HTTP': self._analyze_http,
            'HTTPS': self._analyze_https,
            'DNS': self._analyze_dns,
            'FTP': self._analyze_ftp,
            'SSH': self._analyze_ssh,
            'TELNET': self._analyze_telnet
        }
        
        # Initialize network analysis
        self.init_database()
        self.load_threat_intelligence()
        self.init_ml_models()
        self.establish_network_baselines()
    
    def init_database(self):
        """Initialize network analysis database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Network packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                payload_size INTEGER,
                flags TEXT,
                ttl INTEGER,
                packet_hash TEXT,
                threat_score REAL,
                classification TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')
        
        # Network flows table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_flows (
                flow_id TEXT PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time TEXT,
                end_time TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                duration REAL,
                flags TEXT,
                threat_score REAL,
                classification TEXT,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                port INTEGER,
                protocol TEXT,
                confidence REAL,
                details TEXT,
                mitigation_action TEXT,
                investigated BOOLEAN DEFAULT 0
            )
        ''')
        
        # Traffic baselines table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_type TEXT,
                baseline_data TEXT,
                created_at TEXT,
                last_updated TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Protocol analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                protocol TEXT,
                analysis_type TEXT,
                findings TEXT,
                threat_score REAL,
                confidence REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_threat_intelligence(self):
        """Load threat intelligence data"""
        logger.info("Loading threat intelligence...")
        
        # Load malicious IPs
        self._load_malicious_ips()
        
        # Load suspicious domains
        self._load_suspicious_domains()
        
        # Load suspicious user agents
        self._load_suspicious_user_agents()
        
        logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs")
        logger.info(f"Loaded {len(self.suspicious_domains)} suspicious domains")
    
    def _load_malicious_ips(self):
        """Load malicious IP addresses"""
        # In a real implementation, this would load from threat intelligence feeds
        # For demonstration, use some known malicious patterns
        known_malicious = [
            '192.168.1.100', '10.0.0.50', '172.16.0.10',
            '203.0.113.1', '198.51.100.1', '192.0.2.1'
        ]
        
        self.malicious_ips.update(known_malicious)
    
    def _load_suspicious_domains(self):
        """Load suspicious domain names"""
        # In a real implementation, this would load from threat intelligence feeds
        suspicious_domains = [
            'malware-example.com', 'c2-server.net', 'botnet.org',
            'phishing-site.info', 'suspicious-domain.biz'
        ]
        
        self.suspicious_domains.update(suspicious_domains)
    
    def _load_suspicious_user_agents(self):
        """Load suspicious user agent strings"""
        suspicious_agents = [
            'malware-bot', 'c2-client', 'backdoor-agent',
            'exploit-kit', 'scanner-tool'
        ]
        
        self.suspicious_user_agents.update(suspicious_agents)
    
    def init_ml_models(self):
        """Initialize machine learning models"""
        logger.info("Initializing ML models...")
        
        model_dir = "network_models"
        os.makedirs(model_dir, exist_ok=True)
        
        # Anomaly detection model
        anomaly_model_path = os.path.join(model_dir, "network_anomaly.pkl")
        if os.path.exists(anomaly_model_path):
            self.anomaly_models['anomaly'] = joblib.load(anomaly_model_path)
            logger.info("Loaded network anomaly model")
        else:
            self.anomaly_models['anomaly'] = self._train_anomaly_model()
            joblib.dump(self.anomaly_models['anomaly'], anomaly_model_path)
            logger.info("Trained network anomaly model")
        
        # Traffic classification model
        classification_model_path = os.path.join(model_dir, "traffic_classification.pkl")
        if os.path.exists(classification_model_path):
            self.anomaly_models['classification'] = joblib.load(classification_model_path)
            logger.info("Loaded traffic classification model")
        else:
            self.anomaly_models['classification'] = self._train_classification_model()
            joblib.dump(self.anomaly_models['classification'], classification_model_path)
            logger.info("Trained traffic classification model")
    
    def _train_anomaly_model(self):
        """Train network anomaly detection model"""
        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 10000
        
        # Normal traffic patterns
        normal_data = np.random.multivariate_normal(
            [1000, 500, 50, 10, 5],  # [bytes, packets, duration, src_ports, dst_ports]
            [[50000, 10000, 500, 50, 25],
             [10000, 2500, 125, 25, 12],
             [500, 125, 25, 5, 2],
             [50, 25, 5, 2, 1],
             [25, 12, 2, 1, 0.5]],
            n_samples // 2
        )
        
        # Anomalous traffic patterns
        anomalous_data = np.random.multivariate_normal(
            [10000, 2000, 200, 50, 20],  # Higher values for anomalies
            [[100000, 20000, 1000, 100, 50],
             [20000, 5000, 250, 50, 25],
             [1000, 250, 50, 10, 5],
             [100, 50, 10, 4, 2],
             [50, 25, 5, 2, 1]],
            n_samples // 2
        )
        
        X = np.vstack([normal_data, anomalous_data])
        
        # Train isolation forest
        model = IsolationForest(
            contamination=0.1,
            n_estimators=100,
            max_samples='auto',
            random_state=42
        )
        model.fit(X)
        
        return model
    
    def _train_classification_model(self):
        """Train traffic classification model"""
        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 8000
        
        # Different traffic types
        web_traffic = np.random.multivariate_normal(
            [5000, 100, 30, 80, 443],  # [bytes, packets, duration, src_port, dst_port]
            np.eye(5) * 1000,
            n_samples // 4
        )
        
        dns_traffic = np.random.multivariate_normal(
            [100, 2, 0.1, 53, 53],
            np.eye(5) * 50,
            n_samples // 4
        )
        
        ssh_traffic = np.random.multivariate_normal(
            [2000, 50, 60, 22, 22],
            np.eye(5) * 500,
            n_samples // 4
        )
        
        malicious_traffic = np.random.multivariate_normal(
            [15000, 300, 120, 4444, 4444],  # Suspicious ports
            np.eye(5) * 2000,
            n_samples // 4
        )
        
        X = np.vstack([web_traffic, dns_traffic, ssh_traffic, malicious_traffic])
        y = np.hstack([
            np.ones(n_samples // 4) * 0,  # Web
            np.ones(n_samples // 4) * 1,  # DNS
            np.ones(n_samples // 4) * 2,  # SSH
            np.ones(n_samples // 4) * 3   # Malicious
        ])
        
        # Train random forest
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        model.fit(X, y)
        
        return model
    
    def establish_network_baselines(self):
        """Establish network traffic baselines"""
        logger.info("Establishing network baselines...")
        
        # Collect baseline data
        baseline_data = self._collect_baseline_data()
        
        # Store baselines
        self.network_baselines['traffic_volume'] = self._create_traffic_baseline(baseline_data)
        self.network_baselines['protocol_distribution'] = self._create_protocol_baseline(baseline_data)
        self.network_baselines['connection_patterns'] = self._create_connection_baseline(baseline_data)
        
        logger.info("Network baselines established")
    
    def _collect_baseline_data(self) -> Dict:
        """Collect baseline network data"""
        baseline_data = {
            'packets': [],
            'connections': [],
            'protocols': defaultdict(int),
            'ports': defaultdict(int)
        }
        
        # Collect data over time
        for _ in range(60):  # Collect for 60 seconds
            try:
                # Get current connections
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        baseline_data['connections'].append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'timestamp': datetime.now()
                        })
                        
                        # Track protocols
                        if conn.type == socket.SOCK_STREAM:
                            baseline_data['protocols']['TCP'] += 1
                        elif conn.type == socket.SOCK_DGRAM:
                            baseline_data['protocols']['UDP'] += 1
                        
                        # Track ports
                        baseline_data['ports'][conn.raddr.port] += 1
                
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"Error collecting baseline data: {e}")
                time.sleep(1)
        
        return baseline_data
    
    def _create_traffic_baseline(self, data: Dict) -> Dict:
        """Create traffic volume baseline"""
        if not data['connections']:
            return {'mean_connections': 0, 'std_connections': 0}
        
        connection_counts = []
        for i in range(0, len(data['connections']), 10):  # Sample every 10 seconds
            sample = data['connections'][i:i+10]
            connection_counts.append(len(sample))
        
        return {
            'mean_connections': np.mean(connection_counts),
            'std_connections': np.std(connection_counts),
            'max_connections': np.max(connection_counts),
            'min_connections': np.min(connection_counts)
        }
    
    def _create_protocol_baseline(self, data: Dict) -> Dict:
        """Create protocol distribution baseline"""
        total = sum(data['protocols'].values())
        if total == 0:
            return {}
        
        return {
            protocol: count / total 
            for protocol, count in data['protocols'].items()
        }
    
    def _create_connection_baseline(self, data: Dict) -> Dict:
        """Create connection patterns baseline"""
        if not data['connections']:
            return {}
        
        # Analyze connection patterns
        remote_ips = defaultdict(int)
        port_usage = defaultdict(int)
        
        for conn in data['connections']:
            remote_ip = conn['remote_addr'].split(':')[0]
            port = int(conn['remote_addr'].split(':')[1])
            
            remote_ips[remote_ip] += 1
            port_usage[port] += 1
        
        return {
            'unique_remote_ips': len(remote_ips),
            'avg_connections_per_ip': np.mean(list(remote_ips.values())),
            'most_common_ports': dict(sorted(port_usage.items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            logger.warning("Network monitoring already running")
            return
        
        self.monitoring = True
        logger.info("Starting network traffic analysis...")
        
        # Start monitoring threads
        threading.Thread(target=self._packet_capture_loop, daemon=True).start()
        threading.Thread(target=self._flow_analysis_loop, daemon=True).start()
        threading.Thread(target=self._threat_detection_loop, daemon=True).start()
        threading.Thread(target=self._protocol_analysis_loop, daemon=True).start()
        threading.Thread(target=self._baseline_monitoring_loop, daemon=True).start()
        
        logger.info("Network traffic analysis started")
    
    def _packet_capture_loop(self):
        """Packet capture loop"""
        self.packet_capture_active = True
        
        while self.packet_capture_active:
            try:
                # Capture packets (simplified for demonstration)
                # In a real implementation, this would use scapy's sniff()
                self._capture_network_packets()
                
                time.sleep(0.1)  # Capture interval
            
            except Exception as e:
                logger.error(f"Error in packet capture: {e}")
                time.sleep(1)
    
    def _capture_network_packets(self):
        """Capture network packets"""
        try:
            # Get current network statistics
            net_io = psutil.net_io_counters()
            connections = psutil.net_connections()
            
            # Simulate packet capture
            for conn in connections[:10]:  # Limit for performance
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    packet = NetworkPacket(
                        timestamp=datetime.now(),
                        src_ip=conn.laddr.ip,
                        dst_ip=conn.raddr.ip,
                        src_port=conn.laddr.port,
                        dst_port=conn.raddr.port,
                        protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        packet_size=random.randint(64, 1500),
                        payload_size=random.randint(0, 1400),
                        flags=['ACK', 'PSH'],
                        ttl=64,
                        packet_hash=self._generate_packet_hash(conn),
                        threat_score=0.0,
                        classification='normal'
                    )
                    
                    self._process_packet(packet)
        
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")
    
    def _generate_packet_hash(self, conn) -> str:
        """Generate packet hash"""
        packet_data = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{datetime.now()}"
        return hashlib.md5(packet_data.encode()).hexdigest()
    
    def _process_packet(self, packet: NetworkPacket):
        """Process captured packet"""
        # Add to packets list
        self.packets.append(packet)
        
        # Keep only recent packets
        if len(self.packets) > 10000:
            self.packets = self.packets[-10000:]
        
        # Update or create flow
        self._update_flow(packet)
        
        # Analyze packet for threats
        threat_score = self._analyze_packet_threat(packet)
        packet.threat_score = threat_score
        
        # Classify packet
        packet.classification = self._classify_packet(packet)
        
        # Store in database
        self._store_packet(packet)
    
    def _update_flow(self, packet: NetworkPacket):
        """Update or create network flow"""
        # Generate flow ID (5-tuple)
        flow_id = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
        
        if flow_id in self.flows:
            # Update existing flow
            flow = self.flows[flow_id]
            flow.end_time = packet.timestamp
            flow.packet_count += 1
            flow.byte_count += packet.packet_size
            flow.duration = (flow.end_time - flow.start_time).total_seconds()
            flow.flags.update(packet.flags)
        else:
            # Create new flow
            flow = NetworkFlow(
                flow_id=flow_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
                packet_count=1,
                byte_count=packet.packet_size,
                duration=0.0,
                flags=set(packet.flags),
                threat_score=packet.threat_score,
                classification=packet.classification
            )
            self.flows[flow_id] = flow
    
    def _analyze_packet_threat(self, packet: NetworkPacket) -> float:
        """Analyze packet for threats"""
        threat_score = 0.0
        
        # Check malicious IPs
        if packet.src_ip in self.malicious_ips or packet.dst_ip in self.malicious_ips:
            threat_score += 0.8
        
        # Check suspicious ports
        if packet.dst_port in self.c2_ports or packet.src_port in self.c2_ports:
            threat_score += 0.6
        
        # Check for unusual packet sizes
        if packet.packet_size > 8000 or packet.packet_size < 20:
            threat_score += 0.3
        
        # Check TTL anomalies
        if packet.ttl < 32 or packet.ttl > 128:
            threat_score += 0.2
        
        # Check protocol-specific threats
        if packet.protocol == 'TCP':
            # Check for suspicious flags
            if 'FIN' in packet.flags and 'URG' in packet.flags:
                threat_score += 0.4  # XMAS scan
            elif 'SYN' in packet.flags and 'FIN' in packet.flags:
                threat_score += 0.4  # SYN/FIN scan
        
        return min(threat_score, 1.0)
    
    def _classify_packet(self, packet: NetworkPacket) -> str:
        """Classify packet type"""
        # Port-based classification
        if packet.dst_port == 80 or packet.src_port == 80:
            return 'HTTP'
        elif packet.dst_port == 443 or packet.src_port == 443:
            return 'HTTPS'
        elif packet.dst_port == 53 or packet.src_port == 53:
            return 'DNS'
        elif packet.dst_port == 22 or packet.src_port == 22:
            return 'SSH'
        elif packet.dst_port == 21 or packet.src_port == 21:
            return 'FTP'
        elif packet.dst_port in self.c2_ports or packet.src_port in self.c2_ports:
            return 'C2'
        else:
            return 'OTHER'
    
    def _store_packet(self, packet: NetworkPacket):
        """Store packet in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_packets 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
             packet_size, payload_size, flags, ttl, packet_hash, threat_score, classification)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet.timestamp.isoformat(),
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
            packet.packet_size,
            packet.payload_size,
            json.dumps(list(packet.flags)),
            packet.ttl,
            packet.packet_hash,
            packet.threat_score,
            packet.classification
        ))
        
        conn.commit()
        conn.close()
    
    def _flow_analysis_loop(self):
        """Flow analysis loop"""
        self.flow_analysis_active = True
        
        while self.flow_analysis_active:
            try:
                # Analyze active flows
                for flow_id, flow in list(self.flows.items()):
                    # Update flow analysis
                    self._analyze_flow(flow)
                    
                    # Check if flow should be closed
                    if (datetime.now() - flow.end_time).seconds > 300:  # 5 minutes inactive
                        self._close_flow(flow_id)
                
                time.sleep(10)  # Analyze every 10 seconds
            
            except Exception as e:
                logger.error(f"Error in flow analysis: {e}")
                time.sleep(20)
    
    def _analyze_flow(self, flow: NetworkFlow):
        """Analyze network flow"""
        # Calculate flow threat score
        flow.threat_score = self._calculate_flow_threat(flow)
        
        # Classify flow
        flow.classification = self._classify_flow(flow)
        
        # Update flow in database
        self._update_flow_in_db(flow)
    
    def _calculate_flow_threat(self, flow: NetworkFlow) -> float:
        """Calculate flow threat score"""
        threat_score = 0.0
        
        # Check for malicious IPs
        if flow.src_ip in self.malicious_ips or flow.dst_ip in self.malicious_ips:
            threat_score += 0.7
        
        # Check for suspicious ports
        if flow.src_port in self.c2_ports or flow.dst_port in self.c2_ports:
            threat_score += 0.6
        
        # Check flow characteristics
        if flow.packet_count > 10000:  # High packet count
            threat_score += 0.3
        
        if flow.byte_count > 10000000:  # High byte count (10MB)
            threat_score += 0.3
        
        if flow.duration > 3600:  # Long duration (>1 hour)
            threat_score += 0.2
        
        # Check for unusual patterns
        if flow.packet_count > 0:
            avg_packet_size = flow.byte_count / flow.packet_count
            if avg_packet_size > 8000 or avg_packet_size < 20:
                threat_score += 0.2
        
        # Use ML model if available
        if 'anomaly' in self.anomaly_models:
            features = self._extract_flow_features(flow)
            try:
                anomaly_score = self.anomaly_models['anomaly'].decision_function([features])[0]
                # Convert to [0,1] where 1 is most anomalous
                normalized_score = 1 - (anomaly_score + 1) / 2
                threat_score += normalized_score * 0.4
            except Exception:
                pass
        
        return min(threat_score, 1.0)
    
    def _extract_flow_features(self, flow: NetworkFlow) -> List[float]:
        """Extract features from flow for ML analysis"""
        return [
            flow.byte_count,
            flow.packet_count,
            flow.duration,
            flow.src_port,
            flow.dst_port,
            len(flow.flags),
            hash(flow.src_ip) % 1000 / 1000.0,  # Normalize IP hash
            hash(flow.dst_ip) % 1000 / 1000.0
        ]
    
    def _classify_flow(self, flow: NetworkFlow) -> str:
        """Classify flow type"""
        # Use ML model if available
        if 'classification' in self.anomaly_models:
            features = self._extract_flow_features(flow)
            try:
                prediction = self.anomaly_models['classification'].predict([features])[0]
                class_map = {0: 'WEB', 1: 'DNS', 2: 'SSH', 3: 'MALICIOUS'}
                return class_map.get(prediction, 'UNKNOWN')
            except Exception:
                pass
        
        # Fallback to rule-based classification
        if flow.dst_port in [80, 8080] or flow.src_port in [80, 8080]:
            return 'WEB'
        elif flow.dst_port == 53 or flow.src_port == 53:
            return 'DNS'
        elif flow.dst_port == 22 or flow.src_port == 22:
            return 'SSH'
        elif flow.dst_port in self.c2_ports or flow.src_port in self.c2_ports:
            return 'C2'
        else:
            return 'OTHER'
    
    def _update_flow_in_db(self, flow: NetworkFlow):
        """Update flow in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO network_flows 
            (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
             start_time, end_time, packet_count, byte_count, duration,
             flags, threat_score, classification, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            flow.flow_id,
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.start_time.isoformat(),
            flow.end_time.isoformat(),
            flow.packet_count,
            flow.byte_count,
            flow.duration,
            json.dumps(list(flow.flags)),
            flow.threat_score,
            flow.classification,
            True
        ))
        
        conn.commit()
        conn.close()
    
    def _close_flow(self, flow_id: str):
        """Close network flow"""
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            flow.active = False
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE network_flows SET active = 0 WHERE flow_id = ?', (flow_id,))
            conn.commit()
            conn.close()
            
            # Remove from active flows
            del self.flows[flow_id]
    
    def _threat_detection_loop(self):
        """Threat detection loop"""
        self.threat_detection_active = True
        
        while self.threat_detection_active:
            try:
                # Detect various threat types
                self._detect_port_scans()
                self._detect_ddos_attacks()
                self._detect_data_exfiltration()
                self._detect_c2_communication()
                self._detect_anomalous_traffic()
                
                time.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.error(f"Error in threat detection: {e}")
                time.sleep(60)
    
    def _detect_port_scans(self):
        """Detect port scanning activity"""
        try:
            # Group packets by source IP
            src_ips = defaultdict(list)
            for packet in self.packets[-1000:]:  # Check recent packets
                src_ips[packet.src_ip].append(packet)
            
            # Look for scanning patterns
            for src_ip, packets in src_ips.items():
                if len(packets) < 10:
                    continue
                
                # Count unique destination ports
                dst_ports = set(packet.dst_port for packet in packets)
                
                # Check for port scan indicators
                if len(dst_ports) > 50:  # Many different ports
                    threat = NetworkThreat(
                        timestamp=datetime.now(),
                        threat_type="port_scan",
                        severity="medium",
                        source_ip=src_ip,
                        dest_ip="multiple",
                        port=0,
                        protocol="TCP",
                        confidence=0.7,
                        details={
                            'unique_ports': len(dst_ports),
                            'packet_count': len(packets),
                            'time_window': "recent"
                        },
                        mitigation_action="monitor_and_alert"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error detecting port scans: {e}")
    
    def _detect_ddos_attacks(self):
        """Detect DDoS attack patterns"""
        try:
            # Look for high traffic volume to single target
            dst_ips = defaultdict(list)
            for packet in self.packets[-1000:]:
                dst_ips[packet.dst_ip].append(packet)
            
            for dst_ip, packets in dst_ips.items():
                if len(packets) < 100:
                    continue
                
                # Check for DDoS indicators
                time_window = (max(p.timestamp for p in packets) - min(p.timestamp for p in packets)).seconds
                
                if time_window > 0:
                    packets_per_second = len(packets) / time_window
                    
                    if packets_per_second > 1000:  # High packet rate
                        threat = NetworkThreat(
                            timestamp=datetime.now(),
                            threat_type="ddos_attack",
                            severity="high",
                            source_ip="multiple",
                            dest_ip=dst_ip,
                            port=0,
                            protocol="TCP",
                            confidence=0.8,
                            details={
                                'packets_per_second': packets_per_second,
                                'total_packets': len(packets),
                                'time_window': time_window
                            },
                            mitigation_action="rate_limit_and_block"
                        )
                        
                        self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error detecting DDoS attacks: {e}")
    
    def _detect_data_exfiltration(self):
        """Detect data exfiltration patterns"""
        try:
            # Look for large outbound transfers
            for flow_id, flow in self.flows.items():
                if flow.byte_count > 100000000:  # > 100MB
                    if flow.dst_ip not in ['127.0.0.1', '::1'] and not flow.dst_ip.startswith('192.168.'):
                        threat = NetworkThreat(
                            timestamp=datetime.now(),
                            threat_type="data_exfiltration",
                            severity="high",
                            source_ip=flow.src_ip,
                            dest_ip=flow.dst_ip,
                            port=flow.dst_port,
                            protocol=flow.protocol,
                            confidence=0.6,
                            details={
                                'bytes_transferred': flow.byte_count,
                                'flow_duration': flow.duration,
                                'flow_id': flow_id
                            },
                            mitigation_action="inspect_and_block"
                        )
                        
                        self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error detecting data exfiltration: {e}")
    
    def _detect_c2_communication(self):
        """Detect command and control communication"""
        try:
            # Look for C2 indicators
            for packet in self.packets[-500:]:
                # Check for C2 ports
                if packet.dst_port in self.c2_ports:
                    threat = NetworkThreat(
                        timestamp=packet.timestamp,
                        threat_type="c2_communication",
                        severity="critical",
                        source_ip=packet.src_ip,
                        dest_ip=packet.dst_ip,
                        port=packet.dst_port,
                        protocol=packet.protocol,
                        confidence=0.8,
                        details={
                            'c2_port': packet.dst_port,
                            'packet_size': packet.packet_size
                        },
                        mitigation_action="block_immediately"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error detecting C2 communication: {e}")
    
    def _detect_anomalous_traffic(self):
        """Detect anomalous traffic patterns"""
        try:
            # Use ML model for anomaly detection
            if 'anomaly' not in self.anomaly_models:
                return
            
            # Analyze recent flows
            for flow in list(self.flows.values())[-100:]:
                features = self._extract_flow_features(flow)
                
                try:
                    anomaly_score = self.anomaly_models['anomaly'].decision_function([features])[0]
                    normalized_score = 1 - (anomaly_score + 1) / 2
                    
                    if normalized_score > 0.8:  # High anomaly score
                        threat = NetworkThreat(
                            timestamp=datetime.now(),
                            threat_type="anomalous_traffic",
                            severity="medium",
                            source_ip=flow.src_ip,
                            dest_ip=flow.dst_ip,
                            port=flow.dst_port,
                            protocol=flow.protocol,
                            confidence=normalized_score,
                            details={
                                'anomaly_score': normalized_score,
                                'flow_features': features,
                                'flow_id': flow.flow_id
                            },
                            mitigation_action="monitor_and_investigate"
                        )
                        
                        self._handle_threat(threat)
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting anomalous traffic: {e}")
    
    def _handle_threat(self, threat: NetworkThreat):
        """Handle detected threat"""
        logger.warning(f"THREAT DETECTED: {threat.threat_type}")
        logger.warning(f"Source: {threat.source_ip} -> Destination: {threat.dest_ip}")
        logger.warning(f"Confidence: {threat.confidence}")
        
        # Store threat
        self.threats.append(threat)
        
        # Keep only recent threats
        if len(self.threats) > 1000:
            self.threats = self.threats[-1000:]
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_threats 
            (timestamp, threat_type, severity, source_ip, dest_ip, port,
             protocol, confidence, details, mitigation_action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.timestamp.isoformat(),
            threat.threat_type,
            threat.severity,
            threat.source_ip,
            threat.dest_ip,
            threat.port,
            threat.protocol,
            threat.confidence,
            json.dumps(threat.details),
            threat.mitigation_action
        ))
        
        conn.commit()
        conn.close()
        
        # Take mitigation action
        self._apply_mitigation(threat)
    
    def _apply_mitigation(self, threat: NetworkThreat):
        """Apply mitigation action"""
        if threat.mitigation_action == "block_immediately":
            logger.critical(f"BLOCKING: {threat.source_ip}")
            # In a real implementation, this would use iptables or similar
            # subprocess.run(['iptables', '-A', 'INPUT', '-s', threat.source_ip, '-j', 'DROP'])
        
        elif threat.mitigation_action == "rate_limit_and_block":
            logger.warning(f"RATE LIMITING: {threat.source_ip}")
            # Apply rate limiting
        
        elif threat.mitigation_action == "monitor_and_alert":
            logger.info(f"MONITORING: {threat.source_ip}")
        
        elif threat.mitigation_action == "inspect_and_block":
            logger.warning(f"INSPECTING: {threat.source_ip}")
            # Deep packet inspection and potential blocking
    
    def _protocol_analysis_loop(self):
        """Protocol-specific analysis loop"""
        while self.monitoring:
            try:
                # Analyze different protocols
                for protocol, analyzer in self.protocol_analyzers.items():
                    try:
                        analyzer()
                    except Exception as e:
                        logger.error(f"Error analyzing {protocol}: {e}")
                
                time.sleep(60)  # Analyze every minute
            
            except Exception as e:
                logger.error(f"Error in protocol analysis: {e}")
                time.sleep(120)
    
    def _analyze_http(self):
        """Analyze HTTP traffic"""
        try:
            # Look for HTTP packets
            http_packets = [p for p in self.packets[-100:] if p.classification == 'HTTP']
            
            for packet in http_packets:
                # Check for suspicious HTTP patterns
                if packet.packet_size > 10000:  # Large HTTP request
                    threat = NetworkThreat(
                        timestamp=packet.timestamp,
                        threat_type="suspicious_http",
                        severity="medium",
                        source_ip=packet.src_ip,
                        dest_ip=packet.dst_ip,
                        port=packet.dst_port,
                        protocol="HTTP",
                        confidence=0.5,
                        details={'large_request': True, 'size': packet.packet_size},
                        mitigation_action="monitor"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing HTTP traffic: {e}")
    
    def _analyze_https(self):
        """Analyze HTTPS traffic"""
        try:
            # Look for HTTPS packets
            https_packets = [p for p in self.packets[-100:] if p.classification == 'HTTPS']
            
            # Check for suspicious HTTPS patterns
            for packet in https_packets:
                # Check for certificate issues (simplified)
                if packet.dst_port not in [443, 8443]:
                    threat = NetworkThreat(
                        timestamp=packet.timestamp,
                        threat_type="suspicious_https",
                        severity="low",
                        source_ip=packet.src_ip,
                        dest_ip=packet.dst_ip,
                        port=packet.dst_port,
                        protocol="HTTPS",
                        confidence=0.3,
                        details={'unusual_port': packet.dst_port},
                        mitigation_action="monitor"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing HTTPS traffic: {e}")
    
    def _analyze_dns(self):
        """Analyze DNS traffic"""
        try:
            # Look for DNS packets
            dns_packets = [p for p in self.packets[-100:] if p.classification == 'DNS']
            
            # Check for DNS tunneling
            for packet in dns_packets:
                if packet.packet_size > 512:  # Large DNS packet
                    threat = NetworkThreat(
                        timestamp=packet.timestamp,
                        threat_type="dns_tunneling",
                        severity="medium",
                        source_ip=packet.src_ip,
                        dest_ip=packet.dst_ip,
                        port=packet.dst_port,
                        protocol="DNS",
                        confidence=0.6,
                        details={'large_dns_packet': True, 'size': packet.packet_size},
                        mitigation_action="monitor"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing DNS traffic: {e}")
    
    def _analyze_ftp(self):
        """Analyze FTP traffic"""
        try:
            # Look for FTP packets
            ftp_packets = [p for p in self.packets[-100:] if p.classification == 'FTP']
            
            # Check for suspicious FTP activity
            for packet in ftp_packets:
                # FTP is inherently insecure
                threat = NetworkThreat(
                    timestamp=packet.timestamp,
                    threat_type="insecure_ftp",
                    severity="low",
                    source_ip=packet.src_ip,
                    dest_ip=packet.dst_ip,
                    port=packet.dst_port,
                    protocol="FTP",
                    confidence=0.4,
                    details={'insecure_protocol': True},
                    mitigation_action="monitor"
                )
                
                self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing FTP traffic: {e}")
    
    def _analyze_ssh(self):
        """Analyze SSH traffic"""
        try:
            # Look for SSH packets
            ssh_packets = [p for p in self.packets[-100:] if p.classification == 'SSH']
            
            # Check for suspicious SSH activity
            for packet in ssh_packets:
                # Check for brute force indicators
                if packet.packet_count > 100:  # Many packets
                    threat = NetworkThreat(
                        timestamp=packet.timestamp,
                        threat_type="ssh_brute_force",
                        severity="medium",
                        source_ip=packet.src_ip,
                        dest_ip=packet.dst_ip,
                        port=packet.dst_port,
                        protocol="SSH",
                        confidence=0.5,
                        details={'high_packet_count': True},
                        mitigation_action="monitor"
                    )
                    
                    self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing SSH traffic: {e}")
    
    def _analyze_telnet(self):
        """Analyze Telnet traffic"""
        try:
            # Look for Telnet packets
            telnet_packets = [p for p in self.packets[-100:] if p.classification == 'TELNET']
            
            # Telnet is inherently insecure
            for packet in telnet_packets:
                threat = NetworkThreat(
                    timestamp=packet.timestamp,
                    threat_type="insecure_telnet",
                    severity="medium",
                    source_ip=packet.src_ip,
                    dest_ip=packet.dst_ip,
                    port=packet.dst_port,
                    protocol="TELNET",
                    confidence=0.7,
                    details={'insecure_protocol': True},
                    mitigation_action="monitor"
                )
                
                self._handle_threat(threat)
        
        except Exception as e:
            logger.error(f"Error analyzing Telnet traffic: {e}")
    
    def _baseline_monitoring_loop(self):
        """Monitor traffic against baselines"""
        while self.monitoring:
            try:
                # Check current traffic against baselines
                current_traffic = self._get_current_traffic_stats()
                
                # Compare with baselines
                violations = self._check_baseline_violations(current_traffic)
                
                for violation in violations:
                    self._handle_baseline_violation(violation)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in baseline monitoring: {e}")
                time.sleep(600)
    
    def _get_current_traffic_stats(self) -> Dict:
        """Get current traffic statistics"""
        current_connections = psutil.net_connections()
        net_io = psutil.net_io_counters()
        
        return {
            'connection_count': len(current_connections),
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'active_flows': len(self.flows),
            'recent_packets': len(self.packets[-1000:])
        }
    
    def _check_baseline_violations(self, current_stats: Dict) -> List[Dict]:
        """Check for baseline violations"""
        violations = []
        
        try:
            # Check connection count
            if 'traffic_volume' in self.network_baselines:
                baseline = self.network_baselines['traffic_volume']
                mean_conn = baseline.get('mean_connections', 0)
                std_conn = baseline.get('std_connections', 1)
                
                if current_stats['connection_count'] > mean_conn + 3 * std_conn:
                    violations.append({
                        'type': 'high_connection_count',
                        'current': current_stats['connection_count'],
                        'baseline': mean_conn,
                        'severity': 'medium'
                    })
            
            # Check flow count
            if current_stats['active_flows'] > 1000:
                violations.append({
                    'type': 'high_flow_count',
                    'current': current_stats['active_flows'],
                    'severity': 'medium'
                })
            
            # Check packet rate
            if current_stats['recent_packets'] > 5000:
                violations.append({
                    'type': 'high_packet_rate',
                    'current': current_stats['recent_packets'],
                    'severity': 'high'
                })
        
        except Exception as e:
            logger.error(f"Error checking baseline violations: {e}")
        
        return violations
    
    def _handle_baseline_violation(self, violation: Dict):
        """Handle baseline violation"""
        logger.warning(f"BASELINE VIOLATION: {violation['type']}")
        logger.warning(f"Current: {violation['current']}, Baseline: {violation.get('baseline', 'N/A')}")
        
        threat = NetworkThreat(
            timestamp=datetime.now(),
            threat_type="baseline_violation",
            severity=violation['severity'],
            source_ip="system",
            dest_ip="system",
            port=0,
            protocol="SYSTEM",
            confidence=0.6,
            details=violation,
            mitigation_action="monitor_and_alert"
        )
        
        self._handle_threat(threat)
    
    def get_network_status(self) -> Dict:
        """Get current network analysis status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent statistics
        cursor.execute('''
            SELECT COUNT(*) FROM network_packets 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        recent_packets = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM network_threats 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        recent_threats = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM network_flows WHERE active = 1
        ''')
        active_flows = cursor.fetchone()[0]
        
        # Get threat distribution
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM network_threats 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
        ''')
        threat_distribution = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'packet_capture_active': self.packet_capture_active,
            'flow_analysis_active': self.flow_analysis_active,
            'threat_detection_active': self.threat_detection_active,
            'recent_packets': recent_packets,
            'recent_threats': recent_threats,
            'active_flows': active_flows,
            'threat_distribution': threat_distribution,
            'malicious_ips_count': len(self.malicious_ips),
            'suspicious_domains_count': len(self.suspicious_domains)
        }
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        self.packet_capture_active = False
        self.flow_analysis_active = False
        self.threat_detection_active = False
        
        logger.info("Network monitoring stopped")
    
    def generate_network_report(self) -> Dict:
        """Generate comprehensive network analysis report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get packet statistics
        cursor.execute('''
            SELECT protocol, COUNT(*) as count, AVG(threat_score) as avg_threat
            FROM network_packets 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY protocol
        ''')
        packet_stats = dict(cursor.fetchall())
        
        # Get flow statistics
        cursor.execute('''
            SELECT classification, COUNT(*) as count, AVG(threat_score) as avg_threat
            FROM network_flows 
            WHERE start_time > datetime('now', '-24 hours')
            GROUP BY classification
        ''')
        flow_stats = dict(cursor.fetchall())
        
        # Get top threat sources
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM network_threats 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_threat_sources = dict(cursor.fetchall())
        
        # Get threat severity distribution
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM network_threats 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        severity_distribution = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'monitoring_status': self.get_network_status(),
            'packet_statistics': packet_stats,
            'flow_statistics': flow_stats,
            'top_threat_sources': top_threat_sources,
            'severity_distribution': severity_distribution,
            'baseline_integrity': self._check_baseline_integrity(),
            'recommendations': self._generate_network_recommendations()
        }
    
    def _check_baseline_integrity(self) -> Dict:
        """Check baseline integrity"""
        integrity_status = {}
        
        for baseline_name, baseline_data in self.network_baselines.items():
            integrity_status[baseline_name] = {
                'exists': True,
                'data_points': len(baseline_data) if isinstance(baseline_data, dict) else 0,
                'last_updated': datetime.now().isoformat()
            }
        
        return integrity_status
    
    def _generate_network_recommendations(self) -> List[str]:
        """Generate network security recommendations"""
        recommendations = []
        
        status = self.get_network_status()
        
        if status['recent_threats'] > 50:
            recommendations.append("High threat activity - investigate network security")
        
        if status['active_flows'] > 1000:
            recommendations.append("High number of active flows - monitor for DDoS")
        
        recommendations.extend([
            "Implement network segmentation",
            "Enable deep packet inspection",
            "Regularly update threat intelligence feeds",
            "Monitor for unusual traffic patterns",
            "Implement network access controls",
            "Use encrypted protocols (HTTPS, SSH)"
        ])
        
        return recommendations
