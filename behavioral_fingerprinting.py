#!/usr/bin/env python3
"""
Advanced Behavioral Fingerprinting System
Deep behavioral analysis with machine learning and pattern recognition
"""

import os
import sys
import time
import threading
import logging
import json
import hashlib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Set
import sqlite3
import psutil
import socket
import subprocess
import re
from pathlib import Path

# ML Libraries
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics.pairwise import cosine_similarity
    import joblib
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn"])
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics.pairwise import cosine_similarity
    import joblib

logger = logging.getLogger(__name__)

@dataclass
class BehaviorProfile:
    """Behavioral profile fingerprint"""
    profile_id: str
    entity_type: str  # process, user, network, file
    entity_name: str
    features: Dict
    behavioral_hash: str
    risk_score: float
    anomaly_score: float
    created_at: datetime
    last_updated: datetime
    sample_count: int
    confidence: float

@dataclass
class BehaviorEvent:
    """Behavioral event data"""
    timestamp: datetime
    entity_type: str
    entity_id: str
    action_type: str
    action_details: Dict
    context: Dict
    risk_indicators: List[str]

class BehavioralFingerprinting:
    """Advanced behavioral fingerprinting system"""
    
    def __init__(self, db_path: str = "prix_behavioral.db"):
        self.db_path = db_path
        self.profiles = {}
        self.event_history = deque(maxlen=100000)
        self.behavioral_models = {}
        self.feature_scalers = {}
        self.anomaly_detectors = {}
        self.baseline_profiles = {}
        self.risk_thresholds = {
            'process': 0.7,
            'user': 0.6,
            'network': 0.8,
            'file': 0.5
        }
        
        # Initialize behavioral fingerprinting
        self.init_database()
        self.load_models()
        self.establish_baselines()
        
    def init_database(self):
        """Initialize behavioral database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Behavioral profiles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavior_profiles (
                profile_id TEXT PRIMARY KEY,
                entity_type TEXT,
                entity_name TEXT,
                features TEXT,
                behavioral_hash TEXT,
                risk_score REAL,
                anomaly_score REAL,
                created_at TEXT,
                last_updated TEXT,
                sample_count INTEGER,
                confidence REAL,
                is_baseline BOOLEAN DEFAULT 0
            )
        ''')
        
        # Behavioral events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavior_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                entity_type TEXT,
                entity_id TEXT,
                action_type TEXT,
                action_details TEXT,
                context TEXT,
                risk_indicators TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')
        
        # Anomaly detections
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomaly_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                entity_type TEXT,
                entity_id TEXT,
                anomaly_type TEXT,
                anomaly_score REAL,
                baseline_deviation REAL,
                risk_level TEXT,
                details TEXT,
                investigated BOOLEAN DEFAULT 0
            )
        ''')
        
        # Behavioral correlations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                entity1_type TEXT,
                entity1_id TEXT,
                entity2_type TEXT,
                entity2_id TEXT,
                correlation_score REAL,
                correlation_type TEXT,
                confidence REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_models(self):
        """Load behavioral analysis models"""
        model_dir = "behavioral_models"
        os.makedirs(model_dir, exist_ok=True)
        
        # Process behavior model
        process_model_path = os.path.join(model_dir, "process_behavior.pkl")
        if os.path.exists(process_model_path):
            self.behavioral_models['process'] = joblib.load(process_model_path)
            logger.info("Loaded process behavior model")
        else:
            self.behavioral_models['process'] = self._train_process_behavior_model()
            joblib.dump(self.behavioral_models['process'], process_model_path)
            logger.info("Trained process behavior model")
        
        # Network behavior model
        network_model_path = os.path.join(model_dir, "network_behavior.pkl")
        if os.path.exists(network_model_path):
            self.behavioral_models['network'] = joblib.load(network_model_path)
            logger.info("Loaded network behavior model")
        else:
            self.behavioral_models['network'] = self._train_network_behavior_model()
            joblib.dump(self.behavioral_models['network'], network_model_path)
            logger.info("Trained network behavior model")
        
        # Anomaly detection models
        for entity_type in ['process', 'user', 'network', 'file']:
            anomaly_model_path = os.path.join(model_dir, f"anomaly_{entity_type}.pkl")
            if os.path.exists(anomaly_model_path):
                self.anomaly_detectors[entity_type] = joblib.load(anomaly_model_path)
            else:
                self.anomaly_detectors[entity_type] = self._train_anomaly_detector(entity_type)
                joblib.dump(self.anomaly_detectors[entity_type], anomaly_model_path)
    
    def _train_process_behavior_model(self):
        """Train process behavior classification model"""
        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 8000
        
        # Normal process behaviors
        normal_features = np.random.multivariate_normal(
            [30, 20, 10, 5, 2, 1, 0.5],  # [cpu, memory, disk_io, net_io, file_ops, threads, connections]
            [[100, 30, 20, 10, 5, 2, 1],
             [30, 400, 50, 20, 10, 4, 2],
             [20, 50, 25, 15, 8, 3, 1.5],
             [10, 20, 15, 9, 4, 2, 1],
             [5, 10, 8, 4, 2, 1, 0.5],
             [2, 4, 3, 2, 1, 0.5, 0.25],
             [1, 2, 1.5, 1, 0.5, 0.25, 0.125]],
            n_samples // 2
        )
        
        # Malicious process behaviors
        malicious_features = np.random.multivariate_normal(
            [80, 70, 40, 25, 15, 8, 20],  # Higher resource usage
            [[200, 80, 60, 40, 25, 12, 8],
             [80, 600, 100, 60, 40, 20, 15],
             [60, 100, 80, 50, 35, 18, 12],
             [40, 60, 50, 36, 25, 15, 10],
             [25, 40, 35, 25, 18, 12, 8],
             [12, 20, 18, 15, 12, 8, 6],
             [8, 15, 12, 10, 8, 6, 4]],
            n_samples // 2
        )
        
        X = np.vstack([normal_features, malicious_features])
        
        # Train isolation forest for anomaly detection
        model = IsolationForest(
            contamination=0.1,
            n_estimators=100,
            max_samples='auto',
            random_state=42
        )
        model.fit(X)
        
        # Store feature scaler
        self.feature_scalers['process'] = StandardScaler()
        self.feature_scalers['process'].fit(X)
        
        return model
    
    def _train_network_behavior_model(self):
        """Train network behavior classification model"""
        np.random.seed(42)
        n_samples = 6000
        
        # Normal network behaviors
        normal_features = np.random.multivariate_normal(
            [5, 1000, 100, 10, 1, 50],  # [connections, bytes_sent, bytes_recv, packets, protocols, duration]
            [[4, 500, 50, 5, 0.5, 25],
             [500, 100000, 10000, 1000, 10, 5000],
             [50, 10000, 1000, 100, 1, 500],
             [5, 1000, 100, 10, 1, 50],
             [0.5, 10, 1, 0.1, 0.01, 5],
             [25, 5000, 500, 50, 5, 2500]],
            n_samples // 2
        )
        
        # Malicious network behaviors
        malicious_features = np.random.multivariate_normal(
            [50, 10000, 5000, 500, 10, 300],  # Suspicious activity
            [[25, 2500, 1250, 125, 2.5, 150],
             [2500, 500000, 250000, 25000, 500, 15000],
             [1250, 250000, 125000, 12500, 250, 7500],
             [125, 25000, 12500, 1250, 25, 750],
             [2.5, 500, 250, 25, 5, 150],
             [150, 15000, 7500, 750, 150, 4500]],
            n_samples // 2
        )
        
        X = np.vstack([normal_features, malicious_features])
        
        # Train isolation forest
        model = IsolationForest(
            contamination=0.15,
            n_estimators=100,
            max_samples='auto',
            random_state=42
        )
        model.fit(X)
        
        # Store feature scaler
        self.feature_scalers['network'] = StandardScaler()
        self.feature_scalers['network'].fit(X)
        
        return model
    
    def _train_anomaly_detector(self, entity_type: str):
        """Train anomaly detector for specific entity type"""
        # Generate synthetic data for the entity type
        np.random.seed(42)
        n_samples = 5000
        
        if entity_type == 'process':
            features = np.random.multivariate_normal(
                [30, 20, 10, 5, 2], np.eye(5) * 10, n_samples
            )
        elif entity_type == 'network':
            features = np.random.multivariate_normal(
                [5, 1000, 100, 10], np.eye(4) * 100, n_samples
            )
        elif entity_type == 'user':
            features = np.random.multivariate_normal(
                [10, 5, 2, 1], np.eye(4) * 5, n_samples
            )
        elif entity_type == 'file':
            features = np.random.multivariate_normal(
                [50, 20, 5, 1], np.eye(4) * 20, n_samples
            )
        else:
            features = np.random.randn(n_samples, 10)
        
        # Train isolation forest
        model = IsolationForest(
            contamination=0.1,
            n_estimators=50,
            random_state=42
        )
        model.fit(features)
        
        return model
    
    def establish_baselines(self):
        """Establish behavioral baselines"""
        logger.info("Establishing behavioral baselines...")
        
        # Process baselines
        self._establish_process_baseline()
        
        # Network baselines
        self._establish_network_baseline()
        
        # User baselines
        self._establish_user_baseline()
        
        # File baselines
        self._establish_file_baseline()
        
        logger.info("Behavioral baselines established")
    
    def _establish_process_baseline(self):
        """Establish process behavior baseline"""
        baseline_data = []
        
        # Collect process data over time
        for _ in range(50):  # Sample over time
            snapshot = self._collect_process_behavior()
            baseline_data.extend(snapshot)
            time.sleep(0.1)
        
        if baseline_data:
            # Create baseline profile
            baseline_profile = BehaviorProfile(
                profile_id="process_baseline",
                entity_type="process",
                entity_name="baseline",
                features=self._aggregate_process_features(baseline_data),
                behavioral_hash=self._calculate_behavioral_hash(baseline_data),
                risk_score=0.1,
                anomaly_score=0.1,
                created_at=datetime.now(),
                last_updated=datetime.now(),
                sample_count=len(baseline_data),
                confidence=0.9
            )
            
            self.baseline_profiles['process'] = baseline_profile
            self._save_profile(baseline_profile)
    
    def _collect_process_behavior(self) -> List[Dict]:
        """Collect current process behavior data"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                       'num_threads', 'connections', 'io_counters']):
            try:
                proc_info = proc.info
                
                # Get network connections
                try:
                    connections = proc.connections()
                    connection_count = len(connections)
                except:
                    connection_count = 0
                
                # Get I/O counters
                try:
                    io_counters = proc.io_counters()
                    disk_read = io_counters.read_bytes
                    disk_write = io_counters.write_bytes
                except:
                    disk_read = disk_write = 0
                
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'cpu_percent': proc_info['cpu_percent'],
                    'memory_percent': proc_info['memory_percent'],
                    'num_threads': proc_info['num_threads'],
                    'connections': connection_count,
                    'disk_read': disk_read,
                    'disk_write': disk_write,
                    'timestamp': datetime.now()
                })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def _aggregate_process_features(self, process_data: List[Dict]) -> Dict:
        """Aggregate process features for baseline"""
        if not process_data:
            return {}
        
        # Calculate statistics
        cpu_values = [p['cpu_percent'] for p in process_data]
        memory_values = [p['memory_percent'] for p in process_data]
        thread_values = [p['num_threads'] for p in process_data]
        connection_values = [p['connections'] for p in process_data]
        
        return {
            'cpu_mean': np.mean(cpu_values),
            'cpu_std': np.std(cpu_values),
            'memory_mean': np.mean(memory_values),
            'memory_std': np.std(memory_values),
            'threads_mean': np.mean(thread_values),
            'threads_std': np.std(thread_values),
            'connections_mean': np.mean(connection_values),
            'connections_std': np.std(connection_values),
            'process_count': len(process_data)
        }
    
    def _establish_network_baseline(self):
        """Establish network behavior baseline"""
        baseline_data = []
        
        # Collect network data over time
        for _ in range(30):  # Sample over time
            snapshot = self._collect_network_behavior()
            baseline_data.append(snapshot)
            time.sleep(0.2)
        
        if baseline_data:
            baseline_profile = BehaviorProfile(
                profile_id="network_baseline",
                entity_type="network",
                entity_name="baseline",
                features=self._aggregate_network_features(baseline_data),
                behavioral_hash=self._calculate_behavioral_hash(baseline_data),
                risk_score=0.1,
                anomaly_score=0.1,
                created_at=datetime.now(),
                last_updated=datetime.now(),
                sample_count=len(baseline_data),
                confidence=0.9
            )
            
            self.baseline_profiles['network'] = baseline_profile
            self._save_profile(baseline_profile)
    
    def _collect_network_behavior(self) -> Dict:
        """Collect current network behavior data"""
        connections = psutil.net_connections()
        
        # Count connection types
        established = len([c for c in connections if c.status == 'ESTABLISHED'])
        listening = len([c for c in connections if c.status == 'LISTEN'])
        time_wait = len([c for c in connections if c.status == 'TIME_WAIT'])
        
        # Get network I/O
        try:
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv
            packets_sent = net_io.packets_sent
            packets_recv = net_io.packets_recv
        except:
            bytes_sent = bytes_recv = packets_sent = packets_recv = 0
        
        # Get unique remote hosts
        remote_hosts = set()
        for conn in connections:
            if conn.raddr:
                remote_hosts.add(conn.raddr.ip)
        
        return {
            'total_connections': len(connections),
            'established': established,
            'listening': listening,
            'time_wait': time_wait,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'packets_sent': packets_sent,
            'packets_recv': packets_recv,
            'unique_hosts': len(remote_hosts),
            'timestamp': datetime.now()
        }
    
    def _aggregate_network_features(self, network_data: List[Dict]) -> Dict:
        """Aggregate network features for baseline"""
        if not network_data:
            return {}
        
        # Calculate statistics
        total_conn = [n['total_connections'] for n in network_data]
        established = [n['established'] for n in network_data]
        listening = [n['listening'] for n in network_data]
        bytes_sent = [n['bytes_sent'] for n in network_data]
        bytes_recv = [n['bytes_recv'] for n in network_data]
        unique_hosts = [n['unique_hosts'] for n in network_data]
        
        return {
            'connections_mean': np.mean(total_conn),
            'connections_std': np.std(total_conn),
            'established_mean': np.mean(established),
            'listening_mean': np.mean(listening),
            'bytes_sent_rate': np.mean(np.diff(bytes_sent)) if len(bytes_sent) > 1 else 0,
            'bytes_recv_rate': np.mean(np.diff(bytes_recv)) if len(bytes_recv) > 1 else 0,
            'unique_hosts_mean': np.mean(unique_hosts),
            'sample_count': len(network_data)
        }
    
    def _establish_user_baseline(self):
        """Establish user behavior baseline"""
        # This would track user login patterns, command usage, etc.
        baseline_profile = BehaviorProfile(
            profile_id="user_baseline",
            entity_type="user",
            entity_name="baseline",
            features={'login_frequency': 1.0, 'command_diversity': 0.8},
            behavioral_hash="user_baseline_hash",
            risk_score=0.1,
            anomaly_score=0.1,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            sample_count=100,
            confidence=0.8
        )
        
        self.baseline_profiles['user'] = baseline_profile
        self._save_profile(baseline_profile)
    
    def _establish_file_baseline(self):
        """Establish file behavior baseline"""
        # This would track file access patterns, modifications, etc.
        baseline_profile = BehaviorProfile(
            profile_id="file_baseline",
            entity_type="file",
            entity_name="baseline",
            features={'access_frequency': 2.5, 'modification_rate': 0.3},
            behavioral_hash="file_baseline_hash",
            risk_score=0.1,
            anomaly_score=0.1,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            sample_count=200,
            confidence=0.8
        )
        
        self.baseline_profiles['file'] = baseline_profile
        self._save_profile(baseline_profile)
    
    def _calculate_behavioral_hash(self, data: List[Dict]) -> str:
        """Calculate behavioral fingerprint hash"""
        # Convert data to string representation
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _save_profile(self, profile: BehaviorProfile):
        """Save behavioral profile to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO behavior_profiles 
            (profile_id, entity_type, entity_name, features, behavioral_hash,
             risk_score, anomaly_score, created_at, last_updated, sample_count, confidence, is_baseline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            profile.profile_id,
            profile.entity_type,
            profile.entity_name,
            json.dumps(profile.features),
            profile.behavioral_hash,
            profile.risk_score,
            profile.anomaly_score,
            profile.created_at.isoformat(),
            profile.last_updated.isoformat(),
            profile.sample_count,
            profile.confidence,
            profile.profile_id.endswith('_baseline')
        ))
        
        conn.commit()
        conn.close()
    
    def analyze_process_behavior(self, process_info: Dict) -> Dict:
        """Analyze process behavior against baseline"""
        # Extract features
        features = self._extract_process_features(process_info)
        
        # Get baseline
        baseline = self.baseline_profiles.get('process')
        if not baseline:
            return {'error': 'No baseline established'}
        
        # Calculate deviation from baseline
        deviation_score = self._calculate_process_deviation(features, baseline.features)
        
        # ML-based anomaly detection
        anomaly_score = self._detect_process_anomaly(features)
        
        # Behavioral pattern matching
        pattern_score = self._match_process_patterns(process_info)
        
        # Calculate overall risk
        risk_score = (deviation_score * 0.4) + (anomaly_score * 0.4) + (pattern_score * 0.2)
        
        # Generate behavioral fingerprint
        behavioral_hash = self._generate_process_fingerprint(process_info, features)
        
        # Update or create profile
        profile_id = f"process_{process_info.get('pid', 'unknown')}"
        self._update_process_profile(profile_id, process_info, features, risk_score, anomaly_score)
        
        return {
            'risk_score': risk_score,
            'anomaly_score': anomaly_score,
            'deviation_score': deviation_score,
            'pattern_score': pattern_score,
            'behavioral_hash': behavioral_hash,
            'risk_level': self._calculate_risk_level(risk_score),
            'indicators': self._get_process_risk_indicators(process_info, features),
            'recommendation': self._get_process_recommendation(risk_score)
        }
    
    def _extract_process_features(self, process_info: Dict) -> List[float]:
        """Extract numerical features from process info"""
        features = [
            process_info.get('cpu_percent', 0),
            process_info.get('memory_percent', 0),
            process_info.get('num_threads', 0),
            process_info.get('connections', 0),
            process_info.get('disk_read_bytes', 0) / 1000000,  # Normalize to MB
            process_info.get('disk_write_bytes', 0) / 1000000,  # Normalize to MB
            len(process_info.get('cmdline', [])),
            hash(process_info.get('name', '')) % 1000 / 1000.0,  # Normalize hash
        ]
        return features
    
    def _calculate_process_deviation(self, features: List[float], baseline_features: Dict) -> float:
        """Calculate deviation from baseline"""
        try:
            # Current features vs baseline statistics
            current_cpu = features[0]
            current_memory = features[1]
            current_threads = features[2]
            current_connections = features[3]
            
            # Calculate z-scores
            cpu_z = abs(current_cpu - baseline_features.get('cpu_mean', 0)) / max(baseline_features.get('cpu_std', 1), 1)
            memory_z = abs(current_memory - baseline_features.get('memory_mean', 0)) / max(baseline_features.get('memory_std', 1), 1)
            threads_z = abs(current_threads - baseline_features.get('threads_mean', 0)) / max(baseline_features.get('threads_std', 1), 1)
            connections_z = abs(current_connections - baseline_features.get('connections_mean', 0)) / max(baseline_features.get('connections_std', 1), 1)
            
            # Average deviation
            deviation = (cpu_z + memory_z + threads_z + connections_z) / 4
            
            # Normalize to [0,1]
            return min(deviation / 3.0, 1.0)  # 3 standard deviations is high deviation
            
        except Exception as e:
            logger.error(f"Error calculating process deviation: {e}")
            return 0.5
    
    def _detect_process_anomaly(self, features: List[float]) -> float:
        """Detect process anomalies using ML"""
        try:
            if 'process' not in self.anomaly_detectors:
                return 0.0
            
            # Scale features
            features_scaled = self.feature_scalers.get('process', StandardScaler()).transform([features])
            
            # Get anomaly score
            anomaly_score = self.anomaly_detectors['process'].decision_function(features_scaled)[0]
            
            # Convert to [0,1] where 1 is most anomalous
            normalized_score = 1 - (anomaly_score + 1) / 2
            
            return max(0, min(normalized_score, 1.0))
            
        except Exception as e:
            logger.error(f"Error detecting process anomaly: {e}")
            return 0.0
    
    def _match_process_patterns(self, process_info: Dict) -> float:
        """Match process against known malicious patterns"""
        score = 0.0
        
        name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', [])).lower()
        
        # Suspicious process names
        suspicious_names = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit',
            'keylogger', 'spyware', 'ransomware', 'bot', 'miner'
        ]
        
        for susp in suspicious_names:
            if susp in name:
                score += 0.3
            if susp in cmdline:
                score += 0.2
        
        # Suspicious command line patterns
        suspicious_patterns = [
            '--decode', '--encode', '--encrypt', '--decrypt',
            '--inject', '--hook', '--patch', '--exploit'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in cmdline:
                score += 0.1
        
        return min(score, 1.0)
    
    def _generate_process_fingerprint(self, process_info: Dict, features: List[float]) -> str:
        """Generate unique behavioral fingerprint for process"""
        fingerprint_data = {
            'name': process_info.get('name', ''),
            'cmdline': process_info.get('cmdline', []),
            'features': features,
            'parent_pid': process_info.get('ppid', 0),
            'create_time': process_info.get('create_time', 0)
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def _update_process_profile(self, profile_id: str, process_info: Dict, 
                               features: List[float], risk_score: float, anomaly_score: float):
        """Update or create process profile"""
        profile = BehaviorProfile(
            profile_id=profile_id,
            entity_type="process",
            entity_name=process_info.get('name', 'unknown'),
            features={'features': features, 'process_info': process_info},
            behavioral_hash=self._generate_process_fingerprint(process_info, features),
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            sample_count=1,
            confidence=0.7
        )
        
        self.profiles[profile_id] = profile
        self._save_profile(profile)
    
    def _calculate_risk_level(self, risk_score: float) -> str:
        """Calculate risk level from score"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _get_process_risk_indicators(self, process_info: Dict, features: List[float]) -> List[str]:
        """Get specific risk indicators for process"""
        indicators = []
        
        # High resource usage
        if features[0] > 90:  # CPU
            indicators.append("high_cpu_usage")
        if features[1] > 80:  # Memory
            indicators.append("high_memory_usage")
        if features[3] > 50:  # Connections
            indicators.append("excessive_connections")
        
        # Suspicious characteristics
        if process_info.get('is_hidden', False):
            indicators.append("hidden_process")
        if len(process_info.get('cmdline', [])) > 10:
            indicators.append("complex_command_line")
        if process_info.get('has_elevated_privileges', False):
            indicators.append("elevated_privileges")
        
        return indicators
    
    def _get_process_recommendation(self, risk_score: float) -> str:
        """Get recommendation based on risk score"""
        if risk_score >= 0.8:
            return "IMMEDIATE_INVESTIGATION_REQUIRED"
        elif risk_score >= 0.6:
            return "MONITOR_CLOSELY"
        elif risk_score >= 0.4:
            return "ENHANCED_MONITORING"
        else:
            return "NORMAL_MONITORING"
    
    def analyze_network_behavior(self, network_info: Dict) -> Dict:
        """Analyze network behavior against baseline"""
        # Extract features
        features = self._extract_network_features(network_info)
        
        # Get baseline
        baseline = self.baseline_profiles.get('network')
        if not baseline:
            return {'error': 'No baseline established'}
        
        # Calculate deviation
        deviation_score = self._calculate_network_deviation(features, baseline.features)
        
        # ML-based anomaly detection
        anomaly_score = self._detect_network_anomaly(features)
        
        # Pattern analysis
        pattern_score = self._analyze_network_patterns(network_info)
        
        # Calculate overall risk
        risk_score = (deviation_score * 0.4) + (anomaly_score * 0.4) + (pattern_score * 0.2)
        
        return {
            'risk_score': risk_score,
            'anomaly_score': anomaly_score,
            'deviation_score': deviation_score,
            'pattern_score': pattern_score,
            'risk_level': self._calculate_risk_level(risk_score),
            'indicators': self._get_network_risk_indicators(network_info),
            'recommendation': self._get_network_recommendation(risk_score)
        }
    
    def _extract_network_features(self, network_info: Dict) -> List[float]:
        """Extract numerical features from network info"""
        features = [
            network_info.get('connection_count', 0),
            network_info.get('bytes_sent', 0) / 1000000,  # Normalize to MB
            network_info.get('bytes_received', 0) / 1000000,  # Normalize to MB
            network_info.get('packets_sent', 0),
            network_info.get('packets_received', 0),
            len(network_info.get('remote_hosts', set())),
            network_info.get('suspicious_ports', 0),
            network_info.get('dns_queries', 0)
        ]
        return features
    
    def _calculate_network_deviation(self, features: List[float], baseline_features: Dict) -> float:
        """Calculate network deviation from baseline"""
        try:
            current_connections = features[0]
            current_bytes_sent_rate = features[1]
            current_bytes_recv_rate = features[2]
            current_unique_hosts = features[5]
            
            # Calculate z-scores (simplified)
            connections_z = abs(current_connections - baseline_features.get('connections_mean', 0)) / max(baseline_features.get('connections_std', 1), 1)
            sent_z = abs(current_bytes_sent_rate - baseline_features.get('bytes_sent_rate', 0)) / max(baseline_features.get('bytes_sent_rate', 1), 1)
            recv_z = abs(current_bytes_recv_rate - baseline_features.get('bytes_recv_rate', 0)) / max(baseline_features.get('bytes_recv_rate', 1), 1)
            hosts_z = abs(current_unique_hosts - baseline_features.get('unique_hosts_mean', 0)) / max(baseline_features.get('unique_hosts_mean', 1), 1)
            
            deviation = (connections_z + sent_z + recv_z + hosts_z) / 4
            return min(deviation / 3.0, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating network deviation: {e}")
            return 0.5
    
    def _detect_network_anomaly(self, features: List[float]) -> float:
        """Detect network anomalies using ML"""
        try:
            if 'network' not in self.anomaly_detectors:
                return 0.0
            
            features_scaled = self.feature_scalers.get('network', StandardScaler()).transform([features])
            anomaly_score = self.anomaly_detectors['network'].decision_function(features_scaled)[0]
            normalized_score = 1 - (anomaly_score + 1) / 2
            
            return max(0, min(normalized_score, 1.0))
            
        except Exception as e:
            logger.error(f"Error detecting network anomaly: {e}")
            return 0.0
    
    def _analyze_network_patterns(self, network_info: Dict) -> float:
        """Analyze network patterns for suspicious activity"""
        score = 0.0
        
        # High connection count
        if network_info.get('connection_count', 0) > 100:
            score += 0.3
        
        # High data transfer
        if network_info.get('bytes_sent', 0) > 100000000:  # 100MB
            score += 0.2
        if network_info.get('bytes_received', 0) > 100000000:  # 100MB
            score += 0.2
        
        # Suspicious ports
        if network_info.get('suspicious_ports', 0) > 0:
            score += 0.3
        
        return min(score, 1.0)
    
    def _get_network_risk_indicators(self, network_info: Dict) -> List[str]:
        """Get network risk indicators"""
        indicators = []
        
        if network_info.get('connection_count', 0) > 100:
            indicators.append("excessive_connections")
        if network_info.get('bytes_sent', 0) > 100000000:
            indicators.append("high_data_egress")
        if network_info.get('bytes_received', 0) > 100000000:
            indicators.append("high_data_ingress")
        if network_info.get('suspicious_ports', 0) > 0:
            indicators.append("suspicious_ports")
        if len(network_info.get('remote_hosts', set())) > 50:
            indicators.append("many_remote_hosts")
        
        return indicators
    
    def _get_network_recommendation(self, risk_score: float) -> str:
        """Get network recommendation"""
        if risk_score >= 0.8:
            return "BLOCK_SUSPICIOUS_TRAFFIC"
        elif risk_score >= 0.6:
            return "THROTTLE_CONNECTIONS"
        elif risk_score >= 0.4:
            return "MONITOR_TRAFFIC"
        else:
            return "NORMAL_MONITORING"
    
    def correlate_behaviors(self, entity1_type: str, entity1_id: str, 
                           entity2_type: str, entity2_id: str) -> Dict:
        """Correlate behaviors between entities"""
        # Get profiles
        profile1 = self.profiles.get(f"{entity1_type}_{entity1_id}")
        profile2 = self.profiles.get(f"{entity2_type}_{entity2_id}")
        
        if not profile1 or not profile2:
            return {'error': 'Profiles not found'}
        
        # Calculate correlation score
        correlation_score = self._calculate_behavioral_correlation(profile1, profile2)
        
        # Determine correlation type
        correlation_type = self._determine_correlation_type(profile1, profile2, correlation_score)
        
        # Calculate confidence
        confidence = min(profile1.confidence, profile2.confidence) * correlation_score
        
        # Store correlation
        self._store_correlation(entity1_type, entity1_id, entity2_type, entity2_id,
                               correlation_score, correlation_type, confidence)
        
        return {
            'correlation_score': correlation_score,
            'correlation_type': correlation_type,
            'confidence': confidence,
            'risk_implication': self._assess_correlation_risk(correlation_score, correlation_type)
        }
    
    def _calculate_behavioral_correlation(self, profile1: BehaviorProfile, profile2: BehaviorProfile) -> float:
        """Calculate behavioral correlation between profiles"""
        try:
            # Extract feature vectors
            features1 = self._extract_profile_features(profile1)
            features2 = self._extract_profile_features(profile2)
            
            # Calculate cosine similarity
            similarity = cosine_similarity([features1], [features2])[0][0]
            
            # Convert to [0,1] range
            correlation = (similarity + 1) / 2
            
            return correlation
            
        except Exception as e:
            logger.error(f"Error calculating behavioral correlation: {e}")
            return 0.5
    
    def _extract_profile_features(self, profile: BehaviorProfile) -> List[float]:
        """Extract feature vector from profile"""
        # This would extract meaningful features from the profile
        # For demonstration, use basic features
        return [
            profile.risk_score,
            profile.anomaly_score,
            profile.confidence,
            profile.sample_count / 1000.0,  # Normalize
            hash(profile.behavioral_hash[:8]) % 1000 / 1000.0  # Normalize partial hash
        ]
    
    def _determine_correlation_type(self, profile1: BehaviorProfile, profile2: BehaviorProfile, 
                                  correlation_score: float) -> str:
        """Determine type of correlation"""
        if correlation_score > 0.8:
            return "strong_behavioral_match"
        elif correlation_score > 0.6:
            return "moderate_behavioral_similarity"
        elif correlation_score > 0.4:
            return "weak_behavioral_link"
        else:
            return "no_significant_correlation"
    
    def _assess_correlation_risk(self, correlation_score: float, correlation_type: str) -> str:
        """Assess risk implication of correlation"""
        if correlation_type == "strong_behavioral_match" and correlation_score > 0.8:
            return "high_risk_coordinated_behavior"
        elif correlation_type == "moderate_behavioral_similarity":
            return "medium_risk_potential_coordination"
        else:
            return "low_risk_coincidence"
    
    def _store_correlation(self, entity1_type: str, entity1_id: str, entity2_type: str, 
                          entity2_id: str, correlation_score: float, 
                          correlation_type: str, confidence: float):
        """Store behavioral correlation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO behavioral_correlations 
            (timestamp, entity1_type, entity1_id, entity2_type, entity2_id,
             correlation_score, correlation_type, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            entity1_type, entity1_id,
            entity2_type, entity2_id,
            correlation_score, correlation_type, confidence
        ))
        
        conn.commit()
        conn.close()
    
    def generate_behavioral_report(self, timeframe_hours: int = 24) -> Dict:
        """Generate comprehensive behavioral analysis report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get profile statistics
        cursor.execute('''
            SELECT entity_type, COUNT(*) as count, AVG(risk_score) as avg_risk
            FROM behavior_profiles 
            WHERE last_updated > datetime('now', '-{} hours')
            GROUP BY entity_type
        '''.format(timeframe_hours))
        
        profile_stats = {}
        for row in cursor.fetchall():
            profile_stats[row[0]] = {
                'count': row[1],
                'avg_risk': row[2]
            }
        
        # Get anomaly statistics
        cursor.execute('''
            SELECT entity_type, COUNT(*) as count, AVG(anomaly_score) as avg_anomaly
            FROM anomaly_detections 
            WHERE timestamp > datetime('now', '-{} hours')
            GROUP BY entity_type
        '''.format(timeframe_hours))
        
        anomaly_stats = {}
        for row in cursor.fetchall():
            anomaly_stats[row[0]] = {
                'count': row[1],
                'avg_anomaly': row[2]
            }
        
        # Get correlation statistics
        cursor.execute('''
            SELECT correlation_type, COUNT(*) as count, AVG(correlation_score) as avg_score
            FROM behavioral_correlations 
            WHERE timestamp > datetime('now', '-{} hours')
            GROUP BY correlation_type
        '''.format(timeframe_hours))
        
        correlation_stats = {}
        for row in cursor.fetchall():
            correlation_stats[row[0]] = {
                'count': row[1],
                'avg_score': row[2]
            }
        
        conn.close()
        
        return {
            'timeframe_hours': timeframe_hours,
            'profile_statistics': profile_stats,
            'anomaly_statistics': anomaly_stats,
            'correlation_statistics': correlation_stats,
            'baseline_integrity': self._verify_baseline_integrity(),
            'recommendations': self._generate_behavioral_recommendations()
        }
    
    def _verify_baseline_integrity(self) -> Dict:
        """Verify baseline integrity"""
        integrity_status = {}
        
        for entity_type, baseline in self.baseline_profiles.items():
            # Check baseline age
            age_hours = (datetime.now() - baseline.last_updated).total_seconds() / 3600
            
            # Check baseline confidence
            confidence_ok = baseline.confidence > 0.7
            
            # Check sample count
            sample_ok = baseline.sample_count > 50
            
            integrity_status[entity_type] = {
                'age_hours': age_hours,
                'confidence_ok': confidence_ok,
                'sample_ok': sample_ok,
                'overall_integrity': confidence_ok and sample_ok and age_hours < 168  # 1 week
            }
        
        return integrity_status
    
    def _generate_behavioral_recommendations(self) -> List[str]:
        """Generate behavioral analysis recommendations"""
        recommendations = []
        
        # Check baseline integrity
        integrity = self._verify_baseline_integrity()
        for entity_type, status in integrity.items():
            if not status['overall_integrity']:
                recommendations.append(f"Update {entity_type} behavioral baseline")
        
        # Check for high-risk profiles
        high_risk_count = sum(1 for p in self.profiles.values() if p.risk_score > 0.7)
        if high_risk_count > 10:
            recommendations.append("Investigate high-risk behavioral profiles")
        
        recommendations.extend([
            "Continue collecting behavioral data",
            "Review anomaly detection thresholds",
            "Update behavioral patterns database"
        ])
        
        return recommendations
