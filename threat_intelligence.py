#!/usr/bin/env python3
"""
Advanced Threat Intelligence Integration System
Real-time threat data collection, analysis, and dissemination
"""

import os
import sys
import time
import threading
import logging
import json
import hashlib
import base64
import requests
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# Threat intelligence libraries
try:
    import feedparser
    import dns.resolver
    import geoip2.database
    import iocextract
    import vt
except ImportError:
    print("Installing threat intelligence libraries...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "feedparser", "dnspython", "geoip2", "iocextract", "virustotal-api"])
    import feedparser
    import dns.resolver
    import geoip2.database
    import iocextract
    import vt

# ML libraries
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    import joblib
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn", "pandas", "numpy"])
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    import joblib

logger = logging.getLogger(__name__)

@dataclass
class ThreatIndicator:
    """Threat intelligence indicator"""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    source: str
    confidence: float
    severity: str
    first_seen: datetime
    last_seen: datetime
    tags: Set[str]
    context: Dict
    malware_families: Set[str]
    actors: Set[str]

@dataclass
class ThreatReport:
    """Threat intelligence report"""
    report_id: str
    title: str
    source: str
    published: datetime
    author: str
    tags: Set[str]
    indicators: List[ThreatIndicator]
    tactics: Set[str]
    techniques: Set[str]
    malware_families: Set[str]
    threat_actors: Set[str]
    severity: str
    confidence: float
    summary: str

@dataclass
class ThreatAlert:
    """Threat intelligence alert"""
    alert_id: str
    timestamp: datetime
    alert_type: str
    severity: str
    indicator: ThreatIndicator
    context: Dict
    correlation_score: float
    recommended_actions: List[str]

class ThreatIntelligence:
    """Advanced threat intelligence integration system"""
    
    def __init__(self, db_path: str = "prix_threatintel.db"):
        self.db_path = db_path
        self.monitoring = False
        
        # Threat intelligence components
        self.indicators = {}
        self.reports = {}
        self.alerts = []
        self.feed_sources = {}
        self.analyzers = {}
        
        # API keys and configurations
        self.api_keys = {}
        self.feed_configs = {}
        
        # Threat data storage
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.malicious_hashes = set()
        self.malicious_urls = set()
        self.suspicious_emails = set()
        
        # Correlation engine
        self.correlation_engine = None
        self.anomaly_detector = None
        
        # Initialize threat intelligence
        self.init_database()
        self.load_configurations()
        self.init_analyzers()
        self.init_correlation_engine()
        self.load_historical_data()
        self.start_threat_monitoring()
    
    def init_database(self):
        """Initialize threat intelligence database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threat indicators table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                indicator_type TEXT,
                value TEXT,
                source TEXT,
                confidence REAL,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                tags TEXT,
                context TEXT,
                malware_families TEXT,
                actors TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Threat reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_reports (
                report_id TEXT PRIMARY KEY,
                title TEXT,
                source TEXT,
                published TEXT,
                author TEXT,
                tags TEXT,
                indicators TEXT,
                tactics TEXT,
                techniques TEXT,
                malware_families TEXT,
                threat_actors TEXT,
                severity TEXT,
                confidence REAL,
                summary TEXT,
                processed BOOLEAN DEFAULT 0,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Threat alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT,
                alert_type TEXT,
                severity TEXT,
                indicator_id TEXT,
                context TEXT,
                correlation_score REAL,
                recommended_actions TEXT,
                acknowledged BOOLEAN DEFAULT 0,
                created_at TEXT
            )
        ''')
        
        # Feed sources table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feed_sources (
                source_id TEXT PRIMARY KEY,
                name TEXT,
                url TEXT,
                feed_type TEXT,
                format TEXT,
                api_key_required BOOLEAN DEFAULT 0,
                last_updated TEXT,
                update_frequency INTEGER,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT
            )
        ''')
        
        # Correlations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT,
                indicator_ids TEXT,
                correlation_type TEXT,
                confidence REAL,
                context TEXT,
                discovered_at TEXT
            )
        ''')
        
        # Threat statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                indicator_type TEXT,
                source TEXT,
                new_indicators INTEGER,
                total_indicators INTEGER,
                high_severity INTEGER,
                medium_severity INTEGER,
                low_severity INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_configurations(self):
        """Load threat intelligence configurations"""
        logger.info("Loading threat intelligence configurations...")
        
        # Load feed sources
        self._load_feed_sources()
        
        # Load API keys
        self._load_api_keys()
        
        logger.info(f"Loaded {len(self.feed_sources)} feed sources")
    
    def _load_feed_sources(self):
        """Load threat feed sources"""
        default_feeds = [
            {
                'source_id': 'malware_domain_list',
                'name': 'Malware Domain List',
                'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
                'feed_type': 'domain',
                'format': 'text',
                'api_key_required': False,
                'update_frequency': 3600  # 1 hour
            },
            {
                'source_id': 'phish tank',
                'name': 'PhishTank',
                'url': 'https://checkurl.phishtank.com/api/',
                'feed_type': 'url',
                'format': 'json',
                'api_key_required': True,
                'update_frequency': 1800  # 30 minutes
            },
            {
                'source_id': 'vxvault',
                'name': 'VXVault',
                'url': 'http://vxvault.net/VirusList.txt',
                'feed_type': 'url',
                'format': 'text',
                'api_key_required': False,
                'update_frequency': 3600
            },
            {
                'source_id': 'abuse_ch',
                'name': 'Abuse.ch Feeds',
                'url': 'https://feodotracker.abuse.ch/downloads/feodotracker.txt',
                'feed_type': 'domain',
                'format': 'text',
                'api_key_required': False,
                'update_frequency': 3600
            },
            {
                'source_id': 'cve_feed',
                'name': 'CVE Feed',
                'url': 'https://cve.circl.lu/api/cves/',
                'feed_type': 'cve',
                'format': 'json',
                'api_key_required': False,
                'update_frequency': 86400  # 24 hours
            }
        ]
        
        for feed_config in default_feeds:
            self.feed_sources[feed_config['source_id']] = feed_config
            self._store_feed_source(feed_config)
    
    def _store_feed_source(self, feed_config: Dict):
        """Store feed source in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO feed_sources 
            (source_id, name, url, feed_type, format, api_key_required, 
             update_frequency, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            feed_config['source_id'],
            feed_config['name'],
            feed_config['url'],
            feed_config['feed_type'],
            feed_config['format'],
            feed_config['api_key_required'],
            feed_config['update_frequency'],
            True,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _load_api_keys(self):
        """Load API keys from environment or config"""
        # In a real implementation, these would be loaded from secure storage
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'phishtank': os.getenv('PHISHTANK_API_KEY', ''),
            'shodan': os.getenv('SHODAN_API_KEY', ''),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', '')
        }
    
    def init_analyzers(self):
        """Initialize threat analyzers"""
        self.analyzers = {
            'ip_analyzer': IPAnalyzer(),
            'domain_analyzer': DomainAnalyzer(),
            'hash_analyzer': HashAnalyzer(),
            'url_analyzer': URLAnalyzer(),
            'email_analyzer': EmailAnalyzer(),
            'malware_analyzer': MalwareAnalyzer()
        }
        
        logger.info("Threat analyzers initialized")
    
    def init_correlation_engine(self):
        """Initialize correlation engine"""
        self.correlation_engine = CorrelationEngine()
        self.anomaly_detector = AnomalyDetector()
        
        logger.info("Correlation engine initialized")
    
    def load_historical_data(self):
        """Load historical threat data"""
        logger.info("Loading historical threat data...")
        
        # Load indicators from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threat_indicators WHERE is_active = 1')
        for row in cursor.fetchall():
            indicator = self._row_to_indicator(row)
            self.indicators[indicator.indicator_id] = indicator
            
            # Add to appropriate sets
            if indicator.indicator_type == 'ip':
                self.malicious_ips.add(indicator.value)
            elif indicator.indicator_type == 'domain':
                self.malicious_domains.add(indicator.value)
            elif indicator.indicator_type == 'hash':
                self.malicious_hashes.add(indicator.value)
            elif indicator.indicator_type == 'url':
                self.malicious_urls.add(indicator.value)
            elif indicator.indicator_type == 'email':
                self.suspicious_emails.add(indicator.value)
        
        conn.close()
        logger.info(f"Loaded {len(self.indicators)} historical indicators")
    
    def _row_to_indicator(self, row) -> ThreatIndicator:
        """Convert database row to ThreatIndicator"""
        return ThreatIndicator(
            indicator_id=row[0],
            indicator_type=row[1],
            value=row[2],
            source=row[3],
            confidence=row[4],
            severity=row[5],
            first_seen=datetime.fromisoformat(row[6]),
            last_seen=datetime.fromisoformat(row[7]),
            tags=set(json.loads(row[8])),
            context=json.loads(row[9]),
            malware_families=set(json.loads(row[10])),
            actors=set(json.loads(row[11]))
        )
    
    def start_threat_monitoring(self):
        """Start threat intelligence monitoring"""
        self.monitoring = True
        logger.info("Starting threat intelligence monitoring...")
        
        # Start monitoring threads
        threading.Thread(target=self._feed_collection_loop, daemon=True).start()
        threading.Thread(target=self._threat_analysis_loop, daemon=True).start()
        threading.Thread(target=self._correlation_loop, daemon=True).start()
        threading.Thread(target=self._alert_generation_loop, daemon=True).start()
        threading.Thread(target=self._statistics_loop, daemon=True).start()
        
        logger.info("Threat intelligence monitoring started")
    
    def _feed_collection_loop(self):
        """Collect threat feeds"""
        while self.monitoring:
            try:
                for source_id, feed_config in self.feed_sources.items():
                    if not feed_config.get('is_active', True):
                        continue
                    
                    # Check if feed needs updating
                    last_updated = feed_config.get('last_updated')
                    update_frequency = feed_config.get('update_frequency', 3600)
                    
                    if last_updated:
                        last_update_time = datetime.fromisoformat(last_updated)
                        if (datetime.now() - last_update_time).seconds < update_frequency:
                            continue
                    
                    # Collect feed data
                    self._collect_feed(source_id, feed_config)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in feed collection: {e}")
                time.sleep(600)
    
    def _collect_feed(self, source_id: str, feed_config: Dict):
        """Collect data from specific feed"""
        try:
            logger.info(f"Collecting feed: {feed_config['name']}")
            
            feed_type = feed_config['feed_type']
            feed_format = feed_config['format']
            url = feed_config['url']
            
            if feed_format == 'text':
                indicators = self._parse_text_feed(url, feed_type)
            elif feed_format == 'json':
                indicators = self._parse_json_feed(url, feed_type)
            elif feed_format == 'xml':
                indicators = self._parse_xml_feed(url, feed_type)
            elif feed_format == 'rss':
                indicators = self._parse_rss_feed(url, feed_type)
            else:
                logger.warning(f"Unsupported feed format: {feed_format}")
                return
            
            # Store indicators
            for indicator_data in indicators:
                self._store_indicator(indicator_data, source_id)
            
            # Update feed last_updated
            feed_config['last_updated'] = datetime.now().isoformat()
            self._update_feed_source(feed_config)
            
            logger.info(f"Collected {len(indicators)} indicators from {feed_config['name']}")
        
        except Exception as e:
            logger.error(f"Error collecting feed {source_id}: {e}")
    
    def _parse_text_feed(self, url: str, feed_type: str) -> List[Dict]:
        """Parse text-based threat feed"""
        indicators = []
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Extract indicators based on feed type
                if feed_type == 'domain':
                    if self._is_valid_domain(line):
                        indicators.append({
                            'value': line,
                            'type': 'domain',
                            'source': url,
                            'confidence': 0.7,
                            'severity': 'medium'
                        })
                elif feed_type == 'url':
                    if line.startswith('http'):
                        indicators.append({
                            'value': line,
                            'type': 'url',
                            'source': url,
                            'confidence': 0.7,
                            'severity': 'medium'
                        })
                elif feed_type == 'ip':
                    if self._is_valid_ip(line):
                        indicators.append({
                            'value': line,
                            'type': 'ip',
                            'source': url,
                            'confidence': 0.7,
                            'severity': 'medium'
                        })
        
        except Exception as e:
            logger.error(f"Error parsing text feed {url}: {e}")
        
        return indicators
    
    def _parse_json_feed(self, url: str, feed_type: str) -> List[Dict]:
        """Parse JSON-based threat feed"""
        indicators = []
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse based on feed structure
            if feed_type == 'cve':
                for cve in data.get('CVE_Items', []):
                    cve_id = cve.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                    if cve_id:
                        indicators.append({
                            'value': cve_id,
                            'type': 'cve',
                            'source': url,
                            'confidence': 0.9,
                            'severity': self._get_cve_severity(cve)
                        })
        
        except Exception as e:
            logger.error(f"Error parsing JSON feed {url}: {e}")
        
        return indicators
    
    def _parse_xml_feed(self, url: str, feed_type: str) -> List[Dict]:
        """Parse XML-based threat feed"""
        indicators = []
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Use feedparser for RSS/Atom feeds
            feed = feedparser.parse(response.content)
            
            for entry in feed.entries:
                # Extract indicators from feed content
                content = entry.get('summary', '') + entry.get('content', '')
                extracted_iocs = iocextract.extract_iocs(content)
                
                for ioc_type, ioc_list in extracted_iocs.items():
                    for ioc in ioc_list:
                        indicators.append({
                            'value': ioc,
                            'type': ioc_type,
                            'source': url,
                            'confidence': 0.6,
                            'severity': 'medium'
                        })
        
        except Exception as e:
            logger.error(f"Error parsing XML feed {url}: {e}")
        
        return indicators
    
    def _parse_rss_feed(self, url: str, feed_type: str) -> List[Dict]:
        """Parse RSS threat feed"""
        return self._parse_xml_feed(url, feed_type)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string is valid domain"""
        try:
            # Basic domain validation
            if len(domain) > 253 or len(domain) < 3:
                return False
            if domain.startswith('.') or domain.endswith('.'):
                return False
            return all(c.isalnum() or c in '.-' for c in domain)
        except:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def _get_cve_severity(self, cve_data: Dict) -> str:
        """Extract CVE severity"""
        try:
            impact = cve_data.get('impact', {})
            base_metric_v3 = impact.get('baseMetricV3', {})
            cvss_v3 = base_metric_v3.get('cvssV3', {})
            base_score = cvss_v3.get('baseScore', 0.0)
            
            if base_score >= 9.0:
                return 'critical'
            elif base_score >= 7.0:
                return 'high'
            elif base_score >= 4.0:
                return 'medium'
            else:
                return 'low'
        except:
            return 'medium'
    
    def _store_indicator(self, indicator_data: Dict, source_id: str):
        """Store threat indicator"""
        try:
            indicator_id = self._generate_indicator_id(indicator_data['value'], indicator_data['type'])
            
            # Check if indicator already exists
            if indicator_id in self.indicators:
                existing = self.indicators[indicator_id]
                existing.last_seen = datetime.now()
                existing.confidence = max(existing.confidence, indicator_data['confidence'])
                self._update_indicator(existing)
                return
            
            # Create new indicator
            indicator = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=indicator_data['type'],
                value=indicator_data['value'],
                source=source_id,
                confidence=indicator_data['confidence'],
                severity=indicator_data['severity'],
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=set(),
                context={},
                malware_families=set(),
                actors=set()
            )
            
            self.indicators[indicator_id] = indicator
            self._store_indicator_in_db(indicator)
            
            # Add to appropriate sets
            if indicator.indicator_type == 'ip':
                self.malicious_ips.add(indicator.value)
            elif indicator.indicator_type == 'domain':
                self.malicious_domains.add(indicator.value)
            elif indicator.indicator_type == 'hash':
                self.malicious_hashes.add(indicator.value)
            elif indicator.indicator_type == 'url':
                self.malicious_urls.add(indicator.value)
            elif indicator.indicator_type == 'email':
                self.suspicious_emails.add(indicator.value)
        
        except Exception as e:
            logger.error(f"Error storing indicator: {e}")
    
    def _generate_indicator_id(self, value: str, indicator_type: str) -> str:
        """Generate unique indicator ID"""
        hash_input = f"{indicator_type}:{value}"
        return f"indicator_{hashlib.sha256(hash_input.encode()).hexdigest()[:16]}"
    
    def _store_indicator_in_db(self, indicator: ThreatIndicator):
        """Store indicator in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_indicators 
            (indicator_id, indicator_type, value, source, confidence, severity,
             first_seen, last_seen, tags, context, malware_families, actors,
             is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            indicator.indicator_id,
            indicator.indicator_type,
            indicator.value,
            indicator.source,
            indicator.confidence,
            indicator.severity,
            indicator.first_seen.isoformat(),
            indicator.last_seen.isoformat(),
            json.dumps(list(indicator.tags)),
            json.dumps(indicator.context),
            json.dumps(list(indicator.malware_families)),
            json.dumps(list(indicator.actors)),
            True,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _update_indicator(self, indicator: ThreatIndicator):
        """Update existing indicator"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE threat_indicators 
            SET last_seen = ?, confidence = ?, updated_at = ?
            WHERE indicator_id = ?
        ''', (
            indicator.last_seen.isoformat(),
            indicator.confidence,
            datetime.now().isoformat(),
            indicator.indicator_id
        ))
        
        conn.commit()
        conn.close()
    
    def _update_feed_source(self, feed_config: Dict):
        """Update feed source in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE feed_sources 
            SET last_updated = ?
            WHERE source_id = ?
        ''', (feed_config['last_updated'], feed_config['source_id']))
        
        conn.commit()
        conn.close()
    
    def _threat_analysis_loop(self):
        """Analyze collected threat data"""
        while self.monitoring:
            try:
                # Analyze new indicators
                new_indicators = [
                    ind for ind in self.indicators.values()
                    if (datetime.now() - ind.first_seen).seconds < 3600  # Last hour
                ]
                
                for indicator in new_indicators:
                    self._analyze_indicator(indicator)
                
                # Analyze patterns and trends
                self._analyze_threat_patterns()
                
                time.sleep(600)  # Analyze every 10 minutes
            
            except Exception as e:
                logger.error(f"Error in threat analysis: {e}")
                time.sleep(1200)
    
    def _analyze_indicator(self, indicator: ThreatIndicator):
        """Analyze individual indicator"""
        try:
            analyzer = self.analyzers.get(f"{indicator.indicator_type}_analyzer")
            if analyzer:
                analysis_result = analyzer.analyze(indicator.value)
                
                # Update indicator with analysis results
                indicator.context.update(analysis_result.get('context', {}))
                indicator.tags.update(analysis_result.get('tags', set()))
                indicator.malware_families.update(analysis_result.get('malware_families', set()))
                indicator.actors.update(analysis_result.get('actors', set()))
                
                # Update confidence and severity
                indicator.confidence = min(1.0, indicator.confidence + analysis_result.get('confidence_boost', 0.0))
                if analysis_result.get('severity'):
                    indicator.severity = analysis_result['severity']
                
                self._update_indicator(indicator)
        
        except Exception as e:
            logger.error(f"Error analyzing indicator {indicator.indicator_id}: {e}")
    
    def _analyze_threat_patterns(self):
        """Analyze threat patterns and trends"""
        try:
            # Analyze temporal patterns
            self._analyze_temporal_patterns()
            
            # Analyze geographic patterns
            self._analyze_geographic_patterns()
            
            # Analyze malware family trends
            self._analyze_malware_trends()
            
            # Detect anomalies
            self._detect_threat_anomalies()
        
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {e}")
    
    def _analyze_temporal_patterns(self):
        """Analyze temporal threat patterns"""
        try:
            # Group indicators by time
            time_patterns = defaultdict(list)
            
            for indicator in self.indicators.values():
                hour = indicator.first_seen.hour
                time_patterns[hour].append(indicator)
            
            # Identify unusual time patterns
            avg_indicators_per_hour = len(self.indicators) / 24
            
            for hour, indicators in time_patterns.items():
                if len(indicators) > avg_indicators_per_hour * 2:
                    logger.warning(f"Unusual threat activity at hour {hour}: {len(indicators)} indicators")
        
        except Exception as e:
            logger.error(f"Error analyzing temporal patterns: {e}")
    
    def _analyze_geographic_patterns(self):
        """Analyze geographic threat patterns"""
        try:
            # Analyze IP geolocation patterns
            ip_countries = defaultdict(int)
            
            for indicator in self.indicators.values():
                if indicator.indicator_type == 'ip':
                    country = indicator.context.get('country', 'unknown')
                    ip_countries[country] += 1
            
            # Identify unusual geographic patterns
            for country, count in ip_countries.items():
                if count > 100:  # Threshold for unusual activity
                    logger.warning(f"High threat activity from {country}: {count} indicators")
        
        except Exception as e:
            logger.error(f"Error analyzing geographic patterns: {e}")
    
    def _analyze_malware_trends(self):
        """Analyze malware family trends"""
        try:
            # Analyze malware family distribution
            malware_counts = defaultdict(int)
            
            for indicator in self.indicators.values():
                for family in indicator.malware_families:
                    malware_counts[family] += 1
            
            # Identify trending malware families
            top_families = sorted(malware_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            for family, count in top_families:
                logger.info(f"Trending malware family: {family} ({count} indicators)")
        
        except Exception as e:
            logger.error(f"Error analyzing malware trends: {e}")
    
    def _detect_threat_anomalies(self):
        """Detect anomalies in threat data"""
        try:
            # Use anomaly detector to find unusual patterns
            features = self._extract_threat_features()
            
            if len(features) > 10:
                anomalies = self.anomaly_detector.detect_anomalies(features)
                
                for anomaly in anomalies:
                    logger.warning(f"Threat anomaly detected: {anomaly}")
                    
                    # Create alert for anomaly
                    self._create_anomaly_alert(anomaly)
        
        except Exception as e:
            logger.error(f"Error detecting threat anomalies: {e}")
    
    def _extract_threat_features(self) -> List[List[float]]:
        """Extract features for anomaly detection"""
        features = []
        
        # Extract features from recent indicators
        recent_indicators = [
            ind for ind in self.indicators.values()
            if (datetime.now() - ind.first_seen).days < 7  # Last week
        ]
        
        # Group by hour for feature extraction
        hourly_data = defaultdict(lambda: {'ip': 0, 'domain': 0, 'url': 0, 'hash': 0})
        
        for indicator in recent_indicators:
            hour = indicator.first_seen.hour
            hourly_data[hour][indicator.indicator_type] += 1
        
        for hour in range(24):
            data = hourly_data[hour]
            features.append([
                data['ip'],
                data['domain'],
                data['url'],
                data['hash'],
                sum(data.values())
            ])
        
        return features
    
    def _create_anomaly_alert(self, anomaly: Dict):
        """Create alert for detected anomaly"""
        alert_id = f"alert_anomaly_{secrets.token_hex(8)}"
        
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            alert_type="anomaly",
            severity="medium",
            indicator=None,  # Anomaly alerts don't have specific indicators
            context=anomaly,
            correlation_score=anomaly.get('score', 0.5),
            recommended_actions=["investigate_pattern", "enhance_monitoring"]
        )
        
        self.alerts.append(alert)
        self._store_alert(alert)
    
    def _correlation_loop(self):
        """Correlate threat indicators"""
        while self.monitoring:
            try:
                # Find correlations between indicators
                correlations = self.correlation_engine.find_correlations(self.indicators)
                
                for correlation in correlations:
                    self._handle_correlation(correlation)
                
                time.sleep(1800)  # Correlate every 30 minutes
            
            except Exception as e:
                logger.error(f"Error in threat correlation: {e}")
                time.sleep(3600)
    
    def _handle_correlation(self, correlation: Dict):
        """Handle detected correlation"""
        try:
            correlation_id = f"corr_{secrets.token_hex(8)}"
            
            # Store correlation
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_correlations 
                (correlation_id, indicator_ids, correlation_type, confidence, context, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                correlation_id,
                json.dumps(correlation['indicator_ids']),
                correlation['type'],
                correlation['confidence'],
                json.dumps(correlation['context']),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Create correlation alert if high confidence
            if correlation['confidence'] > 0.8:
                self._create_correlation_alert(correlation)
        
        except Exception as e:
            logger.error(f"Error handling correlation: {e}")
    
    def _create_correlation_alert(self, correlation: Dict):
        """Create alert for high-confidence correlation"""
        alert_id = f"alert_corr_{secrets.token_hex(8)}"
        
        # Get one of the correlated indicators
        indicator_id = correlation['indicator_ids'][0]
        indicator = self.indicators.get(indicator_id)
        
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            alert_type="correlation",
            severity="high",
            indicator=indicator,
            context=correlation,
            correlation_score=correlation['confidence'],
            recommended_actions=["investigate_campaign", "block_related_indicators"]
        )
        
        self.alerts.append(alert)
        self._store_alert(alert)
    
    def _alert_generation_loop(self):
        """Generate threat alerts"""
        while self.monitoring:
            try:
                # Check for high-priority indicators
                high_priority_indicators = [
                    ind for ind in self.indicators.values()
                    if ind.severity in ['critical', 'high'] and 
                       (datetime.now() - ind.first_seen).seconds < 3600  # Last hour
                ]
                
                for indicator in high_priority_indicators:
                    # Check if alert already exists
                    if not self._alert_exists(indicator.indicator_id):
                        self._create_indicator_alert(indicator)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in alert generation: {e}")
                time.sleep(600)
    
    def _alert_exists(self, indicator_id: str) -> bool:
        """Check if alert already exists for indicator"""
        for alert in self.alerts:
            if alert.indicator and alert.indicator.indicator_id == indicator_id:
                return True
        return False
    
    def _create_indicator_alert(self, indicator: ThreatIndicator):
        """Create alert for high-priority indicator"""
        alert_id = f"alert_{secrets.token_hex(8)}"
        
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            alert_type="new_indicator",
            severity=indicator.severity,
            indicator=indicator,
            context={'source': indicator.source, 'confidence': indicator.confidence},
            correlation_score=indicator.confidence,
            recommended_actions=self._get_recommended_actions(indicator)
        )
        
        self.alerts.append(alert)
        self._store_alert(alert)
    
    def _get_recommended_actions(self, indicator: ThreatIndicator) -> List[str]:
        """Get recommended actions for indicator"""
        actions = []
        
        if indicator.indicator_type == 'ip':
            actions.extend(["block_ip", "monitor_connections"])
        elif indicator.indicator_type == 'domain':
            actions.extend(["block_domain", "monitor_dns"])
        elif indicator.indicator_type == 'hash':
            actions.extend(["quarantine_file", "scan_system"])
        elif indicator.indicator_type == 'url':
            actions.extend(["block_url", "monitor_web_traffic"])
        
        if indicator.severity == 'critical':
            actions.append("immediate_action")
        elif indicator.severity == 'high':
            actions.append("enhanced_monitoring")
        
        return actions
    
    def _store_alert(self, alert: ThreatAlert):
        """Store alert in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_alerts 
            (alert_id, timestamp, alert_type, severity, indicator_id, context,
             correlation_score, recommended_actions, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id,
            alert.timestamp.isoformat(),
            alert.alert_type,
            alert.severity,
            alert.indicator.indicator_id if alert.indicator else None,
            json.dumps(alert.context),
            alert.correlation_score,
            json.dumps(alert.recommended_actions),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _statistics_loop(self):
        """Generate threat intelligence statistics"""
        while self.monitoring:
            try:
                # Generate daily statistics
                self._generate_daily_statistics()
                
                time.sleep(86400)  # Generate daily
        
            except Exception as e:
                logger.error(f"Error in statistics generation: {e}")
                time.sleep(3600)
    
    def _generate_daily_statistics(self):
        """Generate daily threat statistics"""
        try:
            today = datetime.now().date()
            
            # Count indicators by type and source
            stats = defaultdict(lambda: defaultdict(int))
            
            for indicator in self.indicators.values():
                if indicator.first_seen.date() == today:
                    stats[indicator.indicator_type][indicator.source] += 1
            
            # Store statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for indicator_type, source_stats in stats.items():
                for source, count in source_stats.items():
                    cursor.execute('''
                        INSERT INTO threat_statistics 
                        (date, indicator_type, source, new_indicators, total_indicators)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        today.isoformat(),
                        indicator_type,
                        source,
                        count,
                        len([i for i in self.indicators.values() if i.indicator_type == indicator_type])
                    ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Generated daily statistics for {today}")
        
        except Exception as e:
            logger.error(f"Error generating daily statistics: {e}")
    
    def check_indicator(self, value: str, indicator_type: str = None) -> Dict:
        """Check if value matches any threat indicators"""
        try:
            # Try to determine type if not specified
            if not indicator_type:
                indicator_type = self._determine_indicator_type(value)
            
            # Search for matching indicators
            matches = []
            
            for indicator in self.indicators.values():
                if indicator.indicator_type == indicator_type and indicator.value == value:
                    matches.append(indicator)
            
            if not matches:
                return {
                    'found': False,
                    'indicator_type': indicator_type,
                    'value': value,
                    'matches': []
                }
            
            # Return best match (highest confidence)
            best_match = max(matches, key=lambda x: x.confidence)
            
            return {
                'found': True,
                'indicator_type': indicator_type,
                'value': value,
                'matches': len(matches),
                'best_match': {
                    'indicator_id': best_match.indicator_id,
                    'source': best_match.source,
                    'confidence': best_match.confidence,
                    'severity': best_match.severity,
                    'first_seen': best_match.first_seen.isoformat(),
                    'last_seen': best_match.last_seen.isoformat(),
                    'tags': list(best_match.tags),
                    'malware_families': list(best_match.malware_families),
                    'actors': list(best_match.actors)
                }
            }
        
        except Exception as e:
            logger.error(f"Error checking indicator {value}: {e}")
            return {'found': False, 'error': str(e)}
    
    def _determine_indicator_type(self, value: str) -> str:
        """Determine indicator type from value"""
        if self._is_valid_ip(value):
            return 'ip'
        elif self._is_valid_domain(value):
            return 'domain'
        elif value.startswith('http'):
            return 'url'
        elif len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value):
            return 'hash'
        elif '@' in value and '.' in value.split('@')[1]:
            return 'email'
        else:
            return 'unknown'
    
    def get_threat_intelligence_status(self) -> Dict:
        """Get threat intelligence system status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get indicator counts by type
        cursor.execute('''
            SELECT indicator_type, COUNT(*) FROM threat_indicators 
            WHERE is_active = 1 GROUP BY indicator_type
        ''')
        indicator_counts = dict(cursor.fetchall())
        
        # Get recent indicators
        cursor.execute('''
            SELECT COUNT(*) FROM threat_indicators 
            WHERE first_seen > datetime('now', '-24 hours')
        ''')
        recent_indicators = cursor.fetchone()[0]
        
        # Get active alerts
        cursor.execute('''
            SELECT COUNT(*) FROM threat_alerts 
            WHERE acknowledged = 0 AND timestamp > datetime('now', '-24 hours')
        ''')
        active_alerts = cursor.fetchone()[0]
        
        # Get feed status
        cursor.execute('''
            SELECT source_id, name, last_updated, is_active FROM feed_sources
        ''')
        feed_status = cursor.fetchall()
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'total_indicators': len(self.indicators),
            'indicator_counts': indicator_counts,
            'recent_indicators': recent_indicators,
            'active_alerts': active_alerts,
            'feed_sources': len(feed_status),
            'active_feeds': len([f for f in feed_status if f[3]]),
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'malicious_hashes': len(self.malicious_hashes),
            'malicious_urls': len(self.malicious_urls)
        }
    
    def stop_monitoring(self):
        """Stop threat intelligence monitoring"""
        self.monitoring = False
        logger.info("Threat intelligence monitoring stopped")
    
    def generate_threat_intelligence_report(self) -> Dict:
        """Generate comprehensive threat intelligence report"""
        try:
            status = self.get_threat_intelligence_status()
            
            # Get detailed statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Severity distribution
            cursor.execute('''
                SELECT severity, COUNT(*) FROM threat_indicators 
                WHERE is_active = 1 GROUP BY severity
            ''')
            severity_distribution = dict(cursor.fetchall())
            
            # Source distribution
            cursor.execute('''
                SELECT source, COUNT(*) FROM threat_indicators 
                WHERE is_active = 1 GROUP BY source
                ORDER BY COUNT(*) DESC LIMIT 10
            ''')
            top_sources = dict(cursor.fetchall())
            
            # Recent trends
            cursor.execute('''
                SELECT DATE(first_seen) as date, COUNT(*) as count
                FROM threat_indicators 
                WHERE first_seen > datetime('now', '-7 days')
                GROUP BY DATE(first_seen)
                ORDER BY date
            ''')
            recent_trends = dict(cursor.fetchall())
            
            # Malware families
            cursor.execute('''
                SELECT value, COUNT(*) as count
                FROM (
                    SELECT json_extract(malware_families, '$[*]') as families
                    FROM threat_indicators 
                    WHERE is_active = 1 AND malware_families != '[]'
                ),
                json_each(families)
                GROUP BY value
                ORDER BY count DESC
                LIMIT 10
            ''')
            malware_families = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'system_status': status,
                'severity_distribution': severity_distribution,
                'top_sources': top_sources,
                'recent_trends': recent_trends,
                'malware_families': malware_families,
                'recommendations': self._generate_threat_intel_recommendations()
            }
        
        except Exception as e:
            logger.error(f"Error generating threat intelligence report: {e}")
            return {'error': str(e)}
    
    def _generate_threat_intel_recommendations(self) -> List[str]:
        """Generate threat intelligence recommendations"""
        recommendations = []
        
        status = self.get_threat_intelligence_status()
        
        if status['active_alerts'] > 50:
            recommendations.append("High number of active alerts - investigate priority threats")
        
        if status['recent_indicators'] > 1000:
            recommendations.append("High volume of new indicators - review feed quality")
        
        if status['active_feeds'] < len(self.feed_sources):
            recommendations.append("Some feeds are inactive - check feed configurations")
        
        recommendations.extend([
            "Regularly review and update threat feed sources",
            "Implement automated indicator blocking for high-confidence threats",
            "Correlate threat intelligence with internal security events",
            "Use threat intelligence for proactive defense measures",
            "Share threat intelligence with trusted partners",
            "Implement machine learning for threat pattern detection"
        ])
        
        return recommendations


# Analyzer classes
class IPAnalyzer:
    """IP address threat analyzer"""
    
    def analyze(self, ip: str) -> Dict:
        """Analyze IP address for threats"""
        result = {
            'context': {},
            'tags': set(),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.0,
            'severity': None
        }
        
        try:
            # Basic IP analysis
            import ipaddress
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private IP
            if ip_obj.is_private:
                result['tags'].add('private')
                result['confidence_boost'] = -0.3
                return result
            
            # Check if reserved
            if ip_obj.is_reserved:
                result['tags'].add('reserved')
                result['confidence_boost'] = -0.2
                return result
            
            # Get geolocation (simplified)
            result['context']['ip_type'] = 'public'
            
            # Check common malicious patterns
            if ip.startswith(('192.0.2', '198.51.100', '203.0.113')):
                result['tags'].add('documentation')
                result['confidence_boost'] = -0.1
            
            # Add basic threat intelligence
            result['confidence_boost'] = 0.1
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip}: {e}")
        
        return result


class DomainAnalyzer:
    """Domain name threat analyzer"""
    
    def analyze(self, domain: str) -> Dict:
        """Analyze domain for threats"""
        result = {
            'context': {},
            'tags': set(),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.0,
            'severity': None
        }
        
        try:
            # Basic domain analysis
            result['context']['domain_length'] = len(domain)
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'malware', 'virus', 'trojan', 'botnet', 'c2',
                'phish', 'scam', 'fake', 'spam'
            ]
            
            domain_lower = domain.lower()
            for pattern in suspicious_patterns:
                if pattern in domain_lower:
                    result['tags'].add(f'suspicious_{pattern}')
                    result['confidence_boost'] += 0.2
            
            # Check for DGA patterns
            if self._is_dga_domain(domain):
                result['tags'].add('dga')
                result['confidence_boost'] += 0.3
                result['severity'] = 'high'
            
            # Check TLD
            tld = domain.split('.')[-1]
            if tld in ['tk', 'ml', 'ga', 'cf']:
                result['tags'].add('suspicious_tld')
                result['confidence_boost'] += 0.1
            
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")
        
        return result
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Simple DGA detection"""
        # Check for high entropy (random-looking) domains
        import string
        
        # Calculate character entropy
        chars = set(domain.lower())
        entropy = len(chars) / len(string.ascii_lowercase)
        
        return entropy > 0.8 and len(domain) > 10


class HashAnalyzer:
    """File hash threat analyzer"""
    
    def analyze(self, file_hash: str) -> Dict:
        """Analyze file hash for threats"""
        result = {
            'context': {},
            'tags': set(),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.0,
            'severity': None
        }
        
        try:
            # Determine hash type
            if len(file_hash) == 32:
                result['context']['hash_type'] = 'MD5'
            elif len(file_hash) == 40:
                result['context']['hash_type'] = 'SHA1'
            elif len(file_hash) == 64:
                result['context']['hash_type'] = 'SHA256'
            else:
                result['context']['hash_type'] = 'unknown'
            
            # Check for known malware hash patterns
            if file_hash.startswith(('0000', 'ffff', 'dead', 'beef')):
                result['tags'].add('suspicious_pattern')
                result['confidence_boost'] += 0.1
            
            # Would normally query VirusTotal and other services
            result['confidence_boost'] = 0.2
            
        except Exception as e:
            logger.error(f"Error analyzing hash {file_hash}: {e}")
        
        return result


class URLAnalyzer:
    """URL threat analyzer"""
    
    def analyze(self, url: str) -> Dict:
        """Analyze URL for threats"""
        result = {
            'context': {},
            'tags': set(),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.0,
            'severity': None
        }
        
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            result['context']['domain'] = parsed.netloc
            result['context']['path'] = parsed.path
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                'malware', 'virus', 'trojan', 'download', 'exe',
                'phish', 'login', 'signin', 'account', 'verify'
            ]
            
            url_lower = url.lower()
            for pattern in suspicious_patterns:
                if pattern in url_lower:
                    result['tags'].add(f'suspicious_{pattern}')
                    result['confidence_boost'] += 0.1
            
            # Check for shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
            if any(shortener in parsed.netloc for shortener in shorteners):
                result['tags'].add('url_shortener')
                result['confidence_boost'] += 0.2
            
            # Check for IP address in URL
            if self._is_ip_in_url(parsed.netloc):
                result['tags'].add('ip_url')
                result['confidence_boost'] += 0.3
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
        
        return result
    
    def _is_ip_in_url(self, netloc: str) -> bool:
        """Check if URL contains IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(netloc.split(':')[0])
            return True
        except:
            return False


class EmailAnalyzer:
    """Email address threat analyzer"""
    
    def analyze(self, email: str) -> Dict:
        """Analyze email address for threats"""
        result = {
            'context': {},
            'tags': set(),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.0,
            'severity': None
        }
        
        try:
            # Basic email analysis
            result['context']['domain'] = email.split('@')[1]
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'noreply', 'admin', 'support', 'security', 'update',
                'verify', 'confirm', 'suspicious', 'fake'
            ]
            
            email_lower = email.lower()
            for pattern in suspicious_patterns:
                if pattern in email_lower:
                    result['tags'].add(f'suspicious_{pattern}')
                    result['confidence_boost'] += 0.1
            
            # Check for disposable email domains
            disposable_domains = ['10minutemail', 'tempmail', 'guerrillamail']
            domain = email.split('@')[1].lower()
            if any(disposable in domain for disposable in disposable_domains):
                result['tags'].add('disposable_email')
                result['confidence_boost'] += 0.2
            
        except Exception as e:
            logger.error(f"Error analyzing email {email}: {e}")
        
        return result


class MalwareAnalyzer:
    """Malware threat analyzer"""
    
    def analyze(self, indicator: str) -> Dict:
        """Analyze malware-related indicators"""
        result = {
            'context': {},
            'tags': set(['malware']),
            'malware_families': set(),
            'actors': set(),
            'confidence_boost': 0.3,
            'severity': 'high'
        }
        
        try:
            # Would normally analyze malware samples
            result['malware_families'].add('unknown')
            result['confidence_boost'] = 0.3
            
        except Exception as e:
            logger.error(f"Error analyzing malware indicator {indicator}: {e}")
        
        return result


class CorrelationEngine:
    """Threat correlation engine"""
    
    def find_correlations(self, indicators: Dict[str, ThreatIndicator]) -> List[Dict]:
        """Find correlations between indicators"""
        correlations = []
        
        try:
            # Group indicators by various attributes
            ip_domains = defaultdict(list)
            malware_families = defaultdict(list)
            actors = defaultdict(list)
            
            for indicator in indicators.values():
                # Group IPs and domains from same source
                if indicator.indicator_type in ['ip', 'domain']:
                    ip_domains[indicator.source].append(indicator.indicator_id)
                
                # Group by malware families
                for family in indicator.malware_families:
                    malware_families[family].append(indicator.indicator_id)
                
                # Group by threat actors
                for actor in indicator.actors:
                    actors[actor].append(indicator.indicator_id)
            
            # Create correlations
            for source, indicator_ids in ip_domains.items():
                if len(indicator_ids) > 5:
                    correlations.append({
                        'type': 'source_cluster',
                        'indicator_ids': indicator_ids,
                        'confidence': 0.7,
                        'context': {'source': source, 'count': len(indicator_ids)}
                    })
            
            for family, indicator_ids in malware_families.items():
                if len(indicator_ids) > 3:
                    correlations.append({
                        'type': 'malware_family',
                        'indicator_ids': indicator_ids,
                        'confidence': 0.8,
                        'context': {'family': family, 'count': len(indicator_ids)}
                    })
            
            for actor, indicator_ids in actors.items():
                if len(indicator_ids) > 2:
                    correlations.append({
                        'type': 'threat_actor',
                        'indicator_ids': indicator_ids,
                        'confidence': 0.9,
                        'context': {'actor': actor, 'count': len(indicator_ids)}
                    })
        
        except Exception as e:
            logger.error(f"Error finding correlations: {e}")
        
        return correlations


class AnomalyDetector:
    """Threat anomaly detector"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.trained = False
    
    def detect_anomalies(self, features: List[List[float]]) -> List[Dict]:
        """Detect anomalies in threat features"""
        anomalies = []
        
        try:
            if len(features) < 10:
                return anomalies
            
            # Train model if not trained
            if not self.trained:
                self.model.fit(features)
                self.trained = True
            
            # Predict anomalies
            predictions = self.model.predict(features)
            
            for i, (feature, prediction) in enumerate(zip(features, predictions)):
                if prediction == -1:  # Anomaly
                    anomalies.append({
                        'feature_index': i,
                        'features': feature,
                        'score': self.model.decision_function([feature])[0],
                        'type': 'statistical_anomaly'
                    })
        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return anomalies
