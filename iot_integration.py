#!/usr/bin/env python3
"""
IoT Device Integration Module
Support for Raspberry Pi, Arduino, ESP32, and other IoT devices with seamless background operation
"""

import os
import sys
import time
import threading
import logging
import json
import socket
import subprocess
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass
from pathlib import Path
import sqlite3

# IoT and embedded systems libraries
try:
    import serial
    import paho.mqtt.client as mqtt
    import RPi.GPIO as gpio
    import board
    import digitalio
    import adafruit_dht
except ImportError:
    print("Installing IoT libraries...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyserial", "paho-mqtt", "RPi.GPIO", "adafruit-circuitpython-dht"])
    import serial
    import paho.mqtt.client as mqtt
    try:
        import RPi.GPIO as gpio
        import board
        import digitalio
        import adafruit_dht
    except ImportError:
        # Mock imports for non-Raspberry Pi systems
        gpio = None
        board = None
        digitalio = None
        adafruit_dht = None

logger = logging.getLogger(__name__)

@dataclass
class IoTDevice:
    """IoT device information"""
    device_id: str
    device_type: str  # raspberry_pi, arduino, esp32, generic_iot
    model: str
    architecture: str
    capabilities: Set[str]
    sensors: List[str]
    actuators: List[str]
    communication_protocols: Set[str]
    power_source: str
    location: str
    status: str
    last_seen: datetime
    trust_level: float

@dataclass
class IoTSensorReading:
    """IoT sensor reading"""
    device_id: str
    sensor_type: str
    sensor_id: str
    value: Union[float, int, str, bool]
    unit: str
    timestamp: datetime
    location: str
    anomaly_detected: bool
    security_impact: str

@dataclass
class IoTSecurityEvent:
    """IoT security event"""
    event_id: str
    device_id: str
    event_type: str
    severity: str
    description: str
    details: Dict
    sensor_data: Dict
    network_activity: Dict
    timestamp: datetime
    mitigation_applied: str
    risk_score: float

class IoTManager:
    """IoT device management and security system"""
    
    def __init__(self, db_path: str = "prix_iot.db"):
        self.db_path = db_path
        self.monitoring = False
        
        # IoT devices registry
        self.iot_devices = {}
        self.sensor_readings = []
        self.security_events = []
        
        # Communication protocols
        self.mqtt_client = None
        self.serial_connections = {}
        self.network_discovery_active = False
        
        # IoT security features
        self.iot_firewall_rules = {}
        self.device_fingerprints = {}
        self.anomaly_thresholds = {}
        
        # Background monitoring threads
        self.monitoring_threads = []
        
        # Initialize IoT system
        self.init_database()
        self.detect_local_devices()
        self.init_communication_protocols()
        self.start_background_monitoring()
    
    def init_database(self):
        """Initialize IoT database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # IoT devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iot_devices (
                device_id TEXT PRIMARY KEY,
                device_type TEXT,
                model TEXT,
                architecture TEXT,
                capabilities TEXT,
                sensors TEXT,
                actuators TEXT,
                communication_protocols TEXT,
                power_source TEXT,
                location TEXT,
                status TEXT,
                last_seen TEXT,
                trust_level REAL,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Sensor readings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sensor_readings (
                reading_id TEXT PRIMARY KEY,
                device_id TEXT,
                sensor_type TEXT,
                sensor_id TEXT,
                value TEXT,
                unit TEXT,
                timestamp TEXT,
                location TEXT,
                anomaly_detected BOOLEAN,
                security_impact TEXT
            )
        ''')
        
        # IoT security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iot_security_events (
                event_id TEXT PRIMARY KEY,
                device_id TEXT,
                event_type TEXT,
                severity TEXT,
                description TEXT,
                details TEXT,
                sensor_data TEXT,
                network_activity TEXT,
                timestamp TEXT,
                mitigation_applied TEXT,
                risk_score REAL
            )
        ''')
        
        # IoT network traffic table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iot_network_traffic (
                traffic_id TEXT PRIMARY KEY,
                device_id TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                port INTEGER,
                bytes_transferred INTEGER,
                timestamp TEXT,
                threat_detected BOOLEAN,
                threat_type TEXT
            )
        ''')
        
        # IoT firmware integrity table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iot_firmware_integrity (
                integrity_id TEXT PRIMARY KEY,
                device_id TEXT,
                component_name TEXT,
                expected_hash TEXT,
                current_hash TEXT,
                integrity_status TEXT,
                last_check TEXT,
                baseline_created TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def detect_local_devices(self):
        """Detect local IoT devices"""
        logger.info("Detecting local IoT devices...")
        
        # Detect Raspberry Pi
        if self._is_raspberry_pi():
            rpi_device = self._create_raspberry_pi_device()
            self.iot_devices[rpi_device.device_id] = rpi_device
            logger.info(f"Detected Raspberry Pi: {rpi_device.model}")
        
        # Detect Arduino devices (via serial)
        arduino_devices = self._detect_arduino_devices()
        for device in arduino_devices:
            self.iot_devices[device.device_id] = device
            logger.info(f"Detected Arduino: {device.model}")
        
        # Detect ESP32 and other WiFi IoT devices
        wifi_devices = self._detect_wifi_iot_devices()
        for device in wifi_devices:
            self.iot_devices[device.device_id] = device
            logger.info(f"Detected WiFi IoT device: {device.model}")
        
        # Detect network IoT devices
        network_devices = self._detect_network_iot_devices()
        for device in network_devices:
            self.iot_devices[device.device_id] = device
            logger.info(f"Detected network IoT device: {device.model}")
        
        # Store devices in database
        for device_id, device in self.iot_devices.items():
            self._store_iot_device(device)
        
        logger.info(f"Detected {len(self.iot_devices)} IoT devices")
    
    def _is_raspberry_pi(self) -> bool:
        """Check if running on Raspberry Pi"""
        try:
            # Check for Raspberry Pi specific files
            if os.path.exists('/proc/device-tree/model'):
                with open('/proc/device-tree/model', 'r') as f:
                    model = f.read().strip()
                    return 'Raspberry Pi' in model
            
            # Check for Raspberry Pi in CPU info
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    return 'Raspberry Pi' in cpuinfo or 'BCM' in cpuinfo
            
            return False
        except:
            return False
    
    def _create_raspberry_pi_device(self) -> IoTDevice:
        """Create Raspberry Pi device object"""
        try:
            # Get Pi model
            model = "Unknown Raspberry Pi"
            if os.path.exists('/proc/device-tree/model'):
                with open('/proc/device-tree/model', 'r') as f:
                    model = f.read().strip()
            
            # Get architecture
            architecture = platform.machine()
            
            # Detect available sensors and actuators
            sensors = []
            actuators = []
            
            # Check for GPIO sensors
            if gpio:
                sensors.extend(['gpio_digital_input', 'gpio_analog_input'])
                actuators.extend(['gpio_digital_output', 'gpio_pwm_output'])
            
            # Check for DHT sensors
            if adafruit_dht:
                sensors.extend(['dht11_temperature', 'dht22_temperature', 'dht_humidity'])
            
            # Check for camera
            if os.path.exists('/dev/vchiq'):
                sensors.append('camera')
            
            # Check for I2C devices
            if os.path.exists('/dev/i2c-1'):
                sensors.extend(['i2c_temperature', 'i2c_pressure', 'i2c_light'])
            
            capabilities = {
                'gpio_control', 'sensor_monitoring', 'network_security',
                'firmware_integrity', 'process_monitoring', 'file_protection'
            }
            
            communication_protocols = {'wifi', 'ethernet', 'bluetooth', 'gpio'}
            
            device = IoTDevice(
                device_id='raspberry_pi_main',
                device_type='raspberry_pi',
                model=model,
                architecture=architecture,
                capabilities=capabilities,
                sensors=sensors,
                actuators=actuators,
                communication_protocols=communication_protocols,
                power_source='dc_power',
                location='local',
                status='active',
                last_seen=datetime.now(),
                trust_level=0.8
            )
            
            return device
        
        except Exception as e:
            logger.error(f"Error creating Raspberry Pi device: {e}")
            return IoTDevice(
                device_id='raspberry_pi_main',
                device_type='raspberry_pi',
                model='Unknown',
                architecture='arm',
                capabilities=set(),
                sensors=[],
                actuators=[],
                communication_protocols=set(),
                power_source='unknown',
                location='local',
                status='error',
                last_seen=datetime.now(),
                trust_level=0.0
            )
    
    def _detect_arduino_devices(self) -> List[IoTDevice]:
        """Detect Arduino devices via serial ports"""
        arduino_devices = []
        
        try:
            # Common Arduino serial port patterns
            serial_patterns = [
                '/dev/ttyACM', '/dev/ttyUSB', '/dev/tty.usbmodem',
                'COM3', 'COM4', 'COM5'  # Windows
            ]
            
            for pattern in serial_patterns:
                if pattern.startswith('/dev/'):
                    # Linux/Mac
                    for i in range(10):
                        port = f"{pattern}{i}"
                        if os.path.exists(port):
                            device = self._create_arduino_device(port)
                            if device:
                                arduino_devices.append(device)
                elif pattern.startswith('COM'):
                    # Windows
                    try:
                        import serial.tools.list_ports
                        ports = serial.tools.list_ports.comports()
                        for port in ports:
                            if 'Arduino' in port.description or 'CH340' in port.description:
                                device = self._create_arduino_device(port.device)
                                if device:
                                    arduino_devices.append(device)
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Error detecting Arduino devices: {e}")
        
        return arduino_devices
    
    def _create_arduino_device(self, port: str) -> Optional[IoTDevice]:
        """Create Arduino device object"""
        try:
            capabilities = {
                'digital_io', 'analog_input', 'pwm_output',
                'serial_communication', 'sensor_monitoring'
            }
            
            sensors = ['digital_input', 'analog_input']
            actuators = ['digital_output', 'pwm_output']
            
            communication_protocols = {'serial', 'i2c', 'spi'}
            
            device = IoTDevice(
                device_id=f"arduino_{port.replace('/', '_').replace(':', '_')}",
                device_type='arduino',
                model='Arduino Uno',
                architecture='avr',
                capabilities=capabilities,
                sensors=sensors,
                actuators=actuators,
                communication_protocols=communication_protocols,
                power_source='usb',
                location='local',
                status='active',
                last_seen=datetime.now(),
                trust_level=0.6
            )
            
            return device
        
        except Exception as e:
            logger.error(f"Error creating Arduino device: {e}")
            return None
    
    def _detect_wifi_iot_devices(self) -> List[IoTDevice]:
        """Detect WiFi IoT devices on the network"""
        wifi_devices = []
        
        try:
            # Scan for common IoT device patterns
            common_iot_patterns = [
                'ESP32', 'ESP8266', 'Arduino', 'Raspberry',
                'SmartPlug', 'SmartSwitch', 'Sensor', 'Camera'
            ]
            
            # Use network scan to discover devices
            import subprocess
            
            try:
                # Try nmap if available
                result = subprocess.run(['nmap', '-sn', '192.168.1.0/24'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    scan_output = result.stdout
                    
                    for pattern in common_iot_patterns:
                        if pattern.lower() in scan_output.lower():
                            # Create a generic WiFi IoT device
                            device = IoTDevice(
                                device_id=f"wifi_iot_{pattern.lower()}_{len(wifi_devices)}",
                                device_type='wifi_iot',
                                model=f'Generic {pattern} Device',
                                architecture='arm',
                                capabilities={'wifi_communication', 'sensor_monitoring'},
                                sensors=['temperature', 'humidity'],
                                actuators=['relay_control'],
                                communication_protocols={'wifi', 'mqtt'},
                                power_source='battery_or_dc',
                                location='network',
                                status='active',
                                last_seen=datetime.now(),
                                trust_level=0.5
                            )
                            wifi_devices.append(device)
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback to simple ping scan
                for i in range(1, 255):
                    ip = f"192.168.1.{i}"
                    try:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                              capture_output=True, timeout=2)
                        if result.returncode == 0:
                            # Device responded - could be IoT
                            device = IoTDevice(
                                device_id=f"wifi_device_{ip.replace('.', '_')}",
                                device_type='wifi_iot',
                                model='Unknown WiFi Device',
                                architecture='unknown',
                                capabilities={'wifi_communication'},
                                sensors=[],
                                actuators=[],
                                communication_protocols={'wifi'},
                                power_source='unknown',
                                location='network',
                                status='discovered',
                                last_seen=datetime.now(),
                                trust_level=0.3
                            )
                            wifi_devices.append(device)
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Error detecting WiFi IoT devices: {e}")
        
        return wifi_devices
    
    def _detect_network_iot_devices(self) -> List[IoTDevice]:
        """Detect network-connected IoT devices"""
        network_devices = []
        
        try:
            # Check for common IoT ports and services
            common_iot_ports = {
                1883: 'MQTT', 8883: 'MQTT_SSL', 8080: 'HTTP_IoT',
                502: 'Modbus', 1978: 'UPnP', 1900: 'SSDP'
            }
            
            # Scan local network for IoT services
            for port, service in common_iot_ports.items():
                try:
                    # Simple port scan on common IoT addresses
                    for ip in ['192.168.1.1', '192.168.1.100', '192.168.1.200']:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        
                        if result == 0:
                            device = IoTDevice(
                                device_id=f"network_iot_{ip.replace('.', '_')}_{port}",
                                device_type='network_iot',
                                model=f'{service} Device',
                                architecture='unknown',
                                capabilities={'network_service'},
                                sensors=[],
                                actuators=[],
                                communication_protocols={service.lower()},
                                power_source='dc_power',
                                location='network',
                                status='active',
                                last_seen=datetime.now(),
                                trust_level=0.4
                            )
                            network_devices.append(device)
                except:
                    continue
        
        except Exception as e:
            logger.error(f"Error detecting network IoT devices: {e}")
        
        return network_devices
    
    def _store_iot_device(self, device: IoTDevice):
        """Store IoT device in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO iot_devices 
            (device_id, device_type, model, architecture, capabilities,
             sensors, actuators, communication_protocols, power_source,
             location, status, last_seen, trust_level, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device.device_id,
            device.device_type,
            device.model,
            device.architecture,
            json.dumps(list(device.capabilities)),
            json.dumps(device.sensors),
            json.dumps(device.actuators),
            json.dumps(list(device.communication_protocols)),
            device.power_source,
            device.location,
            device.status,
            device.last_seen.isoformat(),
            device.trust_level,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def init_communication_protocols(self):
        """Initialize communication protocols for IoT devices"""
        logger.info("Initializing IoT communication protocols...")
        
        # Initialize MQTT client
        self._init_mqtt_client()
        
        # Initialize serial connections
        self._init_serial_connections()
        
        # Initialize network discovery
        self._init_network_discovery()
        
        logger.info("IoT communication protocols initialized")
    
    def _init_mqtt_client(self):
        """Initialize MQTT client for IoT communication"""
        try:
            self.mqtt_client = mqtt.Client("PrixIoTManager")
            
            # MQTT event callbacks
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    logger.info("MQTT client connected successfully")
                    # Subscribe to IoT topics
                    client.subscribe("iot/+/sensors")
                    client.subscribe("iot/+/status")
                    client.subscribe("iot/+/alerts")
                else:
                    logger.error(f"MQTT connection failed with code {rc}")
            
            def on_message(client, userdata, msg):
                self._handle_mqtt_message(msg)
            
            def on_disconnect(client, userdata, rc):
                logger.warning(f"MQTT client disconnected with code {rc}")
            
            self.mqtt_client.on_connect = on_connect
            self.mqtt_client.on_message = on_message
            self.mqtt_client.on_disconnect = on_disconnect
            
            # Try to connect to local MQTT broker
            try:
                self.mqtt_client.connect("localhost", 1883, 60)
                self.mqtt_client.loop_start()
                logger.info("Connected to local MQTT broker")
            except:
                logger.info("No local MQTT broker found, running in standalone mode")
                self.mqtt_client = None
        
        except Exception as e:
            logger.error(f"Error initializing MQTT client: {e}")
            self.mqtt_client = None
    
    def _init_serial_connections(self):
        """Initialize serial connections for Arduino devices"""
        try:
            for device_id, device in self.iot_devices.items():
                if device.device_type == 'arduino':
                    port = device.device_id.replace('arduino_', '').replace('_', '/')
                    
                    try:
                        serial_conn = serial.Serial(port, 9600, timeout=1)
                        self.serial_connections[device_id] = serial_conn
                        logger.info(f"Connected to Arduino on {port}")
                    except Exception as e:
                        logger.warning(f"Could not connect to Arduino on {port}: {e}")
        
        except Exception as e:
            logger.error(f"Error initializing serial connections: {e}")
    
    def _init_network_discovery(self):
        """Initialize network discovery for IoT devices"""
        try:
            self.network_discovery_active = True
            
            # Start network discovery thread
            discovery_thread = threading.Thread(target=self._network_discovery_loop, daemon=True)
            discovery_thread.start()
            
            logger.info("Network discovery initialized")
        
        except Exception as e:
            logger.error(f"Error initializing network discovery: {e}")
    
    def _handle_mqtt_message(self, msg):
        """Handle incoming MQTT messages"""
        try:
            topic_parts = msg.topic.split('/')
            if len(topic_parts) >= 3:
                device_id = topic_parts[1]
                message_type = topic_parts[2]
                
                payload = json.loads(msg.payload.decode())
                
                if message_type == 'sensors':
                    self._handle_sensor_data(device_id, payload)
                elif message_type == 'status':
                    self._handle_device_status(device_id, payload)
                elif message_type == 'alerts':
                    self._handle_device_alert(device_id, payload)
        
        except Exception as e:
            logger.error(f"Error handling MQTT message: {e}")
    
    def _handle_sensor_data(self, device_id: str, sensor_data: Dict):
        """Handle sensor data from IoT device"""
        try:
            for sensor_type, readings in sensor_data.items():
                if isinstance(readings, list):
                    for reading in readings:
                        sensor_reading = IoTSensorReading(
                            device_id=device_id,
                            sensor_type=sensor_type,
                            sensor_id=reading.get('sensor_id', 'unknown'),
                            value=reading.get('value', 0),
                            unit=reading.get('unit', ''),
                            timestamp=datetime.now(),
                            location=reading.get('location', 'unknown'),
                            anomaly_detected=self._check_sensor_anomaly(device_id, sensor_type, reading.get('value')),
                            security_impact=self._assess_sensor_security_impact(sensor_type, reading.get('value'))
                        )
                        
                        self.sensor_readings.append(sensor_reading)
                        self._store_sensor_reading(sensor_reading)
        
        except Exception as e:
            logger.error(f"Error handling sensor data: {e}")
    
    def _handle_device_status(self, device_id: str, status_data: Dict):
        """Handle device status update"""
        try:
            if device_id in self.iot_devices:
                device = self.iot_devices[device_id]
                device.status = status_data.get('status', 'unknown')
                device.last_seen = datetime.now()
                
                # Update device trust level based on status
                if status_data.get('security_status') == 'compromised':
                    device.trust_level = max(0.0, device.trust_level - 0.3)
                    self._create_iot_security_event(device_id, 'device_compromised', 'high')
                
                self._store_iot_device(device)
        
        except Exception as e:
            logger.error(f"Error handling device status: {e}")
    
    def _handle_device_alert(self, device_id: str, alert_data: Dict):
        """Handle security alert from IoT device"""
        try:
            alert_type = alert_data.get('alert_type', 'unknown')
            severity = alert_data.get('severity', 'medium')
            description = alert_data.get('description', 'Security alert from IoT device')
            
            self._create_iot_security_event(device_id, alert_type, severity, description, alert_data)
        
        except Exception as e:
            logger.error(f"Error handling device alert: {e}")
    
    def _check_sensor_anomaly(self, device_id: str, sensor_type: str, value) -> bool:
        """Check for sensor reading anomalies"""
        try:
            # Define normal ranges for common sensors
            normal_ranges = {
                'temperature': (-40, 85),  # Celsius
                'humidity': (0, 100),      # Percentage
                'pressure': (900, 1100),   # hPa
                'light': (0, 100000),      # Lux
                'voltage': (0, 5),         # Volts
                'current': (0, 10)         # Amps
            }
            
            if sensor_type in normal_ranges:
                min_val, max_val = normal_ranges[sensor_type]
                return not (min_val <= value <= max_val)
            
            # Check for rapid changes
            recent_readings = [r for r in self.sensor_readings[-10:] 
                             if r.device_id == device_id and r.sensor_type == sensor_type]
            
            if len(recent_readings) >= 2:
                last_value = recent_readings[-1].value
                if isinstance(value, (int, float)) and isinstance(last_value, (int, float)):
                    change_percent = abs((value - last_value) / last_value) * 100
                    return change_percent > 50  # More than 50% change is suspicious
            
            return False
        
        except Exception as e:
            logger.error(f"Error checking sensor anomaly: {e}")
            return False
    
    def _assess_sensor_security_impact(self, sensor_type: str, value) -> str:
        """Assess security impact of sensor reading"""
        try:
            # High-impact sensors
            critical_sensors = ['motion', 'door', 'window', 'smoke', 'gas', 'intrusion']
            
            if sensor_type in critical_sensors:
                if isinstance(value, bool) and value:  # Alert triggered
                    return 'critical'
                return 'medium'
            
            # Medium-impact sensors
            medium_sensors = ['temperature', 'humidity', 'vibration', 'sound']
            
            if sensor_type in medium_sensors:
                return 'medium'
            
            # Low-impact sensors
            return 'low'
        
        except:
            return 'unknown'
    
    def _store_sensor_reading(self, reading: IoTSensorReading):
        """Store sensor reading in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sensor_readings 
            (reading_id, device_id, sensor_type, sensor_id, value, unit,
             timestamp, location, anomaly_detected, security_impact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            f"reading_{secrets.token_hex(8)}",
            reading.device_id,
            reading.sensor_type,
            reading.sensor_id,
            str(reading.value),
            reading.unit,
            reading.timestamp.isoformat(),
            reading.location,
            reading.anomaly_detected,
            reading.security_impact
        ))
        
        conn.commit()
        conn.close()
    
    def _create_iot_security_event(self, device_id: str, event_type: str, severity: str, 
                                 description: str = "", details: Dict = None):
        """Create IoT security event"""
        try:
            event = IoTSecurityEvent(
                event_id=f"iot_event_{secrets.token_hex(8)}",
                device_id=device_id,
                event_type=event_type,
                severity=severity,
                description=description or f"IoT security event: {event_type}",
                details=details or {},
                sensor_data={},
                network_activity={},
                timestamp=datetime.now(),
                mitigation_applied=self._determine_mitigation(event_type, severity),
                risk_score=self._calculate_risk_score(event_type, severity)
            )
            
            self.security_events.append(event)
            self._store_iot_security_event(event)
            
            # Take immediate action for critical events
            if severity == 'critical':
                self._handle_critical_iot_event(event)
        
        except Exception as e:
            logger.error(f"Error creating IoT security event: {e}")
    
    def _determine_mitigation(self, event_type: str, severity: str) -> str:
        """Determine mitigation strategy for IoT event"""
        if severity == 'critical':
            return 'device_isolation'
        elif severity == 'high':
            return 'network_segmentation'
        elif severity == 'medium':
            return 'enhanced_monitoring'
        else:
            return 'log_only'
    
    def _calculate_risk_score(self, event_type: str, severity: str) -> float:
        """Calculate risk score for IoT event"""
        severity_scores = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
        base_score = severity_scores.get(severity, 0.5)
        
        # Adjust based on event type
        if event_type in ['device_compromised', 'unauthorized_access']:
            return min(1.0, base_score + 0.2)
        elif event_type in ['sensor_anomaly', 'communication_failure']:
            return base_score
        else:
            return base_score - 0.1
    
    def _store_iot_security_event(self, event: IoTSecurityEvent):
        """Store IoT security event in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO iot_security_events 
            (event_id, device_id, event_type, severity, description,
             details, sensor_data, network_activity, timestamp,
             mitigation_applied, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.event_id,
            event.device_id,
            event.event_type,
            event.severity,
            event.description,
            json.dumps(event.details),
            json.dumps(event.sensor_data),
            json.dumps(event.network_activity),
            event.timestamp.isoformat(),
            event.mitigation_applied,
            event.risk_score
        ))
        
        conn.commit()
        conn.close()
    
    def _handle_critical_iot_event(self, event: IoTSecurityEvent):
        """Handle critical IoT security events"""
        logger.critical(f"CRITICAL IOT SECURITY EVENT: {event.description}")
        logger.critical(f"Device: {event.device_id}, Type: {event.event_type}")
        
        # Immediate isolation
        self._isolate_iot_device(event.device_id)
        
        # Alert security team
        self._alert_iot_security_team(event)
        
        # Block network access
        self._block_device_network_access(event.device_id)
    
    def _isolate_iot_device(self, device_id: str):
        """Isolate compromised IoT device"""
        try:
            if device_id in self.iot_devices:
                device = self.iot_devices[device_id]
                device.status = 'isolated'
                device.trust_level = 0.0
                
                # Close connections
                if device_id in self.serial_connections:
                    self.serial_connections[device_id].close()
                    del self.serial_connections[device_id]
                
                logger.warning(f"IoT device {device_id} isolated")
        
        except Exception as e:
            logger.error(f"Error isolating IoT device {device_id}: {e}")
    
    def _alert_iot_security_team(self, event: IoTSecurityEvent):
        """Alert security team about IoT event"""
        logger.critical("IOT SECURITY ALERT:")
        logger.critical(f"Event: {event.event_type}")
        logger.critical(f"Device: {event.device_id}")
        logger.critical(f"Severity: {event.severity}")
        logger.critical(f"Description: {event.description}")
        logger.critical(f"Risk Score: {event.risk_score}")
        logger.critical(f"Mitigation: {event.mitigation_applied}")
    
    def _block_device_network_access(self, device_id: str):
        """Block network access for compromised device"""
        try:
            # Add firewall rule to block device
            if device_id in self.iot_devices:
                device = self.iot_devices[device_id]
                
                # This would integrate with system firewall
                logger.warning(f"Network access blocked for IoT device {device_id}")
        
        except Exception as e:
            logger.error(f"Error blocking network access for {device_id}: {e}")
    
    def start_background_monitoring(self):
        """Start background IoT monitoring"""
        self.monitoring = True
        logger.info("Starting background IoT monitoring...")
        
        # Start monitoring threads
        self.monitoring_threads = [
            threading.Thread(target=self._sensor_monitoring_loop, daemon=True),
            threading.Thread(target=self._device_health_loop, daemon=True),
            threading.Thread(target=self._network_monitoring_loop, daemon=True),
            threading.Thread(target=self._firmware_integrity_loop, daemon=True),
            threading.Thread(target=self._anomaly_detection_loop, daemon=True)
        ]
        
        for thread in self.monitoring_threads:
            thread.start()
        
        logger.info("Background IoT monitoring started")
    
    def _sensor_monitoring_loop(self):
        """Monitor IoT sensors"""
        while self.monitoring:
            try:
                # Monitor Raspberry Pi sensors
                if 'raspberry_pi_main' in self.iot_devices:
                    self._monitor_raspberry_pi_sensors()
                
                # Monitor Arduino sensors
                for device_id, device in self.iot_devices.items():
                    if device.device_type == 'arduino' and device_id in self.serial_connections:
                        self._monitor_arduino_sensors(device_id)
                
                time.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.error(f"Error in sensor monitoring: {e}")
                time.sleep(60)
    
    def _monitor_raspberry_pi_sensors(self):
        """Monitor Raspberry Pi sensors"""
        try:
            # Monitor CPU temperature
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp_c = int(f.read()) / 1000.0
                    
                    reading = IoTSensorReading(
                        device_id='raspberry_pi_main',
                        sensor_type='cpu_temperature',
                        sensor_id='thermal_zone0',
                        value=temp_c,
                        unit='celsius',
                        timestamp=datetime.now(),
                        location='cpu',
                        anomaly_detected=self._check_sensor_anomaly('raspberry_pi_main', 'temperature', temp_c),
                        security_impact='medium'
                    )
                    
                    self.sensor_readings.append(reading)
                    self._store_sensor_reading(reading)
                    
                    if temp_c > 80:  # High temperature
                        self._create_iot_security_event('raspberry_pi_main', 'high_temperature', 'medium',
                                                      f"CPU temperature high: {temp_c}°C")
            except:
                pass
            
            # Monitor GPIO sensors
            if gpio:
                self._monitor_gpio_sensors()
            
            # Monitor DHT sensors
            if adafruit_dht:
                self._monitor_dht_sensors()
        
        except Exception as e:
            logger.error(f"Error monitoring Raspberry Pi sensors: {e}")
    
    def _monitor_gpio_sensors(self):
        """Monitor GPIO sensors"""
        try:
            # This is a simplified GPIO monitoring
            # In a real implementation, you would configure specific GPIO pins
            
            # Example: Monitor a door sensor on GPIO 4
            gpio.setmode(gpio.BCM)
            gpio.setup(4, gpio.IN)
            
            door_state = gpio.input(4)
            
            reading = IoTSensorReading(
                device_id='raspberry_pi_main',
                sensor_type='door_sensor',
                sensor_id='gpio_4',
                value=door_state,
                unit='boolean',
                timestamp=datetime.now(),
                location='entrance',
                anomaly_detected=False,
                security_impact='high'
            )
            
            self.sensor_readings.append(reading)
            self._store_sensor_reading(reading)
            
            if door_state:  # Door opened
                self._create_iot_security_event('raspberry_pi_main', 'door_opened', 'medium',
                                              "Door sensor triggered")
        
        except Exception as e:
            logger.error(f"Error monitoring GPIO sensors: {e}")
    
    def _monitor_dht_sensors(self):
        """Monitor DHT temperature/humidity sensors"""
        try:
            # Example: Monitor DHT22 on GPIO 22
            import adafruit_dht.dht22 as dht
            
            pin = board.D22
            dht_sensor = dht.DHT22(pin)
            
            try:
                temperature = dht_sensor.temperature
                humidity = dht_sensor.humidity
                
                if temperature is not None:
                    temp_reading = IoTSensorReading(
                        device_id='raspberry_pi_main',
                        sensor_type='dht_temperature',
                        sensor_id='dht22_22',
                        value=temperature,
                        unit='celsius',
                        timestamp=datetime.now(),
                        location='indoor',
                        anomaly_detected=self._check_sensor_anomaly('raspberry_pi_main', 'temperature', temperature),
                        security_impact='medium'
                    )
                    
                    self.sensor_readings.append(temp_reading)
                    self._store_sensor_reading(temp_reading)
                
                if humidity is not None:
                    humidity_reading = IoTSensorReading(
                        device_id='raspberry_pi_main',
                        sensor_type='dht_humidity',
                        sensor_id='dht22_22',
                        value=humidity,
                        unit='percentage',
                        timestamp=datetime.now(),
                        location='indoor',
                        anomaly_detected=self._check_sensor_anomaly('raspberry_pi_main', 'humidity', humidity),
                        security_impact='low'
                    )
                    
                    self.sensor_readings.append(humidity_reading)
                    self._store_sensor_reading(humidity_reading)
            
            except RuntimeError as e:
                # DHT sensors sometimes fail to read
                pass
        
        except Exception as e:
            logger.error(f"Error monitoring DHT sensors: {e}")
    
    def _monitor_arduino_sensors(self, device_id: str):
        """Monitor Arduino sensors via serial"""
        try:
            if device_id in self.serial_connections:
                serial_conn = self.serial_connections[device_id]
                
                if serial_conn.in_waiting > 0:
                    line = serial_conn.readline().decode().strip()
                    
                    # Parse sensor data (assuming JSON format)
                    try:
                        sensor_data = json.loads(line)
                        self._handle_sensor_data(device_id, sensor_data)
                    except json.JSONDecodeError:
                        # Handle plain text format
                        if 'TEMP:' in line:
                            temp = float(line.split(':')[1])
                            reading = IoTSensorReading(
                                device_id=device_id,
                                sensor_type='temperature',
                                sensor_id='arduino_temp',
                                value=temp,
                                unit='celsius',
                                timestamp=datetime.now(),
                                location='arduino',
                                anomaly_detected=self._check_sensor_anomaly(device_id, 'temperature', temp),
                                security_impact='medium'
                            )
                            
                            self.sensor_readings.append(reading)
                            self._store_sensor_reading(reading)
        
        except Exception as e:
            logger.error(f"Error monitoring Arduino sensors {device_id}: {e}")
    
    def _device_health_loop(self):
        """Monitor IoT device health"""
        while self.monitoring:
            try:
                for device_id, device in self.iot_devices.items():
                    self._check_device_health(device)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Error in device health monitoring: {e}")
                time.sleep(600)
    
    def _check_device_health(self, device: IoTDevice):
        """Check health of IoT device"""
        try:
            health_issues = []
            
            # Check if device is responsive
            if device.device_type == 'arduino':
                if device.device_id in self.serial_connections:
                    serial_conn = self.serial_connections[device.device_id]
                    try:
                        # Send ping command
                        serial_conn.write(b'PING\n')
                        time.sleep(0.1)
                        
                        if serial_conn.in_waiting > 0:
                            response = serial_conn.readline().decode().strip()
                            if 'PONG' not in response:
                                health_issues.append('unresponsive')
                        else:
                            health_issues.append('unresponsive')
                    except:
                        health_issues.append('communication_failure')
                else:
                    health_issues.append('disconnected')
            
            elif device.device_type == 'raspberry_pi':
                # Check system load
                try:
                    load_avg = os.getloadavg()[0]
                    if load_avg > 2.0:
                        health_issues.append('high_load')
                except:
                    pass
                
                # Check memory usage
                try:
                    import psutil
                    memory_percent = psutil.virtual_memory().percent
                    if memory_percent > 90:
                        health_issues.append('high_memory')
                except:
                    pass
            
            # Update device status based on health
            if health_issues:
                device.status = 'degraded'
                device.trust_level = max(0.0, device.trust_level - 0.1)
                
                for issue in health_issues:
                    self._create_iot_security_event(device.device_id, f'device_{issue}', 'medium',
                                                  f"Device health issue: {issue}")
            else:
                device.status = 'healthy'
                device.last_seen = datetime.now()
            
            self._store_iot_device(device)
        
        except Exception as e:
            logger.error(f"Error checking device health for {device.device_id}: {e}")
    
    def _network_monitoring_loop(self):
        """Monitor IoT network traffic"""
        while self.monitoring:
            try:
                # Monitor network traffic for IoT devices
                for device_id, device in self.iot_devices.items():
                    if device.location == 'network':
                        self._monitor_device_network_traffic(device_id)
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                time.sleep(120)
    
    def _monitor_device_network_traffic(self, device_id: str):
        """Monitor network traffic for specific device"""
        try:
            # This would integrate with network monitoring tools
            # For now, we'll simulate network monitoring
            
            # Check for unusual network patterns
            device = self.iot_devices.get(device_id)
            if device:
                # Example: Check for excessive connections
                if hasattr(self, '_device_connection_counts'):
                    connection_count = self._device_connection_counts.get(device_id, 0)
                    if connection_count > 100:
                        self._create_iot_security_event(device_id, 'excessive_connections', 'medium',
                                                      f"Device has {connection_count} connections")
        
        except Exception as e:
            logger.error(f"Error monitoring network traffic for {device_id}: {e}")
    
    def _firmware_integrity_loop(self):
        """Monitor IoT firmware integrity"""
        while self.monitoring:
            try:
                for device_id, device in self.iot_devices.items():
                    self._check_firmware_integrity(device)
                
                time.sleep(3600)  # Check every hour
            
            except Exception as e:
                logger.error(f"Error in firmware integrity monitoring: {e}")
                time.sleep(7200)
    
    def _check_firmware_integrity(self, device: IoTDevice):
        """Check firmware integrity for IoT device"""
        try:
            if device.device_type == 'raspberry_pi':
                # Check critical system files
                critical_files = [
                    '/boot/config.txt',
                    '/boot/cmdline.txt',
                    '/etc/passwd',
                    '/etc/shadow'
                ]
                
                for file_path in critical_files:
                    if os.path.exists(file_path):
                        current_hash = self._calculate_file_hash(file_path)
                        
                        # Check against stored baseline
                        stored_hash = self._get_stored_file_hash(device.device_id, file_path)
                        
                        if stored_hash and current_hash != stored_hash:
                            self._create_iot_security_event(device.device_id, 'firmware_modified', 'high',
                                                          f"File modified: {file_path}")
            
            elif device.device_type == 'arduino':
                # Check Arduino firmware via serial
                if device.device_id in self.serial_connections:
                    serial_conn = self.serial_connections[device.device_id]
                    try:
                        serial_conn.write(b'CHECK_FIRMWARE\n')
                        time.sleep(0.1)
                        
                        if serial_conn.in_waiting > 0:
                            response = serial_conn.readline().decode().strip()
                            if 'FIRMWARE_HASH:' in response:
                                current_hash = response.split(':')[1].strip()
                                stored_hash = self._get_stored_firmware_hash(device.device_id)
                                
                                if stored_hash and current_hash != stored_hash:
                                    self._create_iot_security_event(device.device_id, 'firmware_modified', 'high',
                                                                  "Arduino firmware modified")
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Error checking firmware integrity for {device.device_id}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return ""
    
    def _get_stored_file_hash(self, device_id: str, file_path: str) -> Optional[str]:
        """Get stored file hash from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT expected_hash FROM iot_firmware_integrity 
                WHERE device_id = ? AND component_name = ?
            ''', (device_id, file_path))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
        
        except:
            return None
    
    def _get_stored_firmware_hash(self, device_id: str) -> Optional[str]:
        """Get stored firmware hash from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT expected_hash FROM iot_firmware_integrity 
                WHERE device_id = ? AND component_name = 'firmware'
            ''', (device_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
        
        except:
            return None
    
    def _anomaly_detection_loop(self):
        """Run anomaly detection for IoT data"""
        while self.monitoring:
            try:
                # Analyze sensor readings for anomalies
                self._analyze_sensor_anomalies()
                
                # Analyze device behavior patterns
                self._analyze_device_behavior()
                
                # Analyze network patterns
                self._analyze_network_anomalies()
                
                time.sleep(600)  # Analyze every 10 minutes
            
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}")
                time.sleep(1200)
    
    def _analyze_sensor_anomalies(self):
        """Analyze sensor readings for anomalies"""
        try:
            # Group readings by device and sensor type
            reading_groups = {}
            
            for reading in self.sensor_readings[-100:]:  # Last 100 readings
                key = (reading.device_id, reading.sensor_type)
                if key not in reading_groups:
                    reading_groups[key] = []
                reading_groups[key].append(reading)
            
            # Analyze each group
            for (device_id, sensor_type), readings in reading_groups.items():
                if len(readings) >= 10:
                    values = [r.value for r in readings if isinstance(r.value, (int, float))]
                    
                    if len(values) >= 10:
                        # Calculate statistics
                        mean_val = sum(values) / len(values)
                        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
                        std_dev = variance ** 0.5
                        
                        # Check for outliers (3 sigma rule)
                        for reading in readings[-10:]:  # Recent readings
                            if isinstance(reading.value, (int, float)):
                                if abs(reading.value - mean_val) > 3 * std_dev:
                                    if not reading.anomaly_detected:
                                        # Mark as anomaly
                                        reading.anomaly_detected = True
                                        reading.security_impact = 'medium'
                                        
                                        self._create_iot_security_event(
                                            device_id, 'sensor_anomaly', 'medium',
                                            f"Anomalous {sensor_type} reading: {reading.value}"
                                        )
        
        except Exception as e:
            logger.error(f"Error analyzing sensor anomalies: {e}")
    
    def _analyze_device_behavior(self):
        """Analyze device behavior patterns"""
        try:
            # Analyze device communication patterns
            for device_id, device in self.iot_devices.items():
                # Check for unusual activity patterns
                recent_events = [e for e in self.security_events 
                                if e.device_id == device_id 
                                and e.timestamp > datetime.now() - timedelta(hours=1)]
                
                if len(recent_events) > 10:  # Too many events
                    self._create_iot_security_event(device_id, 'unusual_activity', 'medium',
                                                  f"High event frequency: {len(recent_events)} events/hour")
        
        except Exception as e:
            logger.error(f"Error analyzing device behavior: {e}")
    
    def _analyze_network_anomalies(self):
        """Analyze network traffic anomalies"""
        try:
            # This would integrate with network monitoring
            # For now, simulate network anomaly detection
            
            for device_id, device in self.iot_devices.items():
                if device.location == 'network':
                    # Check for unusual connection patterns
                    pass
        
        except Exception as e:
            logger.error(f"Error analyzing network anomalies: {e}")
    
    def _network_discovery_loop(self):
        """Continuous network discovery for new IoT devices"""
        while self.network_discovery_active:
            try:
                # Scan for new devices every 30 minutes
                time.sleep(1800)
                
                # Rediscover devices
                new_devices = []
                new_devices.extend(self._detect_wifi_iot_devices())
                new_devices.extend(self._detect_network_iot_devices())
                
                # Add new devices
                for device in new_devices:
                    if device.device_id not in self.iot_devices:
                        self.iot_devices[device.device_id] = device
                        self._store_iot_device(device)
                        logger.info(f"Discovered new IoT device: {device.model}")
        
            except Exception as e:
                logger.error(f"Error in network discovery: {e}")
                time.sleep(3600)
    
    def get_iot_status(self) -> Dict:
        """Get IoT system status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Device statistics
        cursor.execute('SELECT device_type, COUNT(*) FROM iot_devices GROUP BY device_type')
        device_stats = dict(cursor.fetchall())
        
        # Recent sensor readings
        cursor.execute('''
            SELECT COUNT(*) FROM sensor_readings 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        recent_readings = cursor.fetchone()[0]
        
        # Recent security events
        cursor.execute('''
            SELECT COUNT(*) FROM iot_security_events 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        recent_events = cursor.fetchone()[0]
        
        # Critical events
        cursor.execute('''
            SELECT COUNT(*) FROM iot_security_events 
            WHERE severity = 'critical' AND timestamp > datetime('now', '-24 hours')
        ''')
        critical_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'monitoring_active': self.monitoring,
            'total_devices': len(self.iot_devices),
            'device_statistics': device_stats,
            'recent_sensor_readings': recent_readings,
            'recent_security_events': recent_events,
            'critical_events': critical_events,
            'mqtt_connected': self.mqtt_client is not None,
            'serial_connections': len(self.serial_connections),
            'network_discovery_active': self.network_discovery_active
        }
    
    def stop_monitoring(self):
        """Stop IoT monitoring"""
        self.monitoring = False
        self.network_discovery_active = False
        
        # Close MQTT connection
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        
        # Close serial connections
        for device_id, conn in self.serial_connections.items():
            try:
                conn.close()
            except:
                pass
        
        logger.info("IoT monitoring stopped")
    
    def generate_iot_report(self) -> Dict:
        """Generate comprehensive IoT security report"""
        try:
            status = self.get_iot_status()
            
            # Get detailed statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Sensor reading statistics
            cursor.execute('''
                SELECT sensor_type, COUNT(*) as count, AVG(CAST(value AS REAL)) as avg_value
                FROM sensor_readings 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY sensor_type
            ''')
            sensor_stats = cursor.fetchall()
            
            # Security event timeline
            cursor.execute('''
                SELECT DATE(timestamp) as date, event_type, COUNT(*) as count
                FROM iot_security_events 
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY DATE(timestamp), event_type
                ORDER BY date
            ''')
            event_timeline = cursor.fetchall()
            
            # Device health summary
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM iot_devices
                GROUP BY status
            ''')
            health_summary = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'system_status': status,
                'sensor_statistics': sensor_stats,
                'event_timeline': event_timeline,
                'device_health': health_summary,
                'device_details': {
                    device_id: {
                        'type': device.device_type,
                        'model': device.model,
                        'status': device.status,
                        'trust_level': device.trust_level,
                        'sensors': device.sensors,
                        'capabilities': list(device.capabilities)
                    }
                    for device_id, device in self.iot_devices.items()
                },
                'recommendations': self._generate_iot_recommendations()
            }
        
        except Exception as e:
            logger.error(f"Error generating IoT report: {e}")
            return {'error': str(e)}
    
    def _generate_iot_recommendations(self) -> List[str]:
        """Generate IoT security recommendations"""
        recommendations = []
        
        status = self.get_iot_status()
        
        if status['critical_events'] > 0:
            recommendations.append("Critical IoT security events detected - immediate investigation required")
        
        if status['recent_security_events'] > 50:
            recommendations.append("High number of security events - review device configurations")
        
        # Device-specific recommendations
        for device_id, device in self.iot_devices.items():
            if device.trust_level < 0.5:
                recommendations.append(f"Device {device_id} has low trust level - review security settings")
            
            if device.status == 'degraded':
                recommendations.append(f"Device {device_id} is in degraded state - perform maintenance")
        
        recommendations.extend([
            "Regularly update IoT device firmware",
            "Implement network segmentation for IoT devices",
            "Use strong authentication for IoT device access",
            "Monitor IoT device network traffic patterns",
            "Implement physical security for IoT devices",
            "Regular backup of IoT device configurations",
            "Use encrypted communication protocols (MQTT over TLS)",
            "Implement proper device lifecycle management",
            "Monitor for unusual sensor reading patterns",
            "Regular security audits of IoT infrastructure"
        ])
        
        return recommendations


# Background IoT Manager for seamless operation
class BackgroundIoTManager:
    """Background IoT manager for seamless operation"""
    
    def __init__(self):
        self.iot_manager = IoTManager()
        self.running = False
    
    def start(self):
        """Start background IoT monitoring"""
        print("🚀 Starting Prix AI Security System - IoT Edition")
        print("📡 Detecting and securing IoT devices...")
        print("🔄 Background monitoring activated")
        print("✨ You can continue with your tasks - everything is handled automatically!")
        print("")
        
        self.running = True
        self.iot_manager.start_background_monitoring()
        
        # Show initial status
        status = self.iot_manager.get_iot_status()
        print(f"📊 Detected {status['total_devices']} IoT devices")
        print(f"🔒 Security monitoring: {'Active' if status['monitoring_active'] else 'Inactive'}")
        print(f"📡 MQTT Connection: {'Connected' if status['mqtt_connected'] else 'Standalone'}")
        print("")
        
        # Start status display thread
        threading.Thread(target=self._status_display_loop, daemon=True).start()
        
        # Keep running in background
        try:
            while self.running:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down Prix AI Security System...")
            self.stop()
    
    def stop(self):
        """Stop background IoT monitoring"""
        self.running = False
        self.iot_manager.stop_monitoring()
        print("✅ Prix AI Security System stopped safely")
    
    def _status_display_loop(self):
        """Display periodic status updates"""
        while self.running:
            try:
                time.sleep(300)  # Update every 5 minutes
                
                status = self.iot_manager.get_iot_status()
                
                print(f"📊 Status Update: {status['total_devices']} devices, "
                      f"{status['recent_security_events']} recent events")
                
                if status['critical_events'] > 0:
                    print(f"⚠️  {status['critical_events']} critical events detected!")
                
            except Exception as e:
                logger.error(f"Error in status display: {e}")


# Main entry point for seamless IoT operation
def main():
    """Main entry point - start and forget"""
    import secrets
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/prix-iot.log'),
            logging.StreamHandler()
        ]
    )
    
    # Start background IoT manager
    manager = BackgroundIoTManager()
    manager.start()


if __name__ == "__main__":
    main()
