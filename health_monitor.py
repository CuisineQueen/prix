#!/usr/bin/env python3
"""
Health Monitoring and Check System
Production-grade health checks with metrics and alerting
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import psutil
import socket
import sqlite3
from pathlib import Path

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"

class CheckType(Enum):
    SYSTEM = "system"
    DATABASE = "database"
    IOT = "iot"
    SECURITY = "security"
    PERFORMANCE = "performance"
    NETWORK = "network"
    DISK = "disk"
    MEMORY = "memory"

@dataclass
class HealthCheck:
    """Individual health check definition"""
    name: str
    check_type: CheckType
    description: str
    timeout_seconds: int = 30
    interval_seconds: int = 60
    critical: bool = False
    enabled: bool = True
    
@dataclass
class HealthResult:
    """Health check result"""
    name: str
    status: HealthStatus
    message: str
    timestamp: datetime
    execution_time_ms: float
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    load_average: List[float]
    network_connections: int
    process_count: int
    uptime_seconds: float
    timestamp: datetime

class HealthMonitor:
    """Production health monitoring system"""
    
    def __init__(self, config):
        self.config = config
        self.checks: Dict[str, HealthCheck] = {}
        self.results: Dict[str, HealthResult] = {}
        self.metrics_history: List[SystemMetrics] = []
        self.alert_callbacks: List[Callable] = []
        self.monitoring_thread: Optional[threading.Thread] = None
        self.running = False
        self.start_time = time.time()
        
        self._initialize_checks()
    
    def _initialize_checks(self):
        """Initialize default health checks"""
        default_checks = [
            HealthCheck(
                name="system_resources",
                check_type=CheckType.SYSTEM,
                description="Check system CPU, memory, and disk usage",
                timeout_seconds=10,
                interval_seconds=30,
                critical=True
            ),
            HealthCheck(
                name="database_connectivity",
                check_type=CheckType.DATABASE,
                description="Check database connectivity and performance",
                timeout_seconds=15,
                interval_seconds=60,
                critical=True
            ),
            HealthCheck(
                name="iot_devices",
                check_type=CheckType.IOT,
                description="Check IoT device connectivity and status",
                timeout_seconds=20,
                interval_seconds=120,
                critical=False
            ),
            HealthCheck(
                name="security_modules",
                check_type=CheckType.SECURITY,
                description="Check security module functionality",
                timeout_seconds=10,
                interval_seconds=300,
                critical=True
            ),
            HealthCheck(
                name="network_connectivity",
                check_type=CheckType.NETWORK,
                description="Check network connectivity and DNS resolution",
                timeout_seconds=10,
                interval_seconds=60,
                critical=False
            ),
            HealthCheck(
                name="disk_space",
                check_type=CheckType.DISK,
                description="Check available disk space",
                timeout_seconds=5,
                interval_seconds=300,
                critical=True
            ),
            HealthCheck(
                name="memory_usage",
                check_type=CheckType.MEMORY,
                description="Check memory usage and swap",
                timeout_seconds=5,
                interval_seconds=60,
                critical=True
            ),
        ]
        
        for check in default_checks:
            self.add_check(check)
    
    def add_check(self, check: HealthCheck):
        """Add health check"""
        self.checks[check.name] = check
    
    def remove_check(self, name: str):
        """Remove health check"""
        if name in self.checks:
            del self.checks[name]
        if name in self.results:
            del self.results[name]
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback"""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self):
        """Start continuous health monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Run all enabled checks
                for check_name, check in self.checks.items():
                    if check.enabled:
                        self._run_check(check)
                
                # Collect system metrics
                self._collect_metrics()
                
                # Check for alerts
                self._check_alerts()
                
                # Sleep until next check interval
                time.sleep(self.config.monitoring.health_check_interval_seconds)
                
            except Exception as e:
                print(f"Health monitoring error: {e}")
                time.sleep(10)
    
    def _run_check(self, check: HealthCheck):
        """Run individual health check"""
        start_time = time.time()
        
        try:
            # Execute check based on type
            if check.check_type == CheckType.SYSTEM:
                result = self._check_system_resources(check)
            elif check.check_type == CheckType.DATABASE:
                result = self._check_database(check)
            elif check.check_type == CheckType.IOT:
                result = self._check_iot_devices(check)
            elif check.check_type == CheckType.SECURITY:
                result = self._check_security_modules(check)
            elif check.check_type == CheckType.NETWORK:
                result = self._check_network_connectivity(check)
            elif check.check_type == CheckType.DISK:
                result = self._check_disk_space(check)
            elif check.check_type == CheckType.MEMORY:
                result = self._check_memory_usage(check)
            else:
                result = HealthResult(
                    name=check.name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Unknown check type: {check.check_type}",
                    timestamp=datetime.now(),
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            self.results[check.name] = result
            
        except Exception as e:
            result = HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Check execution failed",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
            self.results[check.name] = result
    
    def _check_system_resources(self, check: HealthCheck) -> HealthResult:
        """Check system resources"""
        start_time = time.time()
        
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            load_avg = psutil.getloadavg()
            
            # Determine status based on thresholds
            status = HealthStatus.HEALTHY
            issues = []
            
            if cpu_percent > self.config.monitoring.alert_threshold_cpu_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            
            if memory.percent > self.config.monitoring.alert_threshold_memory_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"High memory usage: {memory.percent:.1f}%")
            
            if disk.percent > self.config.monitoring.alert_threshold_disk_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"High disk usage: {disk.percent:.1f}%")
            
            message = "System resources OK" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent,
                    'load_average': list(load_avg),
                    'memory_available_gb': memory.available / (1024**3),
                    'disk_free_gb': disk.free / (1024**3),
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"System resource check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_database(self, check: HealthCheck) -> HealthResult:
        """Check database connectivity and performance"""
        start_time = time.time()
        
        try:
            # Check database file
            db_path = os.path.join(self.config.data_path, 'prix_security.db')
            
            if not os.path.exists(db_path):
                return HealthResult(
                    name=check.name,
                    status=HealthStatus.CRITICAL,
                    message="Database file not found",
                    timestamp=datetime.now(),
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
            # Test database connectivity
            conn = sqlite3.connect(db_path, timeout=check.timeout_seconds)
            cursor = conn.cursor()
            
            # Test query performance
            query_start = time.time()
            cursor.execute("SELECT COUNT(*) FROM sqlite_master")
            query_time = (time.time() - query_start) * 1000
            
            # Check database size
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
            
            conn.close()
            
            # Determine status
            status = HealthStatus.HEALTHY
            issues = []
            
            if query_time > 1000:  # 1 second
                status = HealthStatus.DEGRADED
                issues.append(f"Slow query performance: {query_time:.1f}ms")
            
            if db_size > 1000:  # 1GB
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"Large database size: {db_size:.1f}MB")
            
            message = "Database OK" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'query_time_ms': query_time,
                    'database_size_mb': db_size,
                    'database_path': db_path,
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Database check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_iot_devices(self, check: HealthCheck) -> HealthResult:
        """Check IoT device connectivity"""
        start_time = time.time()
        
        try:
            # Try to import IoT manager
            from iot_integration import IoTManager
            
            iot_manager = IoTManager()
            status_data = iot_manager.get_iot_status()
            
            total_devices = status_data.get('total_devices', 0)
            online_devices = status_data.get('online_devices', 0)
            critical_events = status_data.get('critical_events', 0)
            
            # Determine status
            health_status = HealthStatus.HEALTHY
            issues = []
            
            if critical_events > 0:
                health_status = HealthStatus.CRITICAL
                issues.append(f"{critical_events} critical events")
            
            if online_devices < total_devices * 0.8:  # Less than 80% online
                health_status = HealthStatus.DEGRADED if health_status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"Only {online_devices}/{total_devices} devices online")
            
            message = "IoT devices OK" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=health_status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'total_devices': total_devices,
                    'online_devices': online_devices,
                    'critical_events': critical_events,
                    'monitoring_active': status_data.get('monitoring_active', False),
                }
            )
            
        except ImportError:
            return HealthResult(
                name=check.name,
                status=HealthStatus.DEGRADED,
                message="IoT module not available",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"IoT check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_security_modules(self, check: HealthCheck) -> HealthResult:
        """Check security module functionality"""
        start_time = time.time()
        
        try:
            # Test importing security modules
            from main import SystemMonitor, ThreatEliminator, DatabaseManager
            
            # Test database manager
            db_manager = DatabaseManager()
            recent_threats = db_manager.get_recent_threats()
            
            # Test system monitor (lightweight check)
            monitor = SystemMonitor()
            
            issues = []
            status = HealthStatus.HEALTHY
            
            # Check if database is accessible
            if recent_threats is None:
                status = HealthStatus.UNHEALTHY
                issues.append("Database manager not responding")
            
            message = "Security modules OK" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'database_accessible': recent_threats is not None,
                    'monitor_initialized': monitor is not None,
                    'recent_threats_count': len(recent_threats) if recent_threats else 0,
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Security modules check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_network_connectivity(self, check: HealthCheck) -> HealthResult:
        """Check network connectivity"""
        start_time = time.time()
        
        try:
            # Test DNS resolution
            dns_start = time.time()
            socket.gethostbyname('google.com')
            dns_time = (time.time() - dns_start) * 1000
            
            # Test local network interface
            interfaces = psutil.net_if_addrs()
            active_interfaces = [name for name, addrs in interfaces.items() 
                               if any(addr.family == socket.AF_INET for addr in addrs)]
            
            # Test network stats
            net_stats = psutil.net_io_counters()
            
            issues = []
            status = HealthStatus.HEALTHY
            
            if dns_time > 5000:  # 5 seconds
                status = HealthStatus.DEGRADED
                issues.append(f"Slow DNS resolution: {dns_time:.1f}ms")
            
            if len(active_interfaces) == 0:
                status = HealthStatus.UNHEALTHY
                issues.append("No active network interfaces")
            
            message = "Network connectivity OK" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'dns_resolution_time_ms': dns_time,
                    'active_interfaces': len(active_interfaces),
                    'interface_names': active_interfaces,
                    'bytes_sent': net_stats.bytes_sent,
                    'bytes_recv': net_stats.bytes_recv,
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Network connectivity check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_disk_space(self, check: HealthCheck) -> HealthResult:
        """Check disk space"""
        start_time = time.time()
        
        try:
            disk = psutil.disk_usage('/')
            free_percent = (disk.free / disk.total) * 100
            
            status = HealthStatus.HEALTHY
            issues = []
            
            if free_percent < 5:  # Less than 5% free
                status = HealthStatus.CRITICAL
                issues.append(f"Critical: Only {free_percent:.1f}% free space")
            elif free_percent < 10:  # Less than 10% free
                status = HealthStatus.UNHEALTHY
                issues.append(f"Low disk space: {free_percent:.1f}% free")
            elif free_percent < 20:  # Less than 20% free
                status = HealthStatus.DEGRADED
                issues.append(f"Moderate disk usage: {free_percent:.1f}% free")
            
            message = f"Disk space OK ({free_percent:.1f}% free)" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'total_gb': disk.total / (1024**3),
                    'used_gb': disk.used / (1024**3),
                    'free_gb': disk.free / (1024**3),
                    'free_percent': free_percent,
                    'used_percent': disk.percent,
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Disk space check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _check_memory_usage(self, check: HealthCheck) -> HealthResult:
        """Check memory usage"""
        start_time = time.time()
        
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            status = HealthStatus.HEALTHY
            issues = []
            
            if swap.percent > 50:  # High swap usage
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"High swap usage: {swap.percent:.1f}%")
            
            if memory.percent > 90:  # Critical memory usage
                status = HealthStatus.CRITICAL
                issues.append(f"Critical memory usage: {memory.percent:.1f}%")
            elif memory.percent > 80:  # High memory usage
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else HealthStatus.UNHEALTHY
                issues.append(f"High memory usage: {memory.percent:.1f}%")
            
            message = f"Memory usage OK ({memory.percent:.1f}%)" if not issues else "; ".join(issues)
            
            return HealthResult(
                name=check.name,
                status=status,
                message=message,
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    'total_gb': memory.total / (1024**3),
                    'available_gb': memory.available / (1024**3),
                    'used_gb': memory.used / (1024**3),
                    'used_percent': memory.percent,
                    'swap_total_gb': swap.total / (1024**3),
                    'swap_used_gb': swap.used / (1024**3),
                    'swap_percent': swap.percent,
                }
            )
            
        except Exception as e:
            return HealthResult(
                name=check.name,
                status=HealthStatus.CRITICAL,
                message=f"Memory usage check failed: {e}",
                timestamp=datetime.now(),
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )
    
    def _collect_metrics(self):
        """Collect system metrics"""
        try:
            metrics = SystemMetrics(
                cpu_percent=psutil.cpu_percent(),
                memory_percent=psutil.virtual_memory().percent,
                disk_percent=psutil.disk_usage('/').percent,
                load_average=list(psutil.getloadavg()),
                network_connections=len(psutil.net_connections()),
                process_count=len(psutil.pids()),
                uptime_seconds=time.time() - self.start_time,
                timestamp=datetime.now()
            )
            
            self.metrics_history.append(metrics)
            
            # Keep only last 24 hours of metrics
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.metrics_history = [m for m in self.metrics_history if m.timestamp > cutoff_time]
            
        except Exception as e:
            print(f"Metrics collection failed: {e}")
    
    def _check_alerts(self):
        """Check for alert conditions"""
        critical_checks = [r for r in self.results.values() if r.status == HealthStatus.CRITICAL]
        
        if critical_checks:
            alert_data = {
                'alert_type': 'health_check_critical',
                'timestamp': datetime.now().isoformat(),
                'critical_checks': [asdict(check) for check in critical_checks],
                'total_checks': len(self.results),
                'hostname': socket.gethostname(),
            }
            
            for callback in self.alert_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    print(f"Alert callback failed: {e}")
    
    def get_overall_status(self) -> HealthStatus:
        """Get overall system health status"""
        if not self.results:
            return HealthStatus.HEALTHY
        
        statuses = [r.status for r in self.results.values()]
        
        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        elif HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.HEALTHY
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive health summary"""
        overall_status = self.get_overall_status()
        
        summary = {
            'overall_status': overall_status.value,
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': time.time() - self.start_time,
            'total_checks': len(self.results),
            'checks_by_status': {
                'healthy': len([r for r in self.results.values() if r.status == HealthStatus.HEALTHY]),
                'degraded': len([r for r in self.results.values() if r.status == HealthStatus.DEGRADED]),
                'unhealthy': len([r for r in self.results.values() if r.status == HealthStatus.UNHEALTHY]),
                'critical': len([r for r in self.results.values() if r.status == HealthStatus.CRITICAL]),
            },
            'check_results': {name: asdict(result) for name, result in self.results.items()},
            'system_metrics': asdict(self.metrics_history[-1]) if self.metrics_history else None,
            'monitoring_active': self.running,
        }
        
        return summary
    
    def run_all_checks(self) -> Dict[str, HealthResult]:
        """Run all health checks immediately"""
        for check_name, check in self.checks.items():
            if check.enabled:
                self._run_check(check)
        
        return self.results

# Global health monitor instance
_health_monitor = None

def get_health_monitor() -> HealthMonitor:
    """Get global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        from production_config import get_config
        config = get_config()
        _health_monitor = HealthMonitor(config)
    return _health_monitor

def init_health_monitor(config) -> HealthMonitor:
    """Initialize health monitor"""
    global _health_monitor
    _health_monitor = HealthMonitor(config)
    return _health_monitor

if __name__ == "__main__":
    # Test health monitoring
    from production_config import get_config
    
    try:
        config = get_config()
        monitor = init_health_monitor(config)
        
        # Run all checks
        results = monitor.run_all_checks()
        
        print("✅ Health monitoring test completed")
        print(f"Overall status: {monitor.get_overall_status().value}")
        
        summary = monitor.get_health_summary()
        print(json.dumps(summary, indent=2, default=str))
        
    except Exception as e:
        print(f"❌ Health monitoring test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
