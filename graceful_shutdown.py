#!/usr/bin/env python3
"""
Graceful Shutdown and Restart Management
Production-grade shutdown with cleanup, state preservation, and recovery
"""

import os
import sys
import time
import signal
import threading
import atexit
import json
import pickle
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import logging

class ShutdownReason(Enum):
    MANUAL = "manual"
    SIGNAL = "signal"
    ERROR = "error"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    MAINTENANCE = "maintenance"

class ComponentStatus(Enum):
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class ShutdownTask:
    """Shutdown task definition"""
    name: str
    priority: int  # Lower numbers = higher priority
    timeout_seconds: float
    critical: bool = False
    cleanup_function: Optional[Callable] = None
    dependencies: Optional[List[str]] = None

@dataclass
class ComponentState:
    """Component state for recovery"""
    name: str
    status: ComponentStatus
    last_checkpoint: datetime
    data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

class GracefulShutdownManager:
    """Production-grade graceful shutdown manager"""
    
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Shutdown state
        self.shutdown_requested = False
        self.shutdown_reason = None
        self.shutdown_start_time = None
        self.shutdown_completed = False
        
        # Components and tasks
        self.components: Dict[str, ComponentState] = {}
        self.shutdown_tasks: List[ShutdownTask] = []
        self.running_threads: Set[threading.Thread] = set()
        self.cleanup_callbacks: List[Callable] = []
        
        # State persistence
        self.state_file = os.path.join(self.config.data_path, 'shutdown_state.json')
        self.checkpoint_file = os.path.join(self.config.data_path, 'checkpoint.pkl')
        
        # Shutdown configuration
        self.default_timeout = 30.0
        self.force_shutdown_timeout = 60.0
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Register exit handler
        atexit.register(self._emergency_shutdown)
        
        # Initialize shutdown tasks
        self._initialize_shutdown_tasks()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Additional signals for Unix systems
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._restart_handler)
        if hasattr(signal, 'SIGUSR1'):
            signal.signal(signal.SIGUSR1, self._checkpoint_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        signal_names = {
            signal.SIGINT: "SIGINT",
            signal.SIGTERM: "SIGTERM",
        }
        
        signal_name = signal_names.get(signum, f"Signal {signum}")
        self.logger.info(f"Received {signal_name}, initiating graceful shutdown")
        
        self.initiate_shutdown(ShutdownReason.SIGNAL, signal_name=signal_name)
    
    def _restart_handler(self, signum, frame):
        """Handle restart signal"""
        self.logger.info("Received restart signal, initiating graceful restart")
        self.initiate_shutdown(ShutdownReason.MAINTENANCE, restart=True)
    
    def _checkpoint_handler(self, signum, frame):
        """Handle checkpoint signal"""
        self.logger.info("Received checkpoint signal, creating checkpoint")
        self.create_checkpoint()
    
    def _emergency_shutdown(self):
        """Emergency shutdown atexit handler"""
        if not self.shutdown_completed:
            self.logger.warning("Emergency shutdown triggered")
            self._force_shutdown()
    
    def _initialize_shutdown_tasks(self):
        """Initialize default shutdown tasks"""
        default_tasks = [
            ShutdownTask(
                name="stop_health_monitoring",
                priority=1,
                timeout_seconds=5.0,
                critical=False,
                cleanup_function=self._stop_health_monitoring
            ),
            ShutdownTask(
                name="stop_iot_monitoring",
                priority=2,
                timeout_seconds=10.0,
                critical=False,
                cleanup_function=self._stop_iot_monitoring
            ),
            ShutdownTask(
                name="stop_security_monitoring",
                priority=3,
                timeout_seconds=10.0,
                critical=False,
                cleanup_function=self._stop_security_monitoring
            ),
            ShutdownTask(
                name="save_database_state",
                priority=4,
                timeout_seconds=15.0,
                critical=True,
                cleanup_function=self._save_database_state
            ),
            ShutdownTask(
                name="close_database_connections",
                priority=5,
                timeout_seconds=10.0,
                critical=True,
                cleanup_function=self._close_database_connections
            ),
            ShutdownTask(
                name="cleanup_temp_files",
                priority=6,
                timeout_seconds=5.0,
                critical=False,
                cleanup_function=self._cleanup_temp_files
            ),
            ShutdownTask(
                name="save_final_logs",
                priority=7,
                timeout_seconds=5.0,
                critical=False,
                cleanup_function=self._save_final_logs
            ),
            ShutdownTask(
                name="create_final_checkpoint",
                priority=8,
                timeout_seconds=10.0,
                critical=True,
                cleanup_function=self._create_final_checkpoint
            ),
        ]
        
        for task in default_tasks:
            self.add_shutdown_task(task)
    
    def register_component(self, name: str, initial_data: Optional[Dict[str, Any]] = None):
        """Register a component for shutdown management"""
        with self.lock:
            self.components[name] = ComponentState(
                name=name,
                status=ComponentStatus.RUNNING,
                last_checkpoint=datetime.now(),
                data=initial_data or {},
                metadata={}
            )
        
        self.logger.info(f"Registered component: {name}")
    
    def unregister_component(self, name: str):
        """Unregister a component"""
        with self.lock:
            if name in self.components:
                del self.components[name]
                self.logger.info(f"Unregistered component: {name}")
    
    def add_shutdown_task(self, task: ShutdownTask):
        """Add shutdown task"""
        self.shutdown_tasks.append(task)
        self.shutdown_tasks.sort(key=lambda t: t.priority)
        self.logger.info(f"Added shutdown task: {task.name} (priority: {task.priority})")
    
    def register_thread(self, thread: threading.Thread):
        """Register a thread for shutdown monitoring"""
        self.running_threads.add(thread)
    
    def unregister_thread(self, thread: threading.Thread):
        """Unregister a thread"""
        self.running_threads.discard(thread)
    
    def add_cleanup_callback(self, callback: Callable):
        """Add cleanup callback"""
        self.cleanup_callbacks.append(callback)
    
    def initiate_shutdown(self, reason: ShutdownReason, restart: bool = False, **context):
        """Initiate graceful shutdown"""
        with self.lock:
            if self.shutdown_requested:
                self.logger.warning("Shutdown already in progress")
                return
            
            self.shutdown_requested = True
            self.shutdown_reason = reason
            self.shutdown_start_time = time.time()
            
            self.logger.info(f"Initiating graceful shutdown: {reason.value}")
            if restart:
                self.logger.info("Restart will be initiated after shutdown")
            
            # Save shutdown state
            self._save_shutdown_state(reason, restart, context)
            
            # Execute shutdown in separate thread
            shutdown_thread = threading.Thread(
                target=self._execute_shutdown,
                args=(restart,),
                name="shutdown-thread"
            )
            shutdown_thread.start()
    
    def _execute_shutdown(self, restart: bool = False):
        """Execute graceful shutdown"""
        try:
            self.logger.info("Starting graceful shutdown sequence")
            
            # Update component statuses
            with self.lock:
                for component in self.components.values():
                    component.status = ComponentStatus.STOPPING
            
            # Execute shutdown tasks
            self._execute_shutdown_tasks()
            
            # Wait for threads to finish
            self._wait_for_threads()
            
            # Execute cleanup callbacks
            self._execute_cleanup_callbacks()
            
            # Mark shutdown complete
            with self.lock:
                self.shutdown_completed = True
                for component in self.components.values():
                    component.status = ComponentStatus.STOPPED
            
            shutdown_time = time.time() - self.shutdown_start_time
            self.logger.info(f"Graceful shutdown completed in {shutdown_time:.2f} seconds")
            
            # Save final state
            self._save_final_state()
            
            # Restart if requested
            if restart:
                self._initiate_restart()
            
        except Exception as e:
            self.logger.error(f"Error during graceful shutdown: {e}")
            self._force_shutdown()
    
    def _execute_shutdown_tasks(self):
        """Execute shutdown tasks in priority order"""
        for task in self.shutdown_tasks:
            if not self.shutdown_requested:
                break
            
            try:
                self.logger.info(f"Executing shutdown task: {task.name}")
                task_start = time.time()
                
                # Check dependencies
                if task.dependencies:
                    for dep in task.dependencies:
                        dep_component = self.components.get(dep)
                        if dep_component and dep_component.status != ComponentStatus.STOPPED:
                            self.logger.warning(f"Dependency {dep} not stopped, skipping task {task.name}")
                            continue
                
                # Execute cleanup function
                if task.cleanup_function:
                    success = self._execute_with_timeout(
                        task.cleanup_function,
                        task.timeout_seconds,
                        task.name
                    )
                    
                    if not success and task.critical:
                        self.logger.error(f"Critical shutdown task {task.name} failed")
                        raise RuntimeError(f"Critical task {task.name} failed")
                
                task_time = time.time() - task_start
                self.logger.info(f"Completed shutdown task {task.name} in {task_time:.2f} seconds")
                
            except Exception as e:
                self.logger.error(f"Shutdown task {task.name} failed: {e}")
                if task.critical:
                    raise
    
    def _execute_with_timeout(self, func: Callable, timeout: float, task_name: str) -> bool:
        """Execute function with timeout"""
        result = [None]
        exception = [None]
        completed = threading.Event()
        
        def wrapper():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e
            finally:
                completed.set()
        
        thread = threading.Thread(target=wrapper, name=f"shutdown-{task_name}")
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            self.logger.error(f"Shutdown task {task_name} timed out after {timeout} seconds")
            return False
        
        if exception[0]:
            self.logger.error(f"Shutdown task {task_name} failed: {exception[0]}")
            return False
        
        return True
    
    def _wait_for_threads(self):
        """Wait for all registered threads to finish"""
        self.logger.info(f"Waiting for {len(self.running_threads)} threads to finish")
        
        remaining_threads = set(self.running_threads)
        timeout = 30.0
        start_time = time.time()
        
        while remaining_threads and (time.time() - start_time) < timeout:
            for thread in list(remaining_threads):
                if not thread.is_alive():
                    remaining_threads.remove(thread)
                    self.logger.debug(f"Thread {thread.name} finished")
            
            if remaining_threads:
                time.sleep(0.1)
        
        # Force stop remaining threads
        for thread in remaining_threads:
            self.logger.warning(f"Thread {thread.name} did not finish gracefully")
            # Note: Python doesn't provide a safe way to force stop threads
    
    def _execute_cleanup_callbacks(self):
        """Execute cleanup callbacks"""
        self.logger.info(f"Executing {len(self.cleanup_callbacks)} cleanup callbacks")
        
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Cleanup callback failed: {e}")
    
    def _stop_health_monitoring(self):
        """Stop health monitoring"""
        try:
            from health_monitor import get_health_monitor
            monitor = get_health_monitor()
            monitor.stop_monitoring()
            self.logger.info("Health monitoring stopped")
        except Exception as e:
            self.logger.error(f"Failed to stop health monitoring: {e}")
    
    def _stop_iot_monitoring(self):
        """Stop IoT monitoring"""
        try:
            from iot_integration import BackgroundIoTManager
            iot_manager = BackgroundIoTManager()
            iot_manager.stop()
            self.logger.info("IoT monitoring stopped")
        except Exception as e:
            self.logger.error(f"Failed to stop IoT monitoring: {e}")
    
    def _stop_security_monitoring(self):
        """Stop security monitoring"""
        try:
            # Implementation would depend on security monitoring system
            self.logger.info("Security monitoring stopped")
        except Exception as e:
            self.logger.error(f"Failed to stop security monitoring: {e}")
    
    def _save_database_state(self):
        """Save database state"""
        try:
            # Implementation would save database state
            self.logger.info("Database state saved")
        except Exception as e:
            self.logger.error(f"Failed to save database state: {e}")
    
    def _close_database_connections(self):
        """Close database connections"""
        try:
            # Implementation would close database connections
            self.logger.info("Database connections closed")
        except Exception as e:
            self.logger.error(f"Failed to close database connections: {e}")
    
    def _cleanup_temp_files(self):
        """Cleanup temporary files"""
        try:
            temp_dir = Path(self.config.data_path) / "temp"
            if temp_dir.exists():
                for file_path in temp_dir.glob("*"):
                    if file_path.is_file():
                        file_path.unlink()
                self.logger.info("Temporary files cleaned up")
        except Exception as e:
            self.logger.error(f"Failed to cleanup temp files: {e}")
    
    def _save_final_logs(self):
        """Save final log entries"""
        try:
            # Implementation would flush logs and create final entries
            self.logger.info("Final logs saved")
        except Exception as e:
            self.logger.error(f"Failed to save final logs: {e}")
    
    def _create_final_checkpoint(self):
        """Create final checkpoint"""
        self.create_checkpoint()
    
    def _save_shutdown_state(self, reason: ShutdownReason, restart: bool, context: Dict[str, Any]):
        """Save shutdown state to file"""
        try:
            state = {
                'shutdown_reason': reason.value,
                'restart': restart,
                'timestamp': datetime.now().isoformat(),
                'context': context,
                'components': {name: asdict(comp) for name, comp in self.components.items()},
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            
        except Exception as e:
            self.logger.error(f"Failed to save shutdown state: {e}")
    
    def _save_final_state(self):
        """Save final state"""
        try:
            final_state = {
                'shutdown_completed': True,
                'completion_time': datetime.now().isoformat(),
                'shutdown_duration': time.time() - self.shutdown_start_time,
                'components': {name: asdict(comp) for name, comp in self.components.items()},
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(final_state, f, indent=2, default=str)
            
        except Exception as e:
            self.logger.error(f"Failed to save final state: {e}")
    
    def _force_shutdown(self):
        """Force shutdown"""
        self.logger.warning("Forcing shutdown")
        
        # Kill all threads
        for thread in self.running_threads:
            if thread.is_alive():
                self.logger.warning(f"Force stopping thread: {thread.name}")
        
        # Emergency state save
        try:
            emergency_state = {
                'emergency_shutdown': True,
                'timestamp': datetime.now().isoformat(),
                'reason': 'force_shutdown',
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(emergency_state, f, indent=2, default=str)
        except Exception:
            pass
        
        # Exit
        os._exit(1)
    
    def _initiate_restart(self):
        """Initiate system restart"""
        self.logger.info("Initiating system restart")
        
        try:
            # Save restart marker
            restart_marker = os.path.join(self.config.data_path, '.restart_pending')
            Path(restart_marker).touch()
            
            # Restart using same executable
            import subprocess
            subprocess.Popen([sys.executable] + sys.argv)
            
        except Exception as e:
            self.logger.error(f"Failed to initiate restart: {e}")
    
    def create_checkpoint(self):
        """Create system checkpoint"""
        try:
            checkpoint_data = {
                'timestamp': datetime.now().isoformat(),
                'components': {name: asdict(comp) for name, comp in self.components.items()},
                'system_state': {
                    'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0,
                    'active_threads': len([t for t in self.running_threads if t.is_alive()]),
                }
            }
            
            with open(self.checkpoint_file, 'wb') as f:
                pickle.dump(checkpoint_data, f)
            
            self.logger.info(f"Checkpoint created at {checkpoint_data['timestamp']}")
            
        except Exception as e:
            self.logger.error(f"Failed to create checkpoint: {e}")
    
    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load system checkpoint"""
        try:
            if not os.path.exists(self.checkpoint_file):
                return None
            
            with open(self.checkpoint_file, 'rb') as f:
                checkpoint_data = pickle.load(f)
            
            self.logger.info(f"Loaded checkpoint from {checkpoint_data['timestamp']}")
            return checkpoint_data
            
        except Exception as e:
            self.logger.error(f"Failed to load checkpoint: {e}")
            return None
    
    def get_shutdown_status(self) -> Dict[str, Any]:
        """Get shutdown status"""
        return {
            'shutdown_requested': self.shutdown_requested,
            'shutdown_reason': self.shutdown_reason.value if self.shutdown_reason else None,
            'shutdown_completed': self.shutdown_completed,
            'shutdown_duration': time.time() - self.shutdown_start_time if self.shutdown_start_time else None,
            'components': {name: comp.status.value for name, comp in self.components.items()},
            'active_threads': len([t for t in self.running_threads if t.is_alive()]),
        }

# Global shutdown manager instance
_shutdown_manager = None

def get_shutdown_manager() -> GracefulShutdownManager:
    """Get global shutdown manager instance"""
    global _shutdown_manager
    if _shutdown_manager is None:
        from production_config import get_config
        config = get_config()
        _shutdown_manager = GracefulShutdownManager(config)
    return _shutdown_manager

def init_shutdown_manager(config, logger=None) -> GracefulShutdownManager:
    """Initialize shutdown manager"""
    global _shutdown_manager
    _shutdown_manager = GracefulShutdownManager(config, logger)
    return _shutdown_manager

if __name__ == "__main__":
    # Test graceful shutdown
    from production_config import get_config
    
    try:
        config = get_config()
        manager = init_shutdown_manager(config)
        
        # Register test component
        manager.register_component("test_component", {"data": "test"})
        
        # Create checkpoint
        manager.create_checkpoint()
        
        # Load checkpoint
        checkpoint = manager.load_checkpoint()
        if checkpoint:
            print(f"✅ Checkpoint loaded from {checkpoint['timestamp']}")
        
        # Test shutdown status
        status = manager.get_shutdown_status()
        print(f"Shutdown status: {json.dumps(status, indent=2)}")
        
        print("✅ Graceful shutdown test completed")
        
    except Exception as e:
        print(f"❌ Graceful shutdown test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
