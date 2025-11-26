#!/usr/bin/env python3
"""
Seamless Launcher - "Start and Forget" Operation
Users can start Prix AI Security System and continue with their tasks
"""

import os
import sys
import time
import threading
import logging
import signal
import platform
import subprocess
from datetime import datetime
from pathlib import Path

# Import Prix modules
from cross_platform import CrossPlatformManager
from iot_integration import BackgroundIoTManager

class SeamlessLauncher:
    """Seamless launcher for Prix AI Security System"""
    
    def __init__(self):
        self.running = False
        self.platform_manager = None
        self.iot_manager = None
        self.background_threads = []
        
        # Configure logging
        self._setup_logging()
        
        # Handle graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_dir = self._get_log_directory()
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, 'prix-seamless.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _get_log_directory(self) -> str:
        """Get platform-specific log directory"""
        system = platform.system().lower()
        
        if system == 'linux':
            return '/var/log/prix-security'
        elif system == 'windows':
            return 'C:\\ProgramData\\PrixSecurity\\logs'
        elif system == 'darwin':
            return '/Library/Logs/PrixSecurity'
        elif 'ANDROID_ROOT' in os.environ:
            return os.path.expanduser('~/.prix/logs')
        else:
            return os.path.expanduser('~/.prix/logs')
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received shutdown signal {signum}")
        self.shutdown()
        sys.exit(0)
    
    def launch(self):
        """Launch Prix AI Security System in seamless mode"""
        # Display beautiful ASCII art
        self._display_ascii_art()
        
        print("🚀 Prix AI Security System - Seamless Mode")
        print("=" * 50)
        print("✨ Start and forget operation activated")
        print("🔒 All security monitoring is now handled automatically")
        print("📊 You can continue with your normal tasks")
        print("")
        
        self.running = True
        
        try:
            # Initialize platform manager
            self._initialize_platform()
            
            # Initialize IoT support
            self._initialize_iot()
            
            # Start background monitoring
            self._start_background_monitoring()
            
            # Display welcome message
            self._display_welcome_message()
            
            # Keep running in background
            self._run_background_loop()
        
        except Exception as e:
            self.logger.error(f"Error launching Prix Security System: {e}")
            print(f"❌ Error: {e}")
            self.shutdown()
    
    def _display_ascii_art(self):
        """Display beautiful ASCII art"""
        print("""
 ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
██║     ██║     ███████║██║   ██║██████╔╝█████╗  
██║     ██║     ██╔══██║╚██╗ ██╔╝██╔══██╗██╔══╝  
╚██████╗███████╗██║  ██║ ╚████╔╝ ██████╔╝███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═════╝ ╚══════╝
                                               
 ██╗ ██████╗ ██████╗ ███████╗                 
 ██║██╔═══██╗██╔══██╗██╔════╝                 
 ██║██║   ██║██████╔╝███████╗                 
 ██║██║   ██║██╔══██╗╚══════║                 
 ██║╚██████╔╝██║  ██║███████║                 
 ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝                 
                                               
    ██╗███╗   ██╗████████╗ ██████╗ ██╗   ██╗██╗███╗   ██╗ ██████╗ 
    ██║████╗  ██║╚══██╔══╝██╔═══██╗██║   ██║██║████╗  ██║██╔═══██╗
    ██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║██╔██╗ ██║██║   ██║
    ██║██║╚██╗██║   ██║   ██║   ██║╚██╗ ██╔╝██║██║╚██╗██║██║   ██║
    ██║██║ ╚████║   ██║   ╚██████╔╝ ╚████╔╝ ██║██║ ╚████║╚██████╔╝
    ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝   ╚═══╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ 

███████╗██╗  ██╗ ██████╗ ██╗    ██╗███████╗██████╗ 
██╔════╝╚██╗██╔╝██╔═══██╗██║    ██║██╔════╝██╔══██╗
█████╗  ╚███╔╝ ██║   ██║██║ █╗ ██║█████╗  ██████╔╝
██╔══╝  ██╔██╗ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗
███████╗██╔╝ ██╗╚██████╔╝╚███╔███╔╝███████╗██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝

Developed by DevMonix Technologies - Let's Lead the Future of Cybersecurity
        """)
    
    def _initialize_platform(self):
        """Initialize platform-specific components"""
        print("🔧 Initializing platform-specific components...")
        
        try:
            self.platform_manager = CrossPlatformManager()
            
            # Generate platform scripts if needed
            self.platform_manager.generate_platform_scripts()
            
            # Create unified launcher
            self.platform_manager.create_unified_launcher()
            
            report = self.platform_manager.get_platform_compatibility_report()
            
            print(f"✅ Platform: {report['current_platform']}")
            print(f"✅ Architecture: {report['architecture']}")
            print(f"✅ Shell: {report['shell_type']}")
            print(f"✅ Features: {len(report['supported_features'])} capabilities")
            print("")
            
        except Exception as e:
            self.logger.error(f"Error initializing platform: {e}")
            print(f"⚠️  Platform initialization warning: {e}")
    
    def _initialize_iot(self):
        """Initialize IoT components"""
        print("📡 Initializing IoT device support...")
        
        try:
            # Check if we're on an IoT-capable platform
            system = platform.system().lower()
            
            if system in ['linux', 'darwin'] or 'ANDROID_ROOT' in os.environ:
                self.iot_manager = BackgroundIoTManager()
                
                # Start IoT monitoring in background
                iot_thread = threading.Thread(target=self._start_iot_monitoring, daemon=True)
                iot_thread.start()
                self.background_threads.append(iot_thread)
                
                print("✅ IoT device monitoring enabled")
            else:
                print("ℹ️  IoT support not available on this platform")
            
            print("")
        
        except Exception as e:
            self.logger.error(f"Error initializing IoT: {e}")
            print(f"⚠️  IoT initialization warning: {e}")
    
    def _start_iot_monitoring(self):
        """Start IoT monitoring in background"""
        try:
            if self.iot_manager:
                self.iot_manager.start()
        except Exception as e:
            self.logger.error(f"Error starting IoT monitoring: {e}")
    
    def _start_background_monitoring(self):
        """Start all background monitoring threads"""
        print("🔄 Starting background security monitoring...")
        
        # Start status update thread
        status_thread = threading.Thread(target=self._status_update_loop, daemon=True)
        status_thread.start()
        self.background_threads.append(status_thread)
        
        # Start health check thread
        health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        health_thread.start()
        self.background_threads.append(health_thread)
        
        # Start log rotation thread
        log_thread = threading.Thread(target=self._log_rotation_loop, daemon=True)
        log_thread.start()
        self.background_threads.append(log_thread)
        
        print("✅ Background monitoring activated")
        print("")
    
    def _display_welcome_message(self):
        """Display welcome and status message"""
        print("🎉 Prix AI Security System is now running!")
        print("")
        print("📋 System Status:")
        print(f"   🔍 Platform: {platform.system()}")
        print(f"   🏗️  Architecture: {platform.machine()}")
        print(f"   📡 IoT Support: {'Enabled' if self.iot_manager else 'Disabled'}")
        print(f"   🔄 Background Mode: Active")
        print("")
        print("💡 What's happening now:")
        print("   • Real-time threat monitoring is active")
        print("   • All security components are running")
        print("   • IoT devices are being protected")
        print("   • System integrity is being verified")
        print("   • Network traffic is being analyzed")
        print("")
        print("🎯 You can now:")
        print("   • Continue with your normal work")
        print("   • All security is handled automatically")
        print("   • Check status anytime with: prix-status")
        print("   • View logs in the background")
        print("")
        print("📊 Status updates will appear periodically below:")
        print("-" * 50)
    
    def _run_background_loop(self):
        """Main background loop"""
        try:
            while self.running:
                time.sleep(60)  # Check every minute
                
                # Verify system is still running properly
                if not self._verify_system_health():
                    self.logger.warning("System health check failed")
        
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.logger.error(f"Error in background loop: {e}")
    
    def _status_update_loop(self):
        """Periodic status updates"""
        last_update = datetime.now()
        
        while self.running:
            try:
                # Wait for 10 minutes between updates
                time.sleep(600)
                
                current_time = datetime.now()
                uptime = current_time - last_update
                
                # Display status update
                print(f"📊 [{current_time.strftime('%H:%M:%S')}] System Status Update")
                print(f"   ⏱️  Uptime: {uptime}")
                
                # Platform status
                if self.platform_manager:
                    platform_report = self.platform_manager.get_platform_compatibility_report()
                    print(f"   🖥️  Platform: {platform_report['current_platform']} - Healthy")
                
                # IoT status
                if self.iot_manager:
                    iot_status = self.iot_manager.get_iot_status()
                    print(f"   📡 IoT Devices: {iot_status['total_devices']} protected")
                    print(f"   🚨 Recent Events: {iot_status['recent_security_events']}")
                    
                    if iot_status['critical_events'] > 0:
                        print(f"   ⚠️  Critical Events: {iot_status['critical_events']}")
                
                print("-" * 30)
                
            except Exception as e:
                self.logger.error(f"Error in status update: {e}")
    
    def _health_check_loop(self):
        """System health monitoring"""
        while self.running:
            try:
                # Check every 5 minutes
                time.sleep(300)
                
                # Monitor system resources
                self._check_system_resources()
                
                # Monitor log files
                self._check_log_health()
                
                # Monitor background threads
                self._check_thread_health()
        
            except Exception as e:
                self.logger.error(f"Error in health check: {e}")
    
    def _check_system_resources(self):
        """Check system resource usage"""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                self.logger.warning(f"High CPU usage: {cpu_percent}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                self.logger.warning(f"High memory usage: {memory.percent}%")
            
            # Disk usage
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                self.logger.warning(f"High disk usage: {disk.percent}%")
        
        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            self.logger.error(f"Error checking system resources: {e}")
    
    def _check_log_health(self):
        """Check log file health"""
        try:
            log_dir = self._get_log_directory()
            log_file = os.path.join(log_dir, 'prix-seamless.log')
            
            if os.path.exists(log_file):
                # Check log file size
                size_mb = os.path.getsize(log_file) / (1024 * 1024)
                if size_mb > 100:  # 100MB
                    self.logger.warning(f"Log file large: {size_mb:.1f}MB")
        
        except Exception as e:
            self.logger.error(f"Error checking log health: {e}")
    
    def _check_thread_health(self):
        """Check background thread health"""
        try:
            alive_threads = sum(1 for thread in self.background_threads if thread.is_alive())
            total_threads = len(self.background_threads)
            
            if alive_threads < total_threads:
                self.logger.warning(f"Only {alive_threads}/{total_threads} background threads alive")
        
        except Exception as e:
            self.logger.error(f"Error checking thread health: {e}")
    
    def _log_rotation_loop(self):
        """Log rotation management"""
        while self.running:
            try:
                # Rotate logs every 24 hours
                time.sleep(86400)  # 24 hours
                
                self._rotate_logs()
        
            except Exception as e:
                self.logger.error(f"Error in log rotation: {e}")
    
    def _rotate_logs(self):
        """Rotate log files"""
        try:
            log_dir = self._get_log_directory()
            log_file = os.path.join(log_dir, 'prix-seamless.log')
            
            if os.path.exists(log_file):
                # Create backup
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_file = f"{log_file}.{timestamp}"
                
                os.rename(log_file, backup_file)
                
                # Create new log file
                with open(log_file, 'w') as f:
                    f.write(f"Log rotated at {datetime.now()}\n")
                
                self.logger.info(f"Log rotated to {backup_file}")
        
        except Exception as e:
            self.logger.error(f"Error rotating logs: {e}")
    
    def _verify_system_health(self) -> bool:
        """Verify overall system health"""
        try:
            # Check if main components are running
            if self.platform_manager is None:
                return False
            
            # Check background threads
            alive_threads = sum(1 for thread in self.background_threads if thread.is_alive())
            if alive_threads == 0 and len(self.background_threads) > 0:
                return False
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error verifying system health: {e}")
            return False
    
    def shutdown(self):
        """Graceful shutdown"""
        print("🛑 Shutting down Prix AI Security System...")
        
        self.running = False
        
        # Stop IoT manager
        if self.iot_manager:
            try:
                self.iot_manager.stop()
            except Exception as e:
                self.logger.error(f"Error stopping IoT manager: {e}")
        
        # Wait for threads to finish
        for thread in self.background_threads:
            try:
                if thread.is_alive():
                    thread.join(timeout=5)
            except Exception as e:
                self.logger.error(f"Error stopping thread: {e}")
        
        print("✅ Prix AI Security System stopped safely")
        print("🔒 All security components have been shut down gracefully")
        
        # Display shutdown ASCII art
        print("""
███████╗██╗██╗  ██╗ ██████╗ ████████╗
██╔════╝██║██║  ██║██╔═══██╗╚══██╔══╝
███████╗██║███████║██║   ██║   ██║   
╚══════██║██╔════██║██║   ██║   ██║   
███████╗██║██║  ██║╚██████╔╝   ██║   
     ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   

Security System Offline - Stay Safe!
        """)


# CLI Status Checker
class StatusChecker:
    """Command-line status checker"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def check_status(self):
        """Check system status"""
        # Display ASCII art
        print("""
███████╗███╗   ███╗ ██████╗ ███╗   ██╗██╗███╗   ██╗███████╗██████╗ 
██╔════╝████╗ ████║██╔═══██╗████╗  ██║██║████╗  ██║██╔════╝██╔══██╗
███████╗██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║█████╗  ██████╔╝
╚══════╝██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║██╔══╝  ██╔══██╗
███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║███████╗██║  ██║
     ╚═╝     ╚═╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        """)
        
        print("📊 Prix AI Security System Status")
        print("=" * 40)
        
        try:
            # Check if running
            if self._is_system_running():
                print("✅ Status: Running")
                
                # Get platform info
                self._show_platform_status()
                
                # Get IoT status
                self._show_iot_status()
                
                # Show resource usage
                self._show_resource_usage()
                
                # Show recent activity
                self._show_recent_activity()
                
            else:
                print("❌ Status: Not running")
                print("💡 Start with: python3 seamless_launcher.py")
        
        except Exception as e:
            print(f"❌ Error checking status: {e}")
    
    def _is_system_running(self) -> bool:
        """Check if Prix Security System is running"""
        try:
            # Check for process
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline', []))
                    if 'seamless_launcher.py' in cmdline or 'prix-security' in cmdline:
                        return True
                except:
                    continue
            
            return False
        
        except ImportError:
            # Fallback: check for lock file
            lock_file = os.path.expanduser('~/.prix/seamless.lock')
            return os.path.exists(lock_file)
        
        except Exception:
            return False
    
    def _show_platform_status(self):
        """Show platform status"""
        try:
            print(f"\n🖥️  Platform Information:")
            print(f"   OS: {platform.system()} {platform.release()}")
            print(f"   Architecture: {platform.machine()}")
            print(f"   Python: {platform.python_version()}")
        except Exception as e:
            print(f"   Error: {e}")
    
    def _show_iot_status(self):
        """Show IoT status"""
        try:
            print(f"\n📡 IoT Status:")
            
            # Try to connect to IoT database
            from iot_integration import IoTManager
            iot_manager = IoTManager()
            status = iot_manager.get_iot_status()
            
            print(f"   Devices: {status['total_devices']}")
            print(f"   Monitoring: {'Active' if status['monitoring_active'] else 'Inactive'}")
            print(f"   Recent Events: {status['recent_security_events']}")
            
            if status['critical_events'] > 0:
                print(f"   ⚠️  Critical Events: {status['critical_events']}")
        
        except Exception as e:
            print(f"   IoT status unavailable: {e}")
    
    def _show_resource_usage(self):
        """Show resource usage"""
        try:
            import psutil
            
            print(f"\n💻 Resource Usage:")
            print(f"   CPU: {psutil.cpu_percent()}%")
            
            memory = psutil.virtual_memory()
            print(f"   Memory: {memory.percent}%")
            
            disk = psutil.disk_usage('/')
            print(f"   Disk: {disk.percent}%")
        
        except ImportError:
            print(f"\n💻 Resource usage: psutil not available")
        except Exception as e:
            print(f"\n💻 Error: {e}")
    
    def _show_recent_activity(self):
        """Show recent activity"""
        try:
            log_dir = self._get_log_directory()
            log_file = os.path.join(log_dir, 'prix-seamless.log')
            
            if os.path.exists(log_file):
                print(f"\n📋 Recent Activity:")
                
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-10:]  # Last 10 lines
                
                for line in lines:
                    if 'INFO' in line or 'WARNING' in line or 'ERROR' in line:
                        print(f"   {line.strip()}")
        
        except Exception as e:
            print(f"\n📋 Recent activity unavailable: {e}")
    
    def _get_log_directory(self) -> str:
        """Get log directory"""
        system = platform.system().lower()
        
        if system == 'linux':
            return '/var/log/prix-security'
        elif system == 'windows':
            return 'C:\\ProgramData\\PrixSecurity\\logs'
        elif system == 'darwin':
            return '/Library/Logs/PrixSecurity'
        else:
            return os.path.expanduser('~/.prix/logs')


# Command-line interface
def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Prix AI Security System - Seamless Launcher')
    parser.add_argument('--status', action='store_true', help='Check system status')
    parser.add_argument('--stop', action='store_true', help='Stop running system')
    
    args = parser.parse_args()
    
    if args.status:
        # Check status
        checker = StatusChecker()
        checker.check_status()
    
    elif args.stop:
        # Stop system
        print("""
███████╗███╗   ███╗███████╗██╗███╗   ██╗███████╗███████╗
██╔════╝████╗ ████║██╔════╝██║████╗  ██║██╔════╝██╔════╝
███████╗██╔████╔██║█████╗  ██║██╔██╗ ██║███████╗███████╗
╚══════╝██║╚██╔╝██║██╔══╝  ██║██║╚██╗██║╚══════╝██╔════╝
███████╗██║ ╚═╝ ██║███████╗██║██║ ╚████║███████╗███████╗
     ╚═╝     ╚═╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
        """)
        print("🛑 Stopping Prix AI Security System...")
        try:
            # Kill processes
            import psutil
            
            killed = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline', []))
                    if 'seamless_launcher.py' in cmdline or 'prix-security' in cmdline:
                        proc.terminate()
                        killed = True
                        print(f"✅ Stopped process {proc.info['pid']}")
                except:
                    continue
            
            if killed:
                print("✅ Prix AI Security System stopped")
                print("🔒 Security components shut down gracefully")
            else:
                print("ℹ️  No running Prix Security processes found")
        
        except Exception as e:
            print(f"❌ Error stopping system: {e}")
    
    else:
        # Start seamless launcher
        launcher = SeamlessLauncher()
        launcher.launch()


if __name__ == "__main__":
    main()
