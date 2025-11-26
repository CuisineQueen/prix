#!/usr/bin/env python3
"""
Production Deployment Script
Automated production deployment with validation and rollback
"""

import os
import sys
import time
import json
import shutil
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from production_config import get_config, init_config
from production_logging import init_logging
from health_monitor import init_health_monitor
from error_handler import init_error_handler
from graceful_shutdown import init_shutdown_manager

class ProductionDeployer:
    """Production deployment manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = init_config(config_file)
        self.logger = init_logging(self.config)
        self.health_monitor = init_health_monitor(self.config)
        self.error_handler = init_error_handler(self.config, self.logger)
        self.shutdown_manager = init_shutdown_manager(self.config, self.logger)
        
        # Deployment paths
        self.deploy_path = Path(self.config.base_path)
        self.backup_path = Path(self.config.data_path) / "backups"
        self.current_version_path = self.deploy_path / "current"
        self.versions_path = self.deploy_path / "versions"
        
        # Create directories
        self._create_directories()
    
    def _create_directories(self):
        """Create deployment directories"""
        directories = [
            self.deploy_path,
            self.backup_path,
            self.versions_path,
            self.config.config_path,
            self.config.log_path,
            self.config.data_path,
            self.config.run_path,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def deploy(self, source_path: str, version: Optional[str] = None) -> bool:
        """Deploy new version"""
        if not version:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.logger.info(f"Starting deployment of version {version}")
        
        try:
            # Pre-deployment checks
            if not self._pre_deployment_checks():
                self.logger.error("Pre-deployment checks failed")
                return False
            
            # Create backup
            if not self._create_backup():
                self.logger.error("Backup creation failed")
                return False
            
            # Deploy new version
            if not self._deploy_version(source_path, version):
                self.logger.error("Version deployment failed")
                return False
            
            # Post-deployment validation
            if not self._post_deployment_validation():
                self.logger.error("Post-deployment validation failed")
                self._rollback()
                return False
            
            # Update current symlink
            self._update_current_version(version)
            
            # Cleanup old versions
            self._cleanup_old_versions()
            
            self.logger.info(f"Deployment of version {version} completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            self._rollback()
            return False
    
    def _pre_deployment_checks(self) -> bool:
        """Pre-deployment health checks"""
        self.logger.info("Running pre-deployment checks")
        
        # Check system resources
        health_summary = self.health_monitor.get_health_summary()
        
        if health_summary['overall_status'] in ['unhealthy', 'critical']:
            self.logger.error(f"System health check failed: {health_summary['overall_status']}")
            return False
        
        # Check configuration
        try:
            self.config.create_directories()
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
        
        # Check permissions
        if not self._check_permissions():
            self.logger.error("Permission check failed")
            return False
        
        # Check disk space
        if not self._check_disk_space():
            self.logger.error("Insufficient disk space")
            return False
        
        self.logger.info("Pre-deployment checks passed")
        return True
    
    def _create_backup(self) -> bool:
        """Create backup of current version"""
        self.logger.info("Creating backup")
        
        if not self.current_version_path.exists():
            self.logger.info("No current version to backup")
            return True
        
        backup_version = datetime.now().strftime("%backup_%Y%m%d_%H%M%S")
        backup_path = self.backup_path / backup_version
        
        try:
            shutil.copytree(self.current_version_path, backup_path)
            
            # Save backup metadata
            backup_metadata = {
                'version': backup_version,
                'timestamp': datetime.now().isoformat(),
                'original_path': str(self.current_version_path),
                'size': sum(f.stat().st_size for f in backup_path.rglob('*') if f.is_file()),
            }
            
            with open(backup_path / 'backup_metadata.json', 'w') as f:
                json.dump(backup_metadata, f, indent=2)
            
            self.logger.info(f"Backup created: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
            return False
    
    def _deploy_version(self, source_path: str, version: str) -> bool:
        """Deploy new version"""
        self.logger.info(f"Deploying version {version}")
        
        source = Path(source_path)
        target = self.versions_path / version
        
        if not source.exists():
            self.logger.error(f"Source path does not exist: {source}")
            return False
        
        try:
            # Copy source to version directory
            if target.exists():
                shutil.rmtree(target)
            
            shutil.copytree(source, target)
            
            # Set permissions
            self._set_permissions(target)
            
            # Install dependencies
            if not self._install_dependencies(target):
                return False
            
            # Run deployment scripts
            if not self._run_deployment_scripts(target):
                return False
            
            self.logger.info(f"Version {version} deployed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Version deployment failed: {e}")
            return False
    
    def _post_deployment_validation(self) -> bool:
        """Post-deployment validation"""
        self.logger.info("Running post-deployment validation")
        
        # Health check
        health_summary = self.health_monitor.get_health_summary()
        
        if health_summary['overall_status'] in ['unhealthy', 'critical']:
            self.logger.error(f"Health check failed: {health_summary['overall_status']}")
            return False
        
        # Configuration validation
        try:
            config = get_config()
            config.create_directories()
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
        
        # Service validation
        if not self._validate_services():
            self.logger.error("Service validation failed")
            return False
        
        self.logger.info("Post-deployment validation passed")
        return True
    
    def _update_current_version(self, version: str):
        """Update current version symlink"""
        current_link = self.current_version_path
        version_path = self.versions_path / version
        
        if current_link.exists():
            current_link.unlink()
        
        current_link.symlink_to(version_path)
        self.logger.info(f"Current version updated to {version}")
    
    def _rollback(self) -> bool:
        """Rollback to previous version"""
        self.logger.warning("Initiating rollback")
        
        try:
            # Find latest backup
            backups = list(self.backup_path.glob("backup_*"))
            if not backups:
                self.logger.error("No backups found for rollback")
                return False
            
            latest_backup = max(backups, key=lambda x: x.stat().st_mtime)
            
            # Restore from backup
            if self.current_version_path.exists():
                self.current_version_path.unlink()
            
            shutil.copytree(latest_backup, self.current_version_path)
            
            self.logger.info(f"Rollback completed to {latest_backup}")
            return True
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False
    
    def _check_permissions(self) -> bool:
        """Check deployment permissions"""
        required_paths = [
            self.deploy_path,
            self.config.config_path,
            self.config.log_path,
            self.config.data_path,
            self.config.run_path,
        ]
        
        for path in required_paths:
            if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
                self.logger.error(f"Insufficient permissions for: {path}")
                return False
        
        return True
    
    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        import psutil
        
        disk = psutil.disk_usage(self.deploy_path.anchor)
        free_gb = disk.free / (1024**3)
        
        if free_gb < 1.0:  # Less than 1GB free
            self.logger.error(f"Insufficient disk space: {free_gb:.2f}GB free")
            return False
        
        return True
    
    def _set_permissions(self, path: Path):
        """Set appropriate permissions"""
        # Set directory permissions
        for directory in path.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
            elif directory.is_file():
                if directory.name.endswith('.py'):
                    directory.chmod(0o755)
                else:
                    directory.chmod(0o644)
    
    def _install_dependencies(self, version_path: Path) -> bool:
        """Install Python dependencies"""
        requirements_file = version_path / 'requirements.txt'
        
        if not requirements_file.exists():
            self.logger.info("No requirements.txt found")
            return True
        
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"Dependency installation failed: {result.stderr}")
                return False
            
            self.logger.info("Dependencies installed successfully")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Dependency installation timed out")
            return False
        except Exception as e:
            self.logger.error(f"Dependency installation failed: {e}")
            return False
    
    def _run_deployment_scripts(self, version_path: Path) -> bool:
        """Run deployment scripts"""
        deploy_script = version_path / 'deploy.sh'
        
        if not deploy_script.exists():
            self.logger.info("No deployment script found")
            return True
        
        try:
            os.chdir(version_path)
            result = subprocess.run(['bash', 'deploy.sh'], capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                self.logger.error(f"Deployment script failed: {result.stderr}")
                return False
            
            self.logger.info("Deployment script executed successfully")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Deployment script timed out")
            return False
        except Exception as e:
            self.logger.error(f"Deployment script execution failed: {e}")
            return False
    
    def _validate_services(self) -> bool:
        """Validate deployed services"""
        # Test import of main modules
        try:
            sys.path.insert(0, str(self.current_version_path))
            
            import main
            import seamless_launcher
            import iot_integration
            
            self.logger.info("Service validation passed")
            return True
            
        except ImportError as e:
            self.logger.error(f"Service validation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Service validation failed: {e}")
            return False
    
    def _cleanup_old_versions(self, keep_versions: int = 5):
        """Cleanup old versions"""
        versions = list(self.versions_path.iterdir())
        versions.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        for version in versions[keep_versions:]:
            try:
                shutil.rmtree(version)
                self.logger.info(f"Removed old version: {version}")
            except Exception as e:
                self.logger.error(f"Failed to remove version {version}: {e}")
    
    def status(self) -> Dict[str, Any]:
        """Get deployment status"""
        status = {
            'current_version': None,
            'available_versions': [],
            'backups': [],
            'health_status': None,
            'deployment_time': None,
        }
        
        # Current version
        if self.current_version_path.exists() and self.current_version_path.is_symlink():
            status['current_version'] = self.current_version_path.resolve().name
        
        # Available versions
        for version_path in self.versions_path.iterdir():
            if version_path.is_dir():
                status['available_versions'].append({
                    'version': version_path.name,
                    'created': datetime.fromtimestamp(version_path.stat().st_mtime).isoformat(),
                    'size': sum(f.stat().st_size for f in version_path.rglob('*') if f.is_file()),
                })
        
        # Backups
        for backup_path in self.backup_path.iterdir():
            if backup_path.is_dir():
                metadata_file = backup_path / 'backup_metadata.json'
                metadata = {}
                if metadata_file.exists():
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                
                status['backups'].append({
                    'version': backup_path.name,
                    'metadata': metadata,
                })
        
        # Health status
        status['health_status'] = self.health_monitor.get_health_summary()
        
        return status

def main():
    """Main deployment script"""
    parser = argparse.ArgumentParser(description='Production deployment script')
    parser.add_argument('action', choices=['deploy', 'rollback', 'status'], help='Deployment action')
    parser.add_argument('--source', help='Source path for deployment')
    parser.add_argument('--version', help='Version identifier')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--keep-versions', type=int, default=5, help='Number of versions to keep')
    
    args = parser.parse_args()
    
    try:
        deployer = ProductionDeployer(args.config)
        
        if args.action == 'deploy':
            if not args.source:
                print("Error: --source required for deploy action")
                sys.exit(1)
            
            success = deployer.deploy(args.source, args.version)
            sys.exit(0 if success else 1)
        
        elif args.action == 'rollback':
            success = deployer.rollback()
            sys.exit(0 if success else 1)
        
        elif args.action == 'status':
            status = deployer.status()
            print(json.dumps(status, indent=2))
            sys.exit(0)
    
    except Exception as e:
        print(f"Deployment error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
