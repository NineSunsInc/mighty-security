#!/usr/bin/env python3
"""
Secure-Toolings Auto-Updater

Manages updates for the security suite:
- Checks for new versions
- Updates threat signatures
- Pulls latest detection patterns
- Preserves user configurations
"""

import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple
import requests
from datetime import datetime, timedelta
import hashlib
import sys


class SecurityUpdater:
    """
    Manages updates for secure-toolings.
    
    Key features:
    - Git-based updates for source installations
    - Pip-based updates for package installations
    - Signature/pattern updates separate from code
    - Configuration preservation
    - Rollback capability
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.config_dir = Path.home() / '.mighty-mcp'
        self.config_dir.mkdir(exist_ok=True)
        
        self.update_cache = self.config_dir / 'update_cache.json'
        self.backup_dir = self.config_dir / 'backups'
        self.backup_dir.mkdir(exist_ok=True)
        
        # URLs for updates
        self.github_repo = "https://github.com/nine-suns/secure-toolings"
        self.signature_url = "https://raw.githubusercontent.com/nine-suns/secure-toolings/main/signatures/latest.json"
        self.pattern_url = "https://raw.githubusercontent.com/nine-suns/secure-toolings/main/patterns/latest.json"
        
    def check_for_updates(self, force: bool = False) -> Dict:
        """
        Check for available updates.
        
        Returns dict with:
        - code_update: bool
        - signature_update: bool
        - pattern_update: bool
        - version_info: dict
        """
        
        # Check cache to avoid excessive checks
        if not force and self._cache_valid():
            return self._load_cache()
        
        results = {
            'code_update': False,
            'signature_update': False,
            'pattern_update': False,
            'current_version': self._get_current_version(),
            'latest_version': None,
            'checked_at': datetime.now().isoformat()
        }
        
        # Check code updates (git or pip)
        if self._is_git_install():
            results['code_update'], results['latest_version'] = self._check_git_updates()
        else:
            results['code_update'], results['latest_version'] = self._check_pip_updates()
        
        # Check signature updates
        results['signature_update'] = self._check_signature_updates()
        
        # Check pattern updates
        results['pattern_update'] = self._check_pattern_updates()
        
        # Save to cache
        self._save_cache(results)
        
        return results
    
    def update_all(self, components: Dict[str, bool] = None) -> Dict:
        """
        Update specified components.
        
        Args:
            components: Dict specifying what to update
                       {'code': True, 'signatures': True, 'patterns': True}
        
        Returns:
            Update results with success/failure for each component
        """
        
        if components is None:
            components = {'code': True, 'signatures': True, 'patterns': True}
        
        results = {
            'success': True,
            'updated': [],
            'failed': [],
            'backup_path': None
        }
        
        # Create backup first
        if components.get('code'):
            results['backup_path'] = self._create_backup()
        
        # Update code
        if components.get('code'):
            try:
                if self._is_git_install():
                    self._update_via_git()
                else:
                    self._update_via_pip()
                results['updated'].append('code')
            except Exception as e:
                results['failed'].append(f'code: {e}')
                results['success'] = False
        
        # Update signatures
        if components.get('signatures'):
            try:
                self._update_signatures()
                results['updated'].append('signatures')
            except Exception as e:
                results['failed'].append(f'signatures: {e}')
        
        # Update patterns
        if components.get('patterns'):
            try:
                self._update_patterns()
                results['updated'].append('patterns')
            except Exception as e:
                results['failed'].append(f'patterns: {e}')
        
        return results
    
    def rollback(self, backup_path: str = None) -> bool:
        """
        Rollback to a previous version.
        
        Args:
            backup_path: Specific backup to restore, or latest if None
        
        Returns:
            True if rollback successful
        """
        
        if backup_path is None:
            # Find latest backup
            backups = sorted(self.backup_dir.glob('backup_*.tar.gz'))
            if not backups:
                raise ValueError("No backups found")
            backup_path = str(backups[-1])
        
        try:
            # Extract backup
            subprocess.run(
                ['tar', '-xzf', backup_path, '-C', str(self.base_dir)],
                check=True
            )
            return True
        except Exception as e:
            print(f"Rollback failed: {e}")
            return False
    
    def auto_update_check(self) -> Optional[Dict]:
        """
        Check if auto-update should run (called on CLI startup).
        
        Returns update info if updates available, None otherwise.
        """
        
        # Check if auto-update is enabled
        config = self._load_config()
        if not config.get('auto_update', {}).get('enabled', True):
            return None
        
        # Check frequency (default: daily)
        last_check = config.get('auto_update', {}).get('last_check')
        frequency = config.get('auto_update', {}).get('frequency', 'daily')
        
        if last_check:
            last_check_time = datetime.fromisoformat(last_check)
            
            if frequency == 'daily':
                if datetime.now() - last_check_time < timedelta(days=1):
                    return None
            elif frequency == 'weekly':
                if datetime.now() - last_check_time < timedelta(days=7):
                    return None
        
        # Check for updates
        updates = self.check_for_updates()
        
        # Update last check time
        config['auto_update'] = config.get('auto_update', {})
        config['auto_update']['last_check'] = datetime.now().isoformat()
        self._save_config(config)
        
        # Return updates if any available
        if updates['code_update'] or updates['signature_update'] or updates['pattern_update']:
            return updates
        
        return None
    
    # Private methods
    
    def _is_git_install(self) -> bool:
        """Check if this is a git installation."""
        git_dir = self.base_dir / '.git'
        return git_dir.exists()
    
    def _get_current_version(self) -> str:
        """Get current version."""
        try:
            if self._is_git_install():
                result = subprocess.run(
                    ['git', 'rev-parse', 'HEAD'],
                    cwd=self.base_dir,
                    capture_output=True,
                    text=True
                )
                return result.stdout.strip()[:8]
            else:
                # Read from version file or package
                version_file = self.base_dir / 'VERSION'
                if version_file.exists():
                    return version_file.read_text().strip()
                return "unknown"
        except:
            return "unknown"
    
    def _check_git_updates(self) -> Tuple[bool, str]:
        """Check for git updates."""
        try:
            # Fetch latest
            subprocess.run(
                ['git', 'fetch', 'origin'],
                cwd=self.base_dir,
                check=True,
                capture_output=True
            )
            
            # Check if behind
            result = subprocess.run(
                ['git', 'rev-list', 'HEAD..origin/main', '--count'],
                cwd=self.base_dir,
                capture_output=True,
                text=True
            )
            
            behind_count = int(result.stdout.strip())
            
            # Get latest commit
            result = subprocess.run(
                ['git', 'rev-parse', 'origin/main'],
                cwd=self.base_dir,
                capture_output=True,
                text=True
            )
            latest = result.stdout.strip()[:8]
            
            return behind_count > 0, latest
            
        except:
            return False, None
    
    def _check_pip_updates(self) -> Tuple[bool, str]:
        """Check for pip updates."""
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True,
                text=True
            )
            
            outdated = json.loads(result.stdout)
            for package in outdated:
                if package['name'] == 'secure-toolings':
                    return True, package['latest_version']
            
            return False, None
            
        except:
            return False, None
    
    def _check_signature_updates(self) -> bool:
        """Check for signature updates."""
        try:
            # Get remote signature hash
            response = requests.get(self.signature_url + '.sha256', timeout=5)
            remote_hash = response.text.strip()
            
            # Get local signature hash
            local_sig_file = self.base_dir / 'signatures' / 'latest.json'
            if local_sig_file.exists():
                local_hash = hashlib.sha256(local_sig_file.read_bytes()).hexdigest()
                return remote_hash != local_hash
            
            return True  # No local file, need update
            
        except:
            return False
    
    def _check_pattern_updates(self) -> bool:
        """Check for pattern updates."""
        try:
            # Similar to signature check
            response = requests.get(self.pattern_url + '.sha256', timeout=5)
            remote_hash = response.text.strip()
            
            local_pattern_file = self.base_dir / 'patterns' / 'latest.json'
            if local_pattern_file.exists():
                local_hash = hashlib.sha256(local_pattern_file.read_bytes()).hexdigest()
                return remote_hash != local_hash
            
            return True
            
        except:
            return False
    
    def _update_via_git(self):
        """Update via git pull."""
        # Stash any local changes
        subprocess.run(
            ['git', 'stash'],
            cwd=self.base_dir,
            check=True
        )
        
        # Pull latest
        subprocess.run(
            ['git', 'pull', 'origin', 'main'],
            cwd=self.base_dir,
            check=True
        )
        
        # Reinstall dependencies
        subprocess.run(
            ['pip', 'install', '-e', '.'],
            cwd=self.base_dir,
            check=True
        )
    
    def _update_via_pip(self):
        """Update via pip."""
        subprocess.run(
            ['pip', 'install', '--upgrade', 'secure-toolings'],
            check=True
        )
    
    def _update_signatures(self):
        """Update threat signatures."""
        response = requests.get(self.signature_url)
        response.raise_for_status()
        
        sig_file = self.base_dir / 'signatures' / 'latest.json'
        sig_file.parent.mkdir(exist_ok=True)
        sig_file.write_bytes(response.content)
    
    def _update_patterns(self):
        """Update detection patterns."""
        response = requests.get(self.pattern_url)
        response.raise_for_status()
        
        pattern_file = self.base_dir / 'patterns' / 'latest.json'
        pattern_file.parent.mkdir(exist_ok=True)
        pattern_file.write_bytes(response.content)
    
    def _create_backup(self) -> str:
        """Create backup of current installation."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f'backup_{timestamp}.tar.gz'
        
        # Create tarball excluding .git and __pycache__
        subprocess.run(
            ['tar', '-czf', str(backup_path), 
             '--exclude=.git', '--exclude=__pycache__',
             '-C', str(self.base_dir.parent), self.base_dir.name],
            check=True
        )
        
        return str(backup_path)
    
    def _cache_valid(self) -> bool:
        """Check if update cache is still valid."""
        if not self.update_cache.exists():
            return False
        
        cache = self._load_cache()
        checked_at = datetime.fromisoformat(cache.get('checked_at', '2000-01-01'))
        
        # Cache valid for 1 hour
        return datetime.now() - checked_at < timedelta(hours=1)
    
    def _load_cache(self) -> Dict:
        """Load update cache."""
        if self.update_cache.exists():
            return json.loads(self.update_cache.read_text())
        return {}
    
    def _save_cache(self, data: Dict):
        """Save update cache."""
        self.update_cache.write_text(json.dumps(data, indent=2))
    
    def _load_config(self) -> Dict:
        """Load updater configuration."""
        config_file = self.config_dir / 'config.json'
        if config_file.exists():
            return json.loads(config_file.read_text())
        return {}
    
    def _save_config(self, config: Dict):
        """Save updater configuration."""
        config_file = self.config_dir / 'config.json'
        config_file.write_text(json.dumps(config, indent=2))


def check_updates_on_startup():
    """
    Check for updates on CLI startup.
    Called from mighty_mcp.py
    """
    updater = SecurityUpdater()
    updates = updater.auto_update_check()
    
    if updates:
        print("🔄 Updates available:")
        if updates['code_update']:
            print(f"  • Code: {updates['current_version']} → {updates['latest_version']}")
        if updates['signature_update']:
            print("  • New threat signatures available")
        if updates['pattern_update']:
            print("  • New detection patterns available")
        
        print("\nRun 'mighty-mcp update' to update\n")
        
        return updates
    
    return None


if __name__ == '__main__':
    # Manual update check
    updater = SecurityUpdater()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        print("🔄 Updating secure-toolings...")
        results = updater.update_all()
        
        if results['success']:
            print("✅ Update successful!")
            print(f"   Updated: {', '.join(results['updated'])}")
        else:
            print("❌ Update failed:")
            for failure in results['failed']:
                print(f"   • {failure}")
    else:
        updates = updater.check_for_updates(force=True)
        
        if updates['code_update'] or updates['signature_update'] or updates['pattern_update']:
            print("🔄 Updates available:")
            if updates['code_update']:
                print(f"  • Code: {updates['current_version']} → {updates['latest_version']}")
            if updates['signature_update']:
                print("  • New threat signatures")
            if updates['pattern_update']:
                print("  • New detection patterns")
        else:
            print("✅ Everything up to date!")