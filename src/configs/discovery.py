"""
MCP client configuration discovery.

Improvements over mcp-scan:
- More client support
- Better platform detection
- Async operations
- Config validation
"""

import json
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Any
import asyncio


class ConfigDiscovery:
    """
    Discover and parse MCP client configurations.
    
    Features:
    - Auto-discovery of known clients
    - Platform-specific path handling
    - Custom config search
    - Config validation
    """
    
    # Known client configuration locations
    CLIENT_CONFIGS = {
        'claude': {
            'darwin': [
                '~/Library/Application Support/Claude/claude_desktop_config.json'
            ],
            'linux': [
                '~/.config/Claude/claude_desktop_config.json',
                '~/.claude/config.json'
            ],
            'win32': [
                '%APPDATA%/Claude/claude_desktop_config.json',
                '%LOCALAPPDATA%/Claude/claude_desktop_config.json'
            ]
        },
        'cursor': {
            'darwin': [
                '~/.cursor/mcp/config.json',
                '~/.cursor/config.json'
            ],
            'linux': [
                '~/.cursor/mcp/config.json',
                '~/.cursor/config.json',
                '~/.config/cursor/mcp/config.json'
            ],
            'win32': [
                '%USERPROFILE%/.cursor/mcp/config.json',
                '%USERPROFILE%/.cursor/config.json',
                '%APPDATA%/Cursor/mcp/config.json'
            ]
        },
        'windsurf': {
            'darwin': [
                '~/.windsurf/mcp/config.json',
                '~/.windsurf/config.json'
            ],
            'linux': [
                '~/.windsurf/mcp/config.json',
                '~/.windsurf/config.json',
                '~/.config/windsurf/mcp/config.json'
            ],
            'win32': [
                '%USERPROFILE%/.windsurf/mcp/config.json',
                '%USERPROFILE%/.windsurf/config.json',
                '%APPDATA%/Windsurf/mcp/config.json'
            ]
        },
        'vscode': {
            'darwin': [
                '~/.vscode/extensions/mcp/config.json',
                '~/Library/Application Support/Code/User/mcp/config.json'
            ],
            'linux': [
                '~/.vscode/extensions/mcp/config.json',
                '~/.config/Code/User/mcp/config.json',
                '~/.config/VSCode/User/mcp/config.json'
            ],
            'win32': [
                '%APPDATA%/Code/User/mcp/config.json',
                '%USERPROFILE%/.vscode/extensions/mcp/config.json'
            ]
        },
        'zed': {
            'darwin': [
                '~/Library/Application Support/Zed/settings.json',
                '~/.config/zed/settings.json'
            ],
            'linux': [
                '~/.config/zed/settings.json'
            ],
            'win32': [
                '%APPDATA%/Zed/settings.json'
            ]
        },
        'neovim': {
            'darwin': [
                '~/.config/nvim/mcp.json',
                '~/.nvim/mcp.json'
            ],
            'linux': [
                '~/.config/nvim/mcp.json',
                '~/.nvim/mcp.json'
            ],
            'win32': [
                '%LOCALAPPDATA%/nvim/mcp.json',
                '%USERPROFILE%/.nvim/mcp.json'
            ]
        }
    }
    
    def __init__(self):
        """Initialize configuration discovery"""
        self.platform = self._detect_platform()
        self.discovered_configs: List[Dict] = []
    
    def _detect_platform(self) -> str:
        """Detect current platform"""
        
        system = platform.system().lower()
        
        if system == 'darwin':
            return 'darwin'
        elif system.startswith('win'):
            return 'win32'
        else:
            return 'linux'
    
    async def discover_all(self) -> List[Dict]:
        """
        Discover all MCP configurations.
        
        Returns:
            List of discovered configurations
        """
        
        configs = []
        
        # Check known client locations
        for client_name, client_paths in self.CLIENT_CONFIGS.items():
            paths = client_paths.get(self.platform, [])
            
            for path_str in paths:
                path = self._expand_path(path_str)
                
                if path.exists():
                    config = await self._load_and_validate(path)
                    
                    if config:
                        configs.append({
                            'client': client_name,
                            'path': str(path),
                            'config': config,
                            'valid': True,
                            'platform': self.platform,
                            'version': self._detect_client_version(client_name)
                        })
        
        # Search for custom configurations
        custom_configs = await self._find_custom_configs()
        configs.extend(custom_configs)
        
        self.discovered_configs = configs
        return configs
    
    async def discover_client(self, client_name: str) -> Optional[Dict]:
        """
        Discover configuration for specific client.
        
        Args:
            client_name: Name of the client
        
        Returns:
            Configuration if found
        """
        
        if client_name not in self.CLIENT_CONFIGS:
            return None
        
        paths = self.CLIENT_CONFIGS[client_name].get(self.platform, [])
        
        for path_str in paths:
            path = self._expand_path(path_str)
            
            if path.exists():
                config = await self._load_and_validate(path)
                
                if config:
                    return {
                        'client': client_name,
                        'path': str(path),
                        'config': config,
                        'valid': True,
                        'platform': self.platform,
                        'version': self._detect_client_version(client_name)
                    }
        
        return None
    
    async def _find_custom_configs(self) -> List[Dict]:
        """Find custom MCP configurations"""
        
        custom_configs = []
        
        # Common search locations
        search_paths = [
            Path.home() / '.mcp',
            Path.home() / '.config' / 'mcp',
            Path.cwd() / '.mcp',
            Path.cwd() / 'mcp.json',
            Path.cwd() / '.mcp.json'
        ]
        
        # Add environment-based paths
        if 'MCP_CONFIG' in os.environ:
            search_paths.append(Path(os.environ['MCP_CONFIG']))
        
        if 'MCP_CONFIG_DIR' in os.environ:
            config_dir = Path(os.environ['MCP_CONFIG_DIR'])
            search_paths.extend(config_dir.glob('*.json'))
        
        for search_path in search_paths:
            if search_path.is_file():
                config = await self._load_and_validate(search_path)
                
                if config:
                    custom_configs.append({
                        'client': 'custom',
                        'path': str(search_path),
                        'config': config,
                        'valid': True,
                        'platform': self.platform,
                        'version': 'unknown'
                    })
            
            elif search_path.is_dir():
                # Search for JSON files in directory
                for json_file in search_path.glob('**/*.json'):
                    if json_file.name.startswith('.'):
                        continue  # Skip hidden files
                    
                    config = await self._load_and_validate(json_file)
                    
                    if config:
                        custom_configs.append({
                            'client': 'custom',
                            'path': str(json_file),
                            'config': config,
                            'valid': True,
                            'platform': self.platform,
                            'version': 'unknown'
                        })
        
        return custom_configs
    
    def _expand_path(self, path_str: str) -> Path:
        """Expand environment variables and ~ in path"""
        
        if self.platform == 'win32':
            # Expand Windows environment variables
            path_str = os.path.expandvars(path_str)
        
        # Expand home directory
        return Path(path_str).expanduser()
    
    async def _load_and_validate(self, path: Path) -> Optional[Dict]:
        """Load and validate MCP configuration"""
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            # Validate MCP configuration structure
            if self._is_valid_mcp_config(data):
                return data
            
            return None
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"Failed to load config from {path}: {e}")
            return None
    
    def _is_valid_mcp_config(self, data: Any) -> bool:
        """Check if data is a valid MCP configuration"""
        
        if not isinstance(data, dict):
            return False
        
        # Check for MCP server definitions
        if 'mcpServers' in data:
            return isinstance(data['mcpServers'], dict)
        
        if 'servers' in data:
            return isinstance(data['servers'], dict)
        
        # Check for Zed-style configuration
        if 'language_models' in data and 'mcp' in data:
            return True
        
        return False
    
    def _detect_client_version(self, client_name: str) -> str:
        """Detect installed client version"""
        
        version_commands = {
            'claude': {
                'darwin': ['/Applications/Claude.app/Contents/MacOS/Claude', '--version'],
                'linux': ['claude', '--version'],
                'win32': ['claude.exe', '--version']
            },
            'cursor': {
                'darwin': ['/Applications/Cursor.app/Contents/MacOS/Cursor', '--version'],
                'linux': ['cursor', '--version'],
                'win32': ['cursor.exe', '--version']
            },
            'vscode': {
                'darwin': ['code', '--version'],
                'linux': ['code', '--version'],
                'win32': ['code.exe', '--version']
            }
        }
        
        if client_name in version_commands:
            commands = version_commands[client_name].get(self.platform, [])
            
            if commands:
                try:
                    import subprocess
                    result = subprocess.run(
                        commands,
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if result.returncode == 0:
                        # Extract version from output
                        lines = result.stdout.strip().split('\n')
                        if lines:
                            return lines[0].strip()
                except:
                    pass
        
        return 'unknown'
    
    def get_client_info(self, config_path: str) -> Dict:
        """Get client information from config path"""
        
        for client_name, client_paths in self.CLIENT_CONFIGS.items():
            paths = client_paths.get(self.platform, [])
            
            for path_str in paths:
                expanded = str(self._expand_path(path_str))
                
                if expanded == config_path or Path(expanded) == Path(config_path):
                    return {
                        'name': client_name,
                        'version': self._detect_client_version(client_name),
                        'platform': self.platform
                    }
        
        return {
            'name': 'unknown',
            'version': 'unknown',
            'platform': self.platform
        }
    
    def get_servers_from_config(self, config: Dict) -> Dict[str, Dict]:
        """Extract server definitions from configuration"""
        
        servers = {}
        
        # Standard format
        if 'mcpServers' in config:
            servers.update(config['mcpServers'])
        
        if 'servers' in config:
            servers.update(config['servers'])
        
        # Zed format
        if 'mcp' in config and 'servers' in config['mcp']:
            servers.update(config['mcp']['servers'])
        
        return servers
    
    def get_summary(self) -> Dict:
        """Get discovery summary"""
        
        summary = {
            'platform': self.platform,
            'discovered_count': len(self.discovered_configs),
            'clients': {},
            'total_servers': 0
        }
        
        for config in self.discovered_configs:
            client = config['client']
            
            if client not in summary['clients']:
                summary['clients'][client] = {
                    'count': 0,
                    'servers': 0,
                    'paths': []
                }
            
            summary['clients'][client]['count'] += 1
            summary['clients'][client]['paths'].append(config['path'])
            
            # Count servers
            servers = self.get_servers_from_config(config['config'])
            server_count = len(servers)
            summary['clients'][client]['servers'] += server_count
            summary['total_servers'] += server_count
        
        return summary