"""
Mighty MCP Security - Gateway Module.

Security gateway for wrapping MCP servers with monitoring:
- Support for multiple transport types (stdio, HTTP, SSE)
- Robust error handling
- Async operations for performance
- Clean abstraction layer
"""

import json
import os
import shutil
from dataclasses import dataclass


@dataclass
class GatewayConfig:
    """Configuration for gateway injection"""
    api_key: str | None = None
    api_url: str = "http://localhost:8888"
    project_name: str = "secure-mcp"
    push_explorer: bool = False
    source_dir: str | None = None
    strict_mode: bool = False


class SecurityGateway:
    """
    Wraps MCP servers with security monitoring.
    
    Improvements:
    - Async operations for better performance
    - Support for stdio, SSE, and HTTP transports
    - Automatic backup and restore
    - Better error recovery
    """

    def __init__(self, config: GatewayConfig | None = None):
        self.config = config or GatewayConfig()
        self.wrapped_configs: dict[str, str] = {}  # path -> backup_path

    async def inject(self, config_path: str) -> bool:
        """
        Inject gateway into MCP configuration.
        
        Returns True if injection was successful.
        """
        config_path = os.path.expanduser(config_path)

        # Check if already wrapped
        if config_path in self.wrapped_configs:
            print(f"Config already wrapped: {config_path}")
            return False

        try:
            # Create backup
            backup_path = await self._backup_config(config_path)

            # Load config
            with open(config_path) as f:
                config = json.load(f)

            # Wrap servers
            modified = False
            servers = config.get('mcpServers', {})

            for name, server in servers.items():
                wrapped = await self._wrap_server(name, server)
                if wrapped != server:
                    servers[name] = wrapped
                    modified = True

            if modified:
                # Save modified config
                config['mcpServers'] = servers
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)

                # Track wrapped config
                self.wrapped_configs[config_path] = backup_path

                return True
            else:
                # No changes needed, remove backup
                os.remove(backup_path)
                return False

        except Exception as e:
            print(f"Failed to inject gateway: {e}")
            # Restore backup if it exists
            if config_path in self.wrapped_configs:
                await self._restore_config(config_path)
            return False

    async def _wrap_server(self, name: str, server: dict) -> dict:
        """Wrap individual server configuration"""

        # Check if already wrapped
        if self._is_wrapped(server):
            return server

        # Handle different transport types
        if 'command' in server:
            # stdio transport
            return await self._wrap_stdio_server(name, server)
        elif 'url' in server:
            # HTTP/SSE transport
            return await self._wrap_http_server(name, server)
        else:
            # Unknown transport type
            print(f"Unknown transport type for server {name}")
            return server

    async def _wrap_stdio_server(self, name: str, server: dict) -> dict:
        """Wrap stdio-based server"""
        # Simpler approach - just add environment variables
        # The proxy will handle the actual interception
        wrapped = server.copy()

        wrapped['env'] = {
            **server.get('env', {}),
            'SECURE_MCP_API_URL': self.config.api_url,
            'SECURE_MCP_SERVER': name,
            'SECURE_MCP_WRAPPED': 'true'
        }

        if self.config.api_key:
            wrapped['env']['SECURE_MCP_API_KEY'] = self.config.api_key

        # Add marker for identification
        wrapped['__secure_mcp__'] = True

        return wrapped

    async def _wrap_http_server(self, name: str, server: dict) -> dict:
        """Wrap HTTP/SSE-based server"""
        original_url = server['url']

        # Proxy through our server
        wrapped = {
            'url': f"{self.config.api_url}/proxy/http",
            'headers': {
                **server.get('headers', {}),
                'X-Original-URL': original_url,
                'X-Server-Name': name
            }
        }

        if self.config.api_key:
            wrapped['headers']['X-API-Key'] = self.config.api_key

        # Keep other properties
        if 'transport' in server:
            wrapped['transport'] = server['transport']

        return wrapped

    def _is_wrapped(self, server: dict) -> bool:
        """Check if server is already wrapped"""

        # Check for our marker
        if server.get('__secure_mcp__'):
            return True

        # Check environment variables
        env = server.get('env', {})
        if 'SECURE_MCP_WRAPPED' in env:
            return True

        # Check URL-based wrapping
        url = server.get('url', '')
        if self.config.api_url in url or 'localhost:8888' in url:
            return True

        return False

    async def _backup_config(self, config_path: str) -> str:
        """Create backup of configuration file"""
        backup_path = f"{config_path}.backup"

        # Use numbered backups if backup already exists
        counter = 1
        while os.path.exists(backup_path):
            backup_path = f"{config_path}.backup.{counter}"
            counter += 1

        shutil.copy2(config_path, backup_path)
        return backup_path

    async def _restore_config(self, config_path: str):
        """Restore configuration from backup"""
        if config_path not in self.wrapped_configs:
            return

        backup_path = self.wrapped_configs[config_path]
        if os.path.exists(backup_path):
            shutil.move(backup_path, config_path)

        del self.wrapped_configs[config_path]

    async def cleanup(self):
        """Remove all gateway injections and restore original configs"""
        print(f"Cleaning up {len(self.wrapped_configs)} wrapped configs...")

        for config_path in list(self.wrapped_configs.keys()):
            try:
                await self._restore_config(config_path)
                print(f"✅ Restored: {config_path}")
            except Exception as e:
                print(f"⚠️ Failed to restore {config_path}: {e}")

        self.wrapped_configs.clear()

    async def is_gateway_installed(self, config_path: str) -> bool:
        """Check if gateway is installed in config"""
        try:
            with open(config_path) as f:
                config = json.load(f)

            servers = config.get('mcpServers', {})
            for server in servers.values():
                if self._is_wrapped(server):
                    return True

            return False
        except OSError:
            return False
