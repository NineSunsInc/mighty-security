"""
Mighty MCP Security - Gateway Injector.

Safe and reversible MCP configuration modification:
- Automated backup management
- Atomic operations for safety
- Multi-transport support (stdio, HTTP, SSE)
- Context manager support for temporary injection
"""

import asyncio
import json
import os
import shutil
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path


class GatewayInjector:
    """
    Safely inject security gateway into MCP configs.
    
    Features:
    - Automatic backup and restore
    - Support for all transport types
    - Atomic operations
    - Context manager support
    """

    def __init__(self, proxy_url: str = "http://localhost:8888"):
        self.proxy_url = proxy_url
        self.backups: dict[str, str] = {}  # config_path -> backup_path
        self.modified_configs: list[str] = []
        self.injection_log: list[dict] = []

    async def inject(self, config_path: str, options: dict = None) -> bool:
        """
        Inject gateway into config file.
        
        Args:
            config_path: Path to MCP configuration file
            options: Optional injection options
        
        Returns:
            True if injection was successful
        """
        config_path = os.path.expanduser(config_path)
        options = options or {}

        try:
            # Create backup first
            backup_path = await self._create_backup(config_path)
            self.backups[config_path] = backup_path

            # Load configuration
            with open(config_path) as f:
                config = json.load(f)

            # Track modifications
            modifications = []

            # Process servers
            servers = config.get('mcpServers', {})
            for server_name, server_config in servers.items():

                # Skip if already wrapped
                if self._is_wrapped(server_config):
                    continue

                # Wrap based on transport type
                wrapped = await self._wrap_server(
                    server_name,
                    server_config,
                    options
                )

                if wrapped != server_config:
                    servers[server_name] = wrapped
                    modifications.append({
                        'server': server_name,
                        'transport': self._get_transport_type(server_config),
                        'timestamp': datetime.now().isoformat()
                    })

            if modifications:
                # Update config
                config['mcpServers'] = servers

                # Add metadata
                if '__secure_mcp__' not in config:
                    config['__secure_mcp__'] = {}

                config['__secure_mcp__'].update({
                    'injected': True,
                    'timestamp': datetime.now().isoformat(),
                    'proxy_url': self.proxy_url,
                    'backup_path': backup_path
                })

                # Write atomically
                await self._write_config_atomic(config_path, config)

                # Track modifications
                self.modified_configs.append(config_path)
                self.injection_log.append({
                    'config': config_path,
                    'modifications': modifications,
                    'timestamp': datetime.now().isoformat()
                })

                return True
            else:
                # No changes needed, remove backup
                os.remove(backup_path)
                del self.backups[config_path]
                return False

        except Exception as e:
            # Restore on error
            if config_path in self.backups:
                await self._restore_backup(config_path)
            raise Exception(f"Failed to inject gateway: {e}")

    async def remove(self, config_path: str) -> bool:
        """
        Remove gateway injection from config.
        
        Returns:
            True if removal was successful
        """
        config_path = os.path.expanduser(config_path)

        try:
            # Check if config has our metadata
            with open(config_path) as f:
                config = json.load(f)

            if '__secure_mcp__' not in config:
                return False

            metadata = config['__secure_mcp__']

            # Restore from backup if available
            if 'backup_path' in metadata and os.path.exists(metadata['backup_path']):
                shutil.move(metadata['backup_path'], config_path)

                # Clean up tracking
                if config_path in self.backups:
                    del self.backups[config_path]
                if config_path in self.modified_configs:
                    self.modified_configs.remove(config_path)

                return True

            # Manual unwrapping if no backup
            servers = config.get('mcpServers', {})
            for server_name, server_config in servers.items():
                if self._is_wrapped(server_config):
                    unwrapped = await self._unwrap_server(server_config)
                    servers[server_name] = unwrapped

            # Remove metadata
            del config['__secure_mcp__']

            # Write config
            await self._write_config_atomic(config_path, config)

            return True

        except Exception as e:
            raise Exception(f"Failed to remove gateway: {e}")

    async def _wrap_server(self, name: str, server: dict, options: dict) -> dict:
        """Wrap server configuration with gateway"""

        transport = self._get_transport_type(server)

        if transport == 'stdio':
            return self._wrap_stdio_server(name, server, options)
        elif transport == 'http':
            return self._wrap_http_server(name, server, options)
        elif transport == 'sse':
            return self._wrap_sse_server(name, server, options)
        else:
            # Unknown transport, return unchanged
            return server

    def _wrap_stdio_server(self, name: str, server: dict, options: dict) -> dict:
        """Wrap stdio transport server"""

        # For now, we'll modify the environment to include proxy info
        # The actual interception will happen at the proxy level
        # This is simpler than creating a separate wrapper module

        wrapped = server.copy()

        # Add proxy environment variables
        wrapped['env'] = wrapped.get('env', {}).copy()
        wrapped['env'].update({
            'SECURE_MCP_PROXY_URL': self.proxy_url,
            'SECURE_MCP_SERVER_NAME': name,
            'SECURE_MCP_WRAPPED': 'true',
            'SECURE_MCP_ORIGINAL_COMMAND': server.get('command', ''),
            'SECURE_MCP_STRICT': str(options.get('strict', False))
        })

        # Store original config for unwrapping
        if 'args' in server:
            wrapped['env']['SECURE_MCP_ORIGINAL_ARGS'] = json.dumps(server['args'])

        # Add a marker to identify wrapped servers
        wrapped['__secure_mcp_wrapped__'] = True

        return wrapped

    def _wrap_http_server(self, name: str, server: dict, options: dict) -> dict:
        """Wrap HTTP transport server"""

        original_url = server['url']

        wrapped = {
            'url': f"{self.proxy_url}/proxy/forward",
            'transport': 'http'
        }

        # Add headers for proxying
        headers = server.get('headers', {}).copy()
        headers.update({
            'X-Secure-MCP-Original-URL': original_url,
            'X-Secure-MCP-Server-Name': name,
            'X-Secure-MCP-Transport': 'http'
        })

        if options.get('api_key'):
            headers['X-Secure-MCP-API-Key'] = options['api_key']

        wrapped['headers'] = headers

        return wrapped

    def _wrap_sse_server(self, name: str, server: dict, options: dict) -> dict:
        """Wrap SSE transport server"""

        original_url = server['url']

        wrapped = {
            'url': f"{self.proxy_url}/proxy/sse",
            'transport': 'sse'
        }

        # Add headers for proxying
        headers = server.get('headers', {}).copy()
        headers.update({
            'X-Secure-MCP-Original-URL': original_url,
            'X-Secure-MCP-Server-Name': name,
            'X-Secure-MCP-Transport': 'sse'
        })

        if options.get('api_key'):
            headers['X-Secure-MCP-API-Key'] = options['api_key']

        wrapped['headers'] = headers

        return wrapped

    async def _unwrap_server(self, server: dict) -> dict:
        """Unwrap a wrapped server configuration"""

        # Check for our wrapper marker
        if server.get('__secure_mcp_wrapped__'):
            unwrapped = server.copy()

            # Remove wrapper marker
            del unwrapped['__secure_mcp_wrapped__']

            # Clean environment variables
            if 'env' in unwrapped:
                env = unwrapped['env'].copy()
                # Remove our injected variables
                for key in list(env.keys()):
                    if key.startswith('SECURE_MCP_'):
                        del env[key]

                if env:
                    unwrapped['env'] = env
                else:
                    del unwrapped['env']

            return unwrapped

        # For HTTP/SSE servers
        if 'headers' in server:
            headers = server['headers']
            if 'X-Secure-MCP-Original-URL' in headers:
                unwrapped = {
                    'url': headers['X-Secure-MCP-Original-URL']
                }

                # Restore transport
                if 'X-Secure-MCP-Transport' in headers:
                    unwrapped['transport'] = headers['X-Secure-MCP-Transport']

                # Clean headers
                clean_headers = {
                    k: v for k, v in headers.items()
                    if not k.startswith('X-Secure-MCP-')
                }

                if clean_headers:
                    unwrapped['headers'] = clean_headers

                return unwrapped

        # Can't unwrap, return as-is
        return server

    def _is_wrapped(self, server: dict) -> bool:
        """Check if server is already wrapped"""

        # Check for our wrapper marker
        if server.get('__secure_mcp_wrapped__'):
            return True

        # Check environment variables for stdio servers
        env = server.get('env', {})
        if 'SECURE_MCP_WRAPPED' in env:
            return True

        # Check HTTP/SSE wrapping
        url = server.get('url', '')
        if self.proxy_url in url:
            return True

        # Check headers
        headers = server.get('headers', {})
        if any(k.startswith('X-Secure-MCP-') for k in headers):
            return True

        return False

    def _get_transport_type(self, server: dict) -> str:
        """Determine transport type of server"""

        if 'command' in server:
            return 'stdio'
        elif 'transport' in server:
            return server['transport']
        elif 'url' in server:
            # Guess based on URL
            if 'sse' in server['url'].lower():
                return 'sse'
            return 'http'

        return 'unknown'

    async def _create_backup(self, config_path: str) -> str:
        """Create backup of configuration file"""

        # Generate unique backup name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = Path(config_path).parent / '.secure-mcp-backups'
        backup_dir.mkdir(exist_ok=True)

        backup_name = f"{Path(config_path).name}.{timestamp}.backup"
        backup_path = backup_dir / backup_name

        # Copy with metadata preservation
        shutil.copy2(config_path, backup_path)

        return str(backup_path)

    async def _restore_backup(self, config_path: str):
        """Restore configuration from backup"""

        if config_path not in self.backups:
            raise ValueError(f"No backup found for {config_path}")

        backup_path = self.backups[config_path]

        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        # Restore
        shutil.move(backup_path, config_path)

        # Clean up tracking
        del self.backups[config_path]
        if config_path in self.modified_configs:
            self.modified_configs.remove(config_path)

    async def _write_config_atomic(self, config_path: str, config: dict):
        """Write configuration atomically"""

        # Write to temp file first
        temp_path = f"{config_path}.tmp"

        with open(temp_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Atomic rename
        os.replace(temp_path, config_path)

    async def cleanup(self):
        """Restore all original configurations"""

        for config_path in list(self.modified_configs):
            try:
                await self.remove(config_path)
                print(f"✅ Restored: {config_path}")
            except Exception as e:
                print(f"⚠️ Failed to restore {config_path}: {e}")

    def get_status(self) -> dict:
        """Get injection status"""

        return {
            'modified_configs': self.modified_configs,
            'backup_count': len(self.backups),
            'injection_log': self.injection_log
        }

    @contextmanager
    def temporary_injection(self, config_paths: list[str], options: dict = None):
        """Context manager for temporary gateway injection"""

        injected = []

        try:
            # Inject gateways
            for path in config_paths:
                if asyncio.run(self.inject(path, options)):
                    injected.append(path)

            yield self

        finally:
            # Always cleanup
            for path in injected:
                try:
                    asyncio.run(self.remove(path))
                except Exception:
                    pass
