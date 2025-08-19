"""
Real-time monitoring command for MCP servers.

This combines mcp-scan's proxy approach with our enhanced analyzers.
"""

import asyncio
from pathlib import Path

import click

from ..runtime.activity_logger import OutputFormat


@click.command('monitor')
@click.option('--port', default=8888, help='Proxy server port')
@click.option('--format',
              type=click.Choice(['oneline', 'compact', 'full', 'json']),
              default='compact',
              help='Output format')
@click.option('--config', help='Path to configuration file')
@click.option('--inject/--no-inject', default=True,
              help='Auto-inject gateway into MCP configs')
@click.option('--clients', multiple=True,
              help='Specific clients to monitor (claude, cursor, etc)')
@click.option('--strict', is_flag=True,
              help='Enable strict mode (block by default)')
@click.option('--enable-llm', is_flag=True,
              help='Enable LLM analysis (requires Cerebras API)')
@click.option('--enable-ml', is_flag=True,
              help='Enable ML-based anomaly detection')
@click.option('--log-file', help='Path to log file')
def monitor_command(port: int, format: str, config: str | None,
                   inject: bool, clients: tuple, strict: bool,
                   enable_llm: bool, enable_ml: bool, log_file: str | None):
    """
    Start real-time MCP security monitoring proxy.
    
    This command:
    - Discovers MCP client configurations
    - Injects security gateway
    - Starts proxy server
    - Monitors and analyzes all MCP traffic
    
    Examples:
        # Monitor all discovered clients
        secure-mcp monitor
        
        # Monitor specific client with strict mode
        secure-mcp monitor --clients claude --strict
        
        # Enable all analyzers
        secure-mcp monitor --enable-llm --enable-ml
        
        # JSON output for automation
        secure-mcp monitor --format json --log-file monitor.log
    """

    click.echo(f"🚀 Starting Secure-MCP Monitor on port {port}")

    # Import monitoring components only when needed
    from ..runtime.injector import GatewayInjector
    from ..runtime.proxy_server import MCPProxyServer

    # Create proxy with configuration
    proxy = MCPProxyServer(config_path=config, port=port)

    # Set output format
    proxy.logger.format = OutputFormat[format.upper()]

    # Configure log file
    if log_file:
        proxy.logger.log_file = Path(log_file)

    # Configure analyzers
    if enable_llm:
        click.echo("✅ LLM analysis enabled (Cerebras)")
        proxy.analyzer.cerebras = True

    if enable_ml:
        click.echo("✅ ML anomaly detection enabled")
        proxy.analyzer.ml_analyzer = True

    # Configure strict mode
    if strict:
        click.echo("⚠️ Strict mode enabled - blocking by default")
        proxy.config['policies']['default_action'] = 'block'

    # Handle gateway injection
    if inject:
        injector = GatewayInjector(proxy_url=f"http://localhost:{port}")

        async def inject_and_monitor():
            # Discover configs
            configs = await proxy.discovery.discover_all()

            # Filter by clients if specified
            if clients:
                configs = [c for c in configs if c['client'] in clients]

            click.echo(f"📦 Found {len(configs)} configurations")

            # Inject gateway
            injected = 0
            for config in configs:
                try:
                    if await injector.inject(config['path']):
                        injected += 1
                        click.echo(f"  ✅ Injected into {config['client']}")
                except Exception as e:
                    click.echo(f"  ⚠️ Failed to inject into {config['client']}: {e}")

            click.echo(f"📊 Injected gateway into {injected}/{len(configs)} configs")

            # Start proxy
            try:
                await proxy.start()
            except KeyboardInterrupt:
                click.echo("\n🛑 Shutting down...")
            finally:
                # Cleanup
                await injector.cleanup()
                await proxy.stop()

                # Show summary
                if proxy.logger:
                    await proxy.logger.display_summary()

        # Run with injection
        asyncio.run(inject_and_monitor())
    else:
        # Run without injection (assume already configured)
        async def monitor_only():
            try:
                await proxy.start()
            except KeyboardInterrupt:
                click.echo("\n🛑 Shutting down...")
            finally:
                await proxy.stop()

                # Show summary
                if proxy.logger:
                    await proxy.logger.display_summary()

        asyncio.run(monitor_only())

    click.echo("✅ Monitor stopped successfully")
