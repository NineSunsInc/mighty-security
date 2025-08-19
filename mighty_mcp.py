#!/usr/bin/env python3
"""
Mighty MCP Security - Unified Security Suite for Model Context Protocol

Simple, powerful API for MCP security:
    from mighty_mcp import check_tool, scan_system
    
    risk = await check_tool(tool_definition)
    if risk.should_block:
        print(f"Blocked: {risk.reason}")
"""

import asyncio
import sys
from pathlib import Path

import click

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# ============================================================================
# SIMPLIFIED PUBLIC API
# ============================================================================

class MightySecurity:
    """
    Unified security interface - ONE class for everything.
    
    Example:
        security = MightySecurity()
        result = await security.check_tool(tool_definition)
    """

    def __init__(self, config: dict | None = None):
        """Initialize with optional configuration."""
        self.config = config or {}
        self._analyzer = None
        self._monitor = None
        self._policies = None

    @property
    def analyzer(self):
        """Lazy load unified analyzer."""
        if not self._analyzer:
            from src.core.unified_analyzer import UnifiedAnalyzer
            self._analyzer = UnifiedAnalyzer(self.config)
        return self._analyzer

    @property
    def monitor(self):
        """Lazy load runtime monitor."""
        if not self._monitor:
            try:
                from src.runtime.proxy_server import MCPProxyServer
                self._monitor = MCPProxyServer(self.config)
            except ImportError:
                self._monitor = None
        return self._monitor

    @property
    def policies(self):
        """Lazy load policy engine."""
        if not self._policies:
            from src.policies.manager import PolicyManager
            self._policies = PolicyManager(self.config.get('policy_file'))
        return self._policies

    async def check_tool(self, tool: dict) -> dict:
        """
        Check a single tool for security issues.
        
        Args:
            tool: Tool definition with name, description, parameters, etc.
            
        Returns:
            Dict with threat_level, reason, should_block, details
        """
        return await self.analyzer.analyze(tool)

    async def check_batch(self, tools: list[dict]) -> list[dict]:
        """Check multiple tools efficiently."""
        tasks = [self.check_tool(tool) for tool in tools]
        return await asyncio.gather(*tasks)

    async def scan_system(self, client: str | None = None) -> dict:
        """
        Scan all MCP configurations on the system.
        
        Args:
            client: Optional specific client to scan (claude, cursor, etc.)
            
        Returns:
            Comprehensive security report
        """
        from src.configs.discovery import ConfigDiscovery
        discovery = ConfigDiscovery()
        configs = await discovery.discover_all()

        if client:
            configs = [c for c in configs if c['client'] == client]

        results = {
            'configs_scanned': len(configs),
            'threats': [],
            'by_client': {}
        }

        for config in configs:
            client_results = await self.analyzer.analyze_config(config)
            results['by_client'][config['client']] = client_results
            results['threats'].extend(client_results.get('threats', []))

        return results

    async def monitor_realtime(self, port: int = 8080) -> None:
        """
        Start real-time monitoring proxy.
        
        Args:
            port: Port to listen on
        """
        if not self.monitor:
            raise ImportError("Runtime monitoring requires: pip install mighty-mcp[monitor]")

        await self.monitor.start(port)

    def add_policy(self, policy: dict) -> None:
        """Add a custom security policy."""
        self.policies.create_policy(policy)

    async def generate_report(self, results: dict, format: str = 'json') -> str:
        """Generate a security report in various formats."""
        from src.report_generator import ReportGenerator
        generator = ReportGenerator()
        return generator.create(results, format)


# Convenience functions for simple use cases
async def check_tool(tool: dict) -> dict:
    """Quick tool check - no setup required."""
    security = MightySecurity()
    return await security.check_tool(tool)

async def scan_system(client: str | None = None) -> dict:
    """Quick system scan - no setup required."""
    security = MightySecurity()
    return await security.scan_system(client)

async def monitor(port: int = 8080) -> None:
    """Quick monitoring start - no setup required."""
    security = MightySecurity()
    await security.monitor_realtime(port)


# ============================================================================
# CLI INTERFACE (SIMPLIFIED)
# ============================================================================

@click.group()
@click.version_option(version='3.0.0')
@click.pass_context
def cli(ctx):
    """
    Mighty MCP Security - Secure by Default
    
    Quick Start:
        mighty-mcp check              # Scan your system
        mighty-mcp check --realtime    # Start monitoring
        mighty-mcp check file.py       # Analyze specific file
    """
    ctx.ensure_object(dict)
    ctx.obj['security'] = MightySecurity()


@cli.command('check')
@click.argument('target', required=False)
@click.option('--client', help='Check specific client (claude, cursor, etc.)')
@click.option('--realtime', is_flag=True, help='Start real-time monitoring')
@click.option('--deep', is_flag=True, help='Enable all analysis methods')
@click.option('--quick', is_flag=True, help='Fast scan only')
@click.option('--profile', type=click.Choice(['production', 'development', 'security-tool']),
              default='production', help='Scan profile (production excludes tests)')
@click.option('--include-tests', is_flag=True, help='Include test directories (overrides profile)')
@click.option('--no-context', is_flag=True, help='Disable context-aware analysis')
@click.option('--no-cache', is_flag=True, help='Force fresh scan, ignore cache')
@click.option('--debug', is_flag=True, help='Enable debug output for troubleshooting')
@click.option('--policy', type=click.Path(exists=True), help='Custom policy file')
@click.option('--output', '-o', help='Save report to file')
@click.option('--format', type=click.Choice(['json', 'text', 'markdown', 'sarif']),
              default='text', help='Output format')
@click.option('--port', default=8080, help='Port for monitoring (with --realtime)')
@click.pass_context
def check_command(ctx, target, client, realtime, deep, quick, profile, include_tests, no_context, no_cache, debug, policy, output, format, port):
    """
    Universal security check command.
    
    Examples:
        mighty-mcp check                    # Scan all MCP configs
        mighty-mcp check --client claude    # Scan specific client
        mighty-mcp check tool.py            # Analyze file
        mighty-mcp check --realtime         # Start monitoring
        mighty-mcp check --deep -o report   # Full analysis with report
    """
    from src.analyzers.url_utils import is_github_url, is_url

    security = ctx.obj['security']

    # Configure based on options
    if policy:
        security.config['policy_file'] = policy
    if deep:
        security.config['enable_all'] = True
    if quick:
        security.config['quick_mode'] = True
    if debug:
        security.config['debug'] = True
        import os
        os.environ['LLM_DEBUG'] = 'true'  # Set environment variable for LLM debug

    # Configure profile and context settings
    security.config['profile'] = profile
    if include_tests:
        security.config['profile'] = 'development'  # Override to development if including tests
    if no_context:
        security.config['context_aware'] = False
    else:
        security.config['context_aware'] = True

    async def run_check():
        # Real-time monitoring mode
        if realtime:
            click.echo(f"🛡️ Starting real-time monitoring on port {port}...")
            try:
                await security.monitor_realtime(port)
            except ImportError:
                click.echo("❌ Monitoring requires: pip install mighty-mcp[monitor]")
                return

        # Check if target is a URL (GitHub or otherwise)
        elif target and (is_github_url(target) or is_url(target)):
            click.echo(f"🔍 Analyzing repository: {target}...")

            # Use comprehensive analyzer for URL analysis
            from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
            analyzer = ComprehensiveMCPAnalyzer(
                deep_scan=not quick,
                enable_llm=deep,
                profile=security.config.get('profile', 'production')
            )
            result = analyzer.analyze_repository(target, no_cache=no_cache)
            display_results(result, format, output)

        # File/directory analysis
        elif target and Path(target).exists():
            click.echo(f"🔍 Analyzing {target}...")
            path = Path(target)

            if path.is_file():
                # Direct file analysis
                from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
                analyzer = ComprehensiveMCPAnalyzer(
                    deep_scan=not quick,
                    enable_llm=deep,
                    profile=security.config.get('profile', 'production')
                )
                result = analyzer.analyze_repository(str(path), no_cache=no_cache)
            else:
                # Directory scan using comprehensive analyzer with profile
                from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
                analyzer = ComprehensiveMCPAnalyzer(
                    deep_scan=not quick,
                    enable_llm=deep,
                    profile=security.config.get('profile', 'production')
                )
                result = analyzer.analyze_repository(str(path), no_cache=no_cache)

            display_results(result, format, output)

        # If target is provided but not a file/directory/URL, treat as potential URL
        elif target:
            # Might be a URL without protocol or a typo
            click.echo(f"🔍 Attempting to analyze: {target}...")

            from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
            analyzer = ComprehensiveMCPAnalyzer(
                deep_scan=not quick,
                enable_llm=deep,
                profile=security.config.get('profile', 'production')
            )
            result = analyzer.analyze_repository(target, no_cache=no_cache)
            display_results(result, format, output)

        # System scan
        else:
            click.echo("🔎 Scanning MCP configurations...")
            result = await security.scan_system(client)
            display_results(result, format, output)

    asyncio.run(run_check())


@cli.command('init')
@click.option('--force', is_flag=True, help='Overwrite existing configuration')
def init_command(force):
    """Initialize security configuration."""
    import json
    from pathlib import Path

    config_dir = Path.home() / '.mighty-mcp'
    config_dir.mkdir(exist_ok=True)

    # Create default configuration
    default_config = {
        'version': '3.0.0',
        'policies': {
            'block_secrets': True,
            'block_pii': True,
            'block_injection': True,
            'block_traversal': True
        },
        'monitoring': {
            'port': 8080,
            'log_level': 'INFO'
        },
        'analysis': {
            'enable_llm': False,
            'enable_ml': False,
            'cache_results': True
        }
    }

    config_file = config_dir / 'config.json'

    if config_file.exists() and not force:
        click.echo("⚠️ Configuration already exists. Use --force to overwrite.")
        return

    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=2)

    click.echo(f"✅ Configuration created at {config_file}")
    click.echo("   Run 'mighty-mcp check' to start scanning")


@cli.command('proxy')
@click.argument('configs', nargs=-1)
@click.option('--pretty', type=click.Choice(['oneline', 'compact', 'full']), default='compact', help='Output format')
@click.option('--port', default=8888, help='Proxy server port')
@click.option('--guardrails-config', type=click.Path(exists=True), help='Path to guardrails YAML config')
@click.pass_context
def proxy_command(ctx, configs, pretty, port, guardrails_config):
    """
    Run proxy server to monitor and guardrail MCP traffic.
    
    Similar to mcp-scan proxy but with our enhanced security features:
    - Real-time threat analysis before execution
    - Toxic flow detection
    - Behavioral pattern recognition
    - Guardrails enforcement from YAML config
    
    Examples:
        mighty-mcp proxy                           # Proxy all discovered configs
        mighty-mcp proxy ~/.claude/config.json     # Proxy specific config
        mighty-mcp proxy --pretty full --port 9000 # Custom settings
    """
    from src.configs.discovery import ConfigDiscovery
    from src.runtime.injector import GatewayInjector
    from src.runtime.proxy_server import MCPProxyServer

    async def run_proxy():
        # Discover configs if not specified
        if not configs:
            discovery = ConfigDiscovery()
            config_list = await discovery.find_all_configs()
        else:
            config_list = list(configs)

        if not config_list:
            click.echo("❌ No MCP configurations found")
            return

        # Initialize injector and proxy
        injector = GatewayInjector(proxy_url=f"http://localhost:{port}")
        proxy = MCPProxyServer(port=port)

        # Load guardrails if specified
        if guardrails_config:
            import yaml
            with open(guardrails_config) as f:
                guardrails = yaml.safe_load(f)
                proxy.policies.load_guardrails(guardrails)
            click.echo(f"✅ Loaded guardrails from {guardrails_config}")

        # Set output format
        proxy.config['logging']['format'] = pretty

        # Inject gateway into configurations
        click.echo("🔧 Installing security gateway...")
        injected = []

        for config_path in config_list:
            try:
                if await injector.inject(config_path):
                    injected.append(config_path)
                    click.echo(f"  ✅ Injected: {config_path}")
            except Exception as e:
                click.echo(f"  ⚠️ Failed to inject {config_path}: {e}")

        if not injected:
            click.echo("❌ No configurations could be wrapped")
            return

        click.echo(f"\n🛡️ Starting proxy server on port {port}")
        click.echo("Press Ctrl+C to stop\n")

        try:
            # Start proxy server
            await proxy.start()
        except KeyboardInterrupt:
            click.echo("\n⏹️ Shutting down proxy...")
        finally:
            # Always cleanup injections
            click.echo("🔧 Removing gateway from configurations...")
            await injector.cleanup()
            click.echo("✅ Gateway removed from all configurations")

    asyncio.run(run_proxy())


@cli.command('inspect')
@click.argument('configs', nargs=-1)
@click.option('--server-timeout', default=10, help='Server connection timeout')
@click.pass_context
def inspect_command(ctx, configs, server_timeout):
    """
    Inspect tools, prompts, and resources without verification.
    
    Shows the raw tool definitions from MCP servers.
    
    Examples:
        mighty-mcp inspect                    # Inspect all configs
        mighty-mcp inspect ~/.claude/config.json  # Inspect specific config
    """
    import json

    from src.configs.discovery import ConfigDiscovery

    async def run_inspect():
        # Discover configs if not specified
        if not configs:
            discovery = ConfigDiscovery()
            config_list = await discovery.find_all_configs()
        else:
            config_list = list(configs)

        for config_path in config_list:
            click.echo(f"\n📋 Configuration: {config_path}")

            try:
                with open(config_path) as f:
                    config = json.load(f)

                servers = config.get('mcpServers', {})

                for server_name, server_config in servers.items():
                    click.echo(f"\n  🔌 Server: {server_name}")

                    # Show server type
                    if 'command' in server_config:
                        click.echo("    Type: stdio")
                        click.echo(f"    Command: {server_config['command']}")
                    elif 'url' in server_config:
                        transport = server_config.get('transport', 'http')
                        click.echo(f"    Type: {transport}")
                        click.echo(f"    URL: {server_config['url']}")

                    # TODO: Connect to server and get tools
                    # This would require implementing MCP client
                    click.echo("    Tools: [Would connect to retrieve]")

            except Exception as e:
                click.echo(f"  ❌ Error: {e}")

    asyncio.run(run_inspect())


@cli.command('whitelist')
@click.argument('entity_type', required=False, type=click.Choice(['tool', 'prompt', 'resource']))
@click.argument('name', required=False)
@click.argument('hash_value', required=False)
@click.option('--reset', is_flag=True, help='Reset the whitelist')
@click.option('--list', 'show_list', is_flag=True, help='Show current whitelist')
@click.pass_context
def whitelist_command(ctx, entity_type, name, hash_value, reset, show_list):
    """
    Manage whitelist of approved entities.
    
    Examples:
        mighty-mcp whitelist --list           # Show whitelist
        mighty-mcp whitelist tool calc abc123  # Add tool to whitelist
        mighty-mcp whitelist --reset          # Clear whitelist
    """
    import json
    from pathlib import Path

    whitelist_file = Path.home() / '.mighty-mcp' / 'whitelist.json'
    whitelist_file.parent.mkdir(exist_ok=True)

    # Load existing whitelist
    whitelist = {}
    if whitelist_file.exists():
        with open(whitelist_file) as f:
            whitelist = json.load(f)

    if reset:
        whitelist = {}
        click.echo("🗑️ Whitelist reset")

    elif show_list or (not entity_type and not name):
        # Show whitelist
        if not whitelist:
            click.echo("📋 Whitelist is empty")
        else:
            click.echo("📋 Whitelisted Entities:")
            for etype, entities in whitelist.items():
                click.echo(f"\n  {etype}s:")
                for ename, ehash in entities.items():
                    click.echo(f"    • {ename}: {ehash[:16]}...")

    elif entity_type and name and hash_value:
        # Add to whitelist
        if entity_type not in whitelist:
            whitelist[entity_type] = {}
        whitelist[entity_type][name] = hash_value
        click.echo(f"✅ Added {entity_type} '{name}' to whitelist")

    else:
        click.echo("❌ Invalid arguments. Use --help for usage.")
        return

    # Save whitelist
    with open(whitelist_file, 'w') as f:
        json.dump(whitelist, f, indent=2)


@cli.command('update')
@click.option('--check', is_flag=True, help='Only check for updates')
@click.option('--force', is_flag=True, help='Force update check (bypass cache)')
@click.option('--code/--no-code', default=True, help='Update code')
@click.option('--signatures/--no-signatures', default=True, help='Update signatures')
@click.option('--patterns/--no-patterns', default=True, help='Update patterns')
@click.option('--auto-update', type=click.Choice(['on', 'off', 'status']), help='Configure auto-updates')
@click.pass_context
def update_command(ctx, check, force, code, signatures, patterns, auto_update):
    """
    Check for and install updates.
    
    Examples:
        mighty-mcp update --check      # Check for updates
        mighty-mcp update              # Install all updates
        mighty-mcp update --no-code    # Update signatures/patterns only
        mighty-mcp update --auto-update on  # Enable auto-update checks
    """
    from src.updater import SecurityUpdater

    updater = SecurityUpdater()

    # Handle auto-update configuration
    if auto_update:
        config_file = Path.home() / '.mighty-mcp' / 'config.json'
        config = {}
        if config_file.exists():
            with open(config_file) as f:
                config = json.load(f)

        if auto_update == 'status':
            enabled = config.get('auto_update', {}).get('enabled', True)
            frequency = config.get('auto_update', {}).get('frequency', 'daily')
            click.echo(f"Auto-update: {'✅ Enabled' if enabled else '❌ Disabled'}")
            click.echo(f"Frequency: {frequency}")
        elif auto_update == 'on':
            config['auto_update'] = {'enabled': True, 'frequency': 'daily'}
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            click.echo("✅ Auto-update enabled (daily checks)")
        else:  # off
            config['auto_update'] = {'enabled': False}
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            click.echo("❌ Auto-update disabled")
        return

    # Check for updates
    click.echo("🔍 Checking for updates...")
    updates = updater.check_for_updates(force=force)

    if not (updates['code_update'] or updates['signature_update'] or updates['pattern_update']):
        click.echo("✅ Everything is up to date!")
        return

    # Show available updates
    click.echo("\n📦 Available updates:")
    if updates['code_update']:
        click.echo(f"  • Code: {updates['current_version']} → {updates['latest_version']}")
    if updates['signature_update']:
        click.echo("  • New threat signatures available")
    if updates['pattern_update']:
        click.echo("  • New detection patterns available")

    if check:
        click.echo("\nRun 'mighty-mcp update' to install updates")
        return

    # Perform update
    if not click.confirm("\nProceed with update?"):
        return

    click.echo("\n🔄 Updating...")

    components = {
        'code': code and updates['code_update'],
        'signatures': signatures and updates['signature_update'],
        'patterns': patterns and updates['pattern_update']
    }

    results = updater.update_all(components)

    if results['success']:
        click.echo("\n✅ Update complete!")
        if results['updated']:
            click.echo(f"   Updated: {', '.join(results['updated'])}")
        if results['backup_path']:
            click.echo(f"   Backup saved: {results['backup_path']}")
    else:
        click.echo("\n❌ Update failed:")
        for failure in results['failed']:
            click.echo(f"   • {failure}")
        if results['backup_path']:
            click.echo("\n   Run 'mighty-mcp rollback' to restore previous version")


@cli.command('rollback')
@click.option('--backup', help='Specific backup to restore')
@click.pass_context
def rollback_command(ctx, backup):
    """
    Rollback to a previous version after failed update.
    
    Examples:
        mighty-mcp rollback           # Rollback to latest backup
        mighty-mcp rollback --backup /path/to/backup.tar.gz
    """
    from src.updater import SecurityUpdater

    updater = SecurityUpdater()

    if updater.rollback(backup):
        click.echo("✅ Rollback successful!")
    else:
        click.echo("❌ Rollback failed")


@cli.command('status')
@click.pass_context
def status_command(ctx):
    """Show security status and configuration."""
    async def show_status():
        security = ctx.obj['security']

        # Get system status
        from src.configs.discovery import ConfigDiscovery
        from src.signatures.manager import SignatureManager

        discovery = ConfigDiscovery()
        signatures = SignatureManager()

        configs = await discovery.discover_all()
        sig_report = await signatures.get_report()

        click.echo("🛡️ Mighty MCP Security Status")
        click.echo("=" * 50)

        click.echo("\n📦 MCP Configurations:")
        click.echo(f"  Clients Found: {len(set(c['client'] for c in configs))}")
        click.echo(f"  Total Configs: {len(configs)}")

        for client in set(c['client'] for c in configs):
            client_configs = [c for c in configs if c['client'] == client]
            click.echo(f"  - {client}: {len(client_configs)} config(s)")

        click.echo("\n🔐 Security Database:")
        click.echo(f"  Known Tools: {sig_report['total_tools']}")
        click.echo(f"  Whitelisted: {sig_report['whitelisted']}")
        click.echo(f"  Blacklisted: {sig_report['blacklisted']}")

        if sig_report['changed_tools_count'] > 0:
            click.echo(f"\n⚠️ WARNING: {sig_report['changed_tools_count']} tools have changed!")

        click.echo("\n✅ Ready to protect your MCP ecosystem")

    asyncio.run(show_status())


def display_results(result, format, output):
    """Display or save analysis results."""
    # Convert SecurityReport object to dict if needed
    if hasattr(result, '__dict__'):
        # It's a SecurityReport object, convert to dict
        from dataclasses import asdict
        result_dict = asdict(result) if hasattr(result, '__dataclass_fields__') else result.__dict__
    else:
        result_dict = result

    # Format the results
    if format == 'json':
        import json
        formatted = json.dumps(result_dict, indent=2, default=str)
    elif format == 'markdown':
        formatted = create_markdown_report(result_dict)
    elif format == 'sarif':
        formatted = create_sarif_report(result_dict)
    else:  # text
        formatted = create_text_report(result_dict)

    # Output to file or console
    if output:
        with open(output, 'w') as f:
            f.write(formatted)
        click.echo(f"✅ Report saved to {output}")
    else:
        click.echo(formatted)


def create_text_report(result):
    """Create simple text report."""
    lines = ["SECURITY REPORT", "=" * 50]

    # Check if it's a SecurityReport from comprehensive analyzer
    if 'threats_found' in result:
        lines.append(f"Repository: {result.get('repository_url', 'Unknown')}")
        lines.append(f"Threat Level: {result.get('threat_level', 'Unknown')}")
        lines.append(f"Threat Score: {result.get('threat_score', 0):.1%}")
        lines.append(f"Total Threats: {len(result.get('threats_found', []))}")
        lines.append(f"Files Scanned: {result.get('total_files_scanned', 0)}")
        lines.append(f"Lines Analyzed: {result.get('total_lines_analyzed', 0):,}")

        if result.get('threats_found'):
            lines.append("\nTop Threats:")
            for threat in result['threats_found'][:10]:
                severity = threat.get('severity', 'UNKNOWN')
                attack = threat.get('attack_vector', 'Unknown')
                file = threat.get('file_path', 'Unknown')
                lines.append(f"  [{severity}] {attack} in {file}")

        if result.get('recommendations'):
            lines.append("\nRecommendations:")
            for rec in result['recommendations'][:5]:
                lines.append(f"  • {rec}")
    elif 'threat_level' in result:
        # Single tool result
        lines.append(f"Threat Level: {result['threat_level']}")
        lines.append(f"Should Block: {result.get('should_block', False)}")
        if result.get('reason'):
            lines.append(f"Reason: {result['reason']}")
    else:
        # System scan result
        lines.append(f"Configs Scanned: {result.get('configs_scanned', 0)}")
        lines.append(f"Total Threats: {len(result.get('threats', []))}")

        if result.get('threats'):
            lines.append("\nTop Threats:")
            for threat in result['threats'][:5]:
                lines.append(f"  - {threat}")

    return "\n".join(lines)


def create_markdown_report(result):
    """Create markdown report."""
    md = ["# 🛡️ Mighty MCP Security Report\n"]

    if 'threat_level' in result:
        md.append("## Threat Assessment\n")
        md.append(f"**Level**: {result['threat_level']}\n")
        md.append(f"**Block**: {result.get('should_block', False)}\n")
        if result.get('reason'):
            md.append(f"**Reason**: {result['reason']}\n")
    else:
        md.append("## Summary\n")
        md.append(f"- Configs Scanned: {result.get('configs_scanned', 0)}\n")
        md.append(f"- Threats Found: {len(result.get('threats', []))}\n")

    return "".join(md)


def create_sarif_report(result):
    """Create SARIF format for CI/CD integration."""
    import json

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Mighty MCP Security",
                    "version": "3.0.0",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    # Convert threats to SARIF results
    for i, threat in enumerate(result.get('threats', [])):
        sarif["runs"][0]["results"].append({
            "ruleId": f"MCP{i:03d}",
            "level": "error" if threat.get('severity') == 'high' else "warning",
            "message": {"text": str(threat)}
        })

    return json.dumps(sarif, indent=2)


# Legacy command mappings for backwards compatibility
@cli.command('scan', hidden=True)
@click.pass_context
def scan_legacy(ctx, **kwargs):
    """[Deprecated] Use 'check' instead."""
    click.echo("Note: 'scan' is deprecated. Use 'mighty-mcp check' instead.")
    ctx.invoke(check_command, **kwargs)

@cli.command('analyze', hidden=True)
@click.pass_context
def analyze_legacy(ctx, **kwargs):
    """[Deprecated] Use 'check' instead."""
    click.echo("Note: 'analyze' is deprecated. Use 'mighty-mcp check' instead.")
    ctx.invoke(check_command, **kwargs)

@cli.command('monitor', hidden=True)
@click.pass_context
def monitor_legacy(ctx, **kwargs):
    """[Deprecated] Use 'check --realtime' instead."""
    click.echo("Note: 'monitor' is deprecated. Use 'mighty-mcp check --realtime' instead.")
    ctx.invoke(check_command, realtime=True, **kwargs)


if __name__ == '__main__':
    cli(obj={})
