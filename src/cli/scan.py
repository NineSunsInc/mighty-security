"""
Static scanning command that leverages our existing analyzers.
"""

import asyncio
import json

# Import from existing analyzer modules
import sys
from pathlib import Path

import click

# Add parent directory to path to import from analyzers
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer
from src.configs.discovery import ConfigDiscovery
from src.signatures.manager import SignatureManager


@click.command('scan')
@click.argument('target', required=False)
@click.option('--client', help='Scan specific client (claude, cursor, etc)')
@click.option('--output', '-o', help='Output file for report')
@click.option('--format', type=click.Choice(['json', 'text', 'markdown']),
              default='text', help='Output format')
@click.option('--enable-llm', is_flag=True,
              help='Enable LLM analysis (requires API key)')
@click.option('--check-signatures', is_flag=True,
              help='Verify tool signatures')
@click.option('--update-signatures', is_flag=True,
              help='Update signature database')
def scan_command(target: str | None, client: str | None,
                output: str | None, format: str,
                enable_llm: bool, check_signatures: bool,
                update_signatures: bool):
    """
    Scan MCP tools and configurations for security issues.
    
    This performs static analysis on:
    - MCP tool implementations
    - Client configurations
    - Server definitions
    
    Examples:
        # Scan all discovered configurations
        secure-mcp scan
        
        # Scan specific file
        secure-mcp scan /path/to/tool.py
        
        # Scan specific client
        secure-mcp scan --client claude
        
        # Generate JSON report
        secure-mcp scan -o report.json --format json
    """

    async def run_scan():
        analyzer = ComprehensiveMCPAnalyzer()
        discovery = ConfigDiscovery()
        signatures = SignatureManager() if check_signatures else None
        cerebras = CerebrasAnalyzer() if enable_llm else None

        results = []

        if target:
            # Scan specific target
            click.echo(f"🔍 Scanning {target}")

            if Path(target).is_file():
                # Scan file
                report = await analyzer.analyze_file(target)

                # Enhanced with LLM if enabled
                if cerebras:
                    llm_result = await cerebras.analyze_file(target)
                    report.llm_insights = llm_result

                results.append({
                    'target': target,
                    'type': 'file',
                    'report': report.to_dict()
                })

            elif Path(target).is_dir():
                # Scan directory
                for file_path in Path(target).rglob('*.py'):
                    click.echo(f"  📄 {file_path}")
                    report = await analyzer.analyze_file(str(file_path))
                    results.append({
                        'target': str(file_path),
                        'type': 'file',
                        'report': report.to_dict()
                    })

        else:
            # Scan discovered configurations
            configs = await discovery.discover_all()

            # Filter by client if specified
            if client:
                configs = [c for c in configs if c['client'] == client]

            click.echo(f"📦 Found {len(configs)} configurations")

            for config in configs:
                click.echo(f"\n🔍 Scanning {config['client']} at {config['path']}")

                # Extract servers
                servers = discovery.get_servers_from_config(config['config'])

                for server_name, server_def in servers.items():
                    click.echo(f"  📡 Server: {server_name}")

                    # Check signatures if enabled
                    if signatures:
                        sig_result = await signatures.verify_tool({
                            'name': server_name,
                            'server': server_name,
                            'params': server_def
                        })

                        if sig_result.status == 'modified':
                            click.echo("    ⚠️ Signature changed!")
                        elif sig_result.status == 'blacklisted':
                            click.echo("    🚨 Blacklisted!")

                        if update_signatures:
                            # Update signature database
                            pass

                    # Analyze server definition
                    # This is where we'd analyze the actual tool code if available
                    results.append({
                        'client': config['client'],
                        'server': server_name,
                        'config_path': config['path'],
                        'signature': sig_result.to_dict() if signatures else None
                    })

        # Generate report
        report = {
            'scan_results': results,
            'summary': {
                'total_scanned': len(results),
                'high_risk': sum(1 for r in results
                               if r.get('report', {}).get('threat_score', 0) >= 7),
                'medium_risk': sum(1 for r in results
                                 if 4 <= r.get('report', {}).get('threat_score', 0) < 7),
                'low_risk': sum(1 for r in results
                              if r.get('report', {}).get('threat_score', 0) < 4)
            }
        }

        # Output report
        if output:
            output_path = Path(output)

            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2, default=str)

            elif format == 'markdown':
                md_content = generate_markdown_report(report)
                with open(output_path, 'w') as f:
                    f.write(md_content)

            else:  # text
                with open(output_path, 'w') as f:
                    f.write(generate_text_report(report))

            click.echo(f"\n✅ Report saved to {output_path}")

        else:
            # Display summary
            click.echo("\n" + "="*50)
            click.echo("SCAN SUMMARY")
            click.echo("="*50)
            click.echo(f"Total Scanned: {report['summary']['total_scanned']}")
            click.echo(f"High Risk: {report['summary']['high_risk']}")
            click.echo(f"Medium Risk: {report['summary']['medium_risk']}")
            click.echo(f"Low Risk: {report['summary']['low_risk']}")

    # Run async scan
    asyncio.run(run_scan())


def generate_markdown_report(report: dict) -> str:
    """Generate markdown report"""

    md = ["# MCP Security Scan Report\n"]
    md.append("## Summary\n")
    md.append(f"- **Total Scanned**: {report['summary']['total_scanned']}\n")
    md.append(f"- **High Risk**: {report['summary']['high_risk']}\n")
    md.append(f"- **Medium Risk**: {report['summary']['medium_risk']}\n")
    md.append(f"- **Low Risk**: {report['summary']['low_risk']}\n")

    md.append("\n## Detailed Results\n")

    for result in report['scan_results']:
        if 'report' in result:
            r = result['report']
            md.append(f"\n### {result['target']}\n")
            md.append(f"- **Threat Score**: {r.get('threat_score', 0)}/10\n")

            if r.get('threats_found'):
                md.append("- **Threats Found**:\n")
                for threat in r['threats_found'][:5]:
                    md.append(f"  - {threat['type']}: {threat.get('description', '')}\n")

    return "".join(md)


def generate_text_report(report: dict) -> str:
    """Generate text report"""

    lines = ["MCP SECURITY SCAN REPORT", "="*50]
    lines.append(f"Total Scanned: {report['summary']['total_scanned']}")
    lines.append(f"High Risk: {report['summary']['high_risk']}")
    lines.append(f"Medium Risk: {report['summary']['medium_risk']}")
    lines.append(f"Low Risk: {report['summary']['low_risk']}")

    lines.append("\nDETAILS:")
    lines.append("-"*50)

    for result in report['scan_results']:
        if 'report' in result:
            r = result['report']
            lines.append(f"\n{result['target']}")
            lines.append(f"  Threat Score: {r.get('threat_score', 0)}/10")

            if r.get('threats_found'):
                lines.append("  Threats:")
                for threat in r['threats_found'][:3]:
                    lines.append(f"    - {threat['type']}")

    return "\n".join(lines)
