"""
Unified scanning command that combines all our capabilities:
- GitHub repo scanning
- MCP configuration discovery and analysis
- Runtime signature verification
- Policy evaluation
- Toxic flow detection
"""

import click
import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, List
import tempfile
import os

# Import from existing analyzers
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer

# Import new integrated components
from src.configs.discovery import ConfigDiscovery
from src.signatures.manager import SignatureManager
from src.policies.manager import PolicyManager
from src.policies.templates import GuardrailTemplate
from src.runtime.session import SessionManager, SessionNode, ThreatLevel
from src.runtime.analyzer_integration import AnalyzerIntegration


class UnifiedScanner:
    """
    Unified scanner that combines all security capabilities.
    
    Features:
    - GitHub repository scanning
    - MCP tool analysis
    - Configuration discovery
    - Signature verification
    - Policy evaluation
    - Toxic flow detection
    """
    
    def __init__(self, enable_llm: bool = False, enable_ml: bool = False):
        # Existing analyzers
        self.comprehensive = ComprehensiveMCPAnalyzer()
        self.cerebras = CerebrasAnalyzer() if enable_llm else None
        
        # New integrated components
        self.discovery = ConfigDiscovery()
        self.signatures = SignatureManager()
        self.policies = PolicyManager()
        self.templates = GuardrailTemplate()
        self.analyzer_integration = AnalyzerIntegration(
            enable_llm=enable_llm,
            enable_ml=enable_ml
        )
    
    async def scan_github_repo(self, repo_url: str) -> Dict:
        """
        Scan a GitHub repository for MCP tools.
        
        This uses our existing GitHub scanning capabilities.
        """
        click.echo(f"🔍 Scanning GitHub repository: {repo_url}")
        
        # Extract owner/repo from URL
        parts = repo_url.replace('https://github.com/', '').split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
        else:
            return {'error': 'Invalid GitHub URL'}
        
        # Use our existing GitHub analyzer
        # This would download and analyze the repo
        results = {
            'repo': f"{owner}/{repo}",
            'files_analyzed': 0,
            'threats': [],
            'mcp_tools_found': []
        }
        
        # TODO: Implement actual GitHub fetching and scanning
        # For now, showing the structure
        
        return results
    
    async def scan_local_directory(self, directory: str) -> Dict:
        """
        Scan a local directory for MCP tools and configurations.
        
        Combines static analysis with signature verification.
        """
        click.echo(f"📁 Scanning directory: {directory}")
        
        dir_path = Path(directory)
        results = {
            'directory': str(dir_path),
            'files_analyzed': 0,
            'threats': [],
            'mcp_configs': [],
            'signatures': {}
        }
        
        # Find MCP-related files
        for file_path in dir_path.rglob('*.json'):
            # Check if it's an MCP config
            try:
                with open(file_path) as f:
                    data = json.load(f)
                
                if 'mcpServers' in data or 'servers' in data:
                    click.echo(f"  📋 Found MCP config: {file_path.name}")
                    results['mcp_configs'].append(str(file_path))
                    
                    # Analyze servers in config
                    servers = data.get('mcpServers', data.get('servers', {}))
                    for server_name, server_def in servers.items():
                        # Verify signature
                        sig_result = await self.signatures.verify_tool({
                            'name': server_name,
                            'server': server_name,
                            'params': server_def
                        })
                        
                        results['signatures'][server_name] = {
                            'status': sig_result.status,
                            'threat_level': sig_result.threat_level,
                            'changed': sig_result.changed
                        }
            except:
                pass
        
        # Scan Python files for MCP tools
        for file_path in dir_path.rglob('*.py'):
            click.echo(f"  🐍 Analyzing: {file_path.name}")
            
            # Run comprehensive analysis
            report = await self.comprehensive.analyze_file(str(file_path))
            results['files_analyzed'] += 1
            
            if report.threats_found:
                results['threats'].extend(report.threats_found)
        
        return results
    
    async def scan_mcp_configs(self, client: Optional[str] = None) -> Dict:
        """
        Discover and scan all MCP client configurations.
        
        This combines configuration discovery with deep analysis.
        """
        click.echo("🔎 Discovering MCP configurations...")
        
        # Discover configs
        configs = await self.discovery.discover_all()
        
        if client:
            configs = [c for c in configs if c['client'] == client]
        
        results = {
            'configs_found': len(configs),
            'clients': {},
            'total_threats': [],
            'policy_violations': [],
            'toxic_flows': []
        }
        
        for config in configs:
            click.echo(f"\n📦 Scanning {config['client']} at {config['path']}")
            
            client_results = {
                'path': config['path'],
                'servers': {},
                'threats': [],
                'signatures': {}
            }
            
            # Extract servers
            servers = self.discovery.get_servers_from_config(config['config'])
            
            for server_name, server_def in servers.items():
                click.echo(f"  📡 Server: {server_name}")
                
                # Create pseudo-tool for analysis
                tool = {
                    'name': server_name,
                    'server': server_name,
                    'description': server_def.get('description', ''),
                    'params': server_def
                }
                
                # 1. Signature verification
                sig_result = await self.signatures.verify_tool(tool)
                client_results['signatures'][server_name] = {
                    'status': sig_result.status,
                    'threat_level': sig_result.threat_level,
                    'changed': sig_result.changed
                }
                
                if sig_result.status == 'blacklisted':
                    click.echo(f"    🚨 BLACKLISTED!")
                elif sig_result.status == 'modified':
                    click.echo(f"    ⚠️ Signature changed!")
                
                # 2. Policy evaluation
                policy_result = await self.policies.evaluate(
                    tool=server_name,
                    params=server_def,
                    context={
                        'client': config['client'],
                        'server': server_name
                    }
                )
                
                if policy_result.action == 'block':
                    results['policy_violations'].append({
                        'client': config['client'],
                        'server': server_name,
                        'reason': policy_result.reason
                    })
                    click.echo(f"    🚫 Policy violation: {policy_result.reason}")
                
                # 3. Deep analysis using analyzer integration
                analysis = await self.analyzer_integration.analyze_tool_before_execution(
                    tool=tool,
                    context={
                        'client': config['client'],
                        'server': server_name
                    }
                )
                
                if analysis['threat_score'] >= 7:
                    click.echo(f"    ⚠️ High risk detected: Score {analysis['threat_score']}/10")
                
                client_results['servers'][server_name] = {
                    'threat_score': analysis.get('threat_score', 0),
                    'threats': analysis.get('threats', []),
                    'vulnerabilities': analysis.get('vulnerabilities', [])
                }
                
                # Add to total threats
                results['total_threats'].extend(analysis.get('threats', []))
            
            results['clients'][config['client']] = client_results
        
        # 4. Check for toxic flows across all tools
        # Create mock session to analyze flow patterns
        all_tools = []
        for client_data in results['clients'].values():
            all_tools.extend(client_data['servers'].keys())
        
        if len(all_tools) > 1:
            toxic_flows = await self.analyzer_integration.analyze_toxic_flow([
                {'type': 'tool_call', 'tool': tool} for tool in all_tools
            ])
            results['toxic_flows'] = toxic_flows
        
        return results
    
    async def generate_security_report(self, scan_results: Dict) -> Dict:
        """
        Generate comprehensive security report with recommendations.
        """
        report = {
            'summary': {
                'total_configs': scan_results.get('configs_found', 0),
                'total_threats': len(scan_results.get('total_threats', [])),
                'policy_violations': len(scan_results.get('policy_violations', [])),
                'toxic_flows': len(scan_results.get('toxic_flows', [])),
                'risk_level': 'low'
            },
            'recommendations': [],
            'critical_issues': [],
            'warnings': []
        }
        
        # Determine overall risk level
        if report['summary']['policy_violations'] > 0:
            report['summary']['risk_level'] = 'high'
        elif report['summary']['total_threats'] > 5:
            report['summary']['risk_level'] = 'medium'
        
        # Generate recommendations based on findings
        if scan_results.get('policy_violations'):
            report['critical_issues'].append({
                'type': 'POLICY_VIOLATIONS',
                'count': len(scan_results['policy_violations']),
                'details': scan_results['policy_violations'][:3]  # Top 3
            })
            report['recommendations'].append(
                "Review and update security policies for blocked tools"
            )
        
        if scan_results.get('toxic_flows'):
            report['critical_issues'].append({
                'type': 'TOXIC_FLOWS',
                'count': len(scan_results['toxic_flows']),
                'details': scan_results['toxic_flows'][:3]
            })
            report['recommendations'].append(
                "Isolate tools that create dangerous data flows"
            )
        
        # Check for signature issues
        for client, client_data in scan_results.get('clients', {}).items():
            for server, sig_data in client_data.get('signatures', {}).items():
                if sig_data.get('status') == 'blacklisted':
                    report['critical_issues'].append({
                        'type': 'BLACKLISTED_TOOL',
                        'client': client,
                        'server': server
                    })
                elif sig_data.get('changed'):
                    report['warnings'].append({
                        'type': 'SIGNATURE_CHANGED',
                        'client': client,
                        'server': server,
                        'message': 'Tool signature has changed - possible tampering'
                    })
        
        # Add general recommendations
        if not report['recommendations']:
            report['recommendations'].append("Continue regular security scanning")
        
        return report


@click.command('unified-scan')
@click.argument('target', required=False)
@click.option('--github', help='Scan GitHub repository URL')
@click.option('--client', help='Scan specific MCP client')
@click.option('--enable-llm', is_flag=True, help='Enable LLM analysis')
@click.option('--enable-ml', is_flag=True, help='Enable ML analysis')
@click.option('--check-policies', is_flag=True, help='Evaluate against policies')
@click.option('--update-signatures', is_flag=True, help='Update signature database')
@click.option('--output', '-o', help='Output file for report')
@click.option('--format', type=click.Choice(['json', 'text', 'markdown']),
              default='text', help='Output format')
def unified_scan_command(target: Optional[str], github: Optional[str],
                        client: Optional[str], enable_llm: bool,
                        enable_ml: bool, check_policies: bool,
                        update_signatures: bool, output: Optional[str],
                        format: str):
    """
    Unified security scanner for MCP tools.
    
    This command combines:
    - GitHub repository scanning
    - Local directory analysis
    - MCP configuration discovery
    - Signature verification
    - Policy evaluation
    - Toxic flow detection
    - Deep static analysis
    - LLM-powered detection (optional)
    
    Examples:
        # Scan all MCP configurations with full analysis
        secure-mcp unified-scan --enable-llm --check-policies
        
        # Scan GitHub repository
        secure-mcp unified-scan --github https://github.com/owner/repo
        
        # Scan local directory
        secure-mcp unified-scan /path/to/project
        
        # Scan specific client with signature updates
        secure-mcp unified-scan --client claude --update-signatures
        
        # Generate comprehensive report
        secure-mcp unified-scan -o report.json --format json
    """
    
    async def run_unified_scan():
        scanner = UnifiedScanner(enable_llm=enable_llm, enable_ml=enable_ml)
        
        all_results = {
            'scan_type': [],
            'github_results': None,
            'directory_results': None,
            'config_results': None,
            'report': None
        }
        
        # Initialize policies if checking
        if check_policies:
            click.echo("📋 Loading security policies...")
            # Load default policies if none exist
            scanner.policies._load_default_policies()
        
        # Scan GitHub if specified
        if github:
            all_results['scan_type'].append('github')
            all_results['github_results'] = await scanner.scan_github_repo(github)
        
        # Scan local directory if specified
        if target and Path(target).exists():
            all_results['scan_type'].append('directory')
            all_results['directory_results'] = await scanner.scan_local_directory(target)
        
        # Always scan MCP configurations
        all_results['scan_type'].append('configs')
        all_results['config_results'] = await scanner.scan_mcp_configs(client)
        
        # Generate security report
        click.echo("\n" + "="*50)
        click.echo("GENERATING SECURITY REPORT")
        click.echo("="*50)
        
        # Combine all results for report
        combined_results = all_results['config_results'] or {}
        
        if all_results['directory_results']:
            combined_results['directory_threats'] = all_results['directory_results']['threats']
        
        report = await scanner.generate_security_report(combined_results)
        all_results['report'] = report
        
        # Display summary
        click.echo(f"\n📊 Summary:")
        click.echo(f"  Risk Level: {report['summary']['risk_level'].upper()}")
        click.echo(f"  Total Threats: {report['summary']['total_threats']}")
        click.echo(f"  Policy Violations: {report['summary']['policy_violations']}")
        click.echo(f"  Toxic Flows: {report['summary']['toxic_flows']}")
        
        if report['critical_issues']:
            click.echo(f"\n🚨 Critical Issues:")
            for issue in report['critical_issues']:
                click.echo(f"  - {issue['type']}: {issue.get('count', 1)}")
        
        if report['warnings']:
            click.echo(f"\n⚠️ Warnings:")
            for warning in report['warnings'][:5]:
                click.echo(f"  - {warning['type']}: {warning.get('message', '')}")
        
        if report['recommendations']:
            click.echo(f"\n💡 Recommendations:")
            for rec in report['recommendations']:
                click.echo(f"  - {rec}")
        
        # Update signatures if requested
        if update_signatures and all_results['config_results']:
            click.echo("\n📝 Updating signature database...")
            # Signatures are already updated during scanning
            scanner.signatures._save_signatures()
            click.echo("✅ Signatures updated")
        
        # Save report if requested
        if output:
            output_path = Path(output)
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(all_results, f, indent=2, default=str)
            
            elif format == 'markdown':
                md = generate_markdown_report(all_results)
                with open(output_path, 'w') as f:
                    f.write(md)
            
            else:  # text
                txt = generate_text_report(all_results)
                with open(output_path, 'w') as f:
                    f.write(txt)
            
            click.echo(f"\n✅ Report saved to {output_path}")
    
    # Run the unified scan
    asyncio.run(run_unified_scan())


def generate_markdown_report(results: Dict) -> str:
    """Generate markdown report from results"""
    
    md = ["# MCP Security Scan Report\n\n"]
    
    report = results.get('report', {})
    
    md.append("## Executive Summary\n\n")
    summary = report.get('summary', {})
    md.append(f"**Risk Level**: {summary.get('risk_level', 'unknown').upper()}\n\n")
    
    md.append("| Metric | Count |\n")
    md.append("|--------|-------|\n")
    md.append(f"| Total Threats | {summary.get('total_threats', 0)} |\n")
    md.append(f"| Policy Violations | {summary.get('policy_violations', 0)} |\n")
    md.append(f"| Toxic Flows | {summary.get('toxic_flows', 0)} |\n")
    
    if report.get('critical_issues'):
        md.append("\n## 🚨 Critical Issues\n\n")
        for issue in report['critical_issues']:
            md.append(f"### {issue['type']}\n")
            md.append(f"Count: {issue.get('count', 1)}\n\n")
    
    if report.get('recommendations'):
        md.append("\n## 💡 Recommendations\n\n")
        for rec in report['recommendations']:
            md.append(f"- {rec}\n")
    
    # Add detailed results
    if results.get('config_results'):
        md.append("\n## Configuration Analysis\n\n")
        config_results = results['config_results']
        
        for client, client_data in config_results.get('clients', {}).items():
            md.append(f"### {client}\n\n")
            md.append(f"**Path**: `{client_data['path']}`\n\n")
            
            if client_data.get('servers'):
                md.append("#### Servers\n\n")
                for server, server_data in client_data['servers'].items():
                    md.append(f"- **{server}**\n")
                    md.append(f"  - Threat Score: {server_data.get('threat_score', 0)}/10\n")
                    
                    if server_data.get('threats'):
                        md.append(f"  - Threats: {len(server_data['threats'])}\n")
    
    return "".join(md)


def generate_text_report(results: Dict) -> str:
    """Generate text report from results"""
    
    lines = ["MCP SECURITY SCAN REPORT", "="*50, ""]
    
    report = results.get('report', {})
    summary = report.get('summary', {})
    
    lines.append(f"Risk Level: {summary.get('risk_level', 'unknown').upper()}")
    lines.append(f"Total Threats: {summary.get('total_threats', 0)}")
    lines.append(f"Policy Violations: {summary.get('policy_violations', 0)}")
    lines.append(f"Toxic Flows: {summary.get('toxic_flows', 0)}")
    
    if report.get('critical_issues'):
        lines.append("\nCRITICAL ISSUES:")
        lines.append("-"*30)
        for issue in report['critical_issues']:
            lines.append(f"  {issue['type']}: {issue.get('count', 1)}")
    
    if report.get('recommendations'):
        lines.append("\nRECOMMENDATIONS:")
        lines.append("-"*30)
        for rec in report['recommendations']:
            lines.append(f"  - {rec}")
    
    return "\n".join(lines)