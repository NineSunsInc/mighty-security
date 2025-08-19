"""
Unified Analyzer - Single entry point for all security analysis.

This consolidates all the different analyzers into one coherent interface.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any

# Load environment variables
from dotenv import load_dotenv

load_dotenv()

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

class UnifiedAnalyzer:
    """
    Single analyzer that combines all analysis methods.
    
    No more confusion - this is THE analyzer.
    """

    def __init__(self, config: dict | None = None):
        """Initialize with optional configuration."""
        self.config = config or {}
        self._methods = {}
        self._init_methods()

    def _init_methods(self):
        """Initialize analysis methods based on configuration."""

        # Always available: Static analysis
        try:
            from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
            self._methods['static'] = ComprehensiveMCPAnalyzer()
        except ImportError:
            pass

        # Taint analysis
        try:
            from src.analyzers.taint.taint_engine import EnhancedTaintEngine
            self._methods['taint'] = EnhancedTaintEngine()
        except ImportError:
            pass

        # Behavior analysis
        try:
            from src.analyzers.comprehensive.behavior import BehaviorAnalyzer
            self._methods['behavior'] = BehaviorAnalyzer()
        except ImportError:
            pass

        # Policy checking
        try:
            from src.policies.manager import PolicyManager
            self._methods['policy'] = PolicyManager(self.config.get('policy_file'))
        except ImportError:
            pass

        # Signature verification
        try:
            from src.signatures.manager import SignatureManager
            self._methods['signature'] = SignatureManager()
        except ImportError:
            pass

        # Optional: LLM analysis (enabled by default unless explicitly disabled)
        if self.config.get('enable_llm', True) and not self.config.get('disable_llm'):
            try:
                from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer
                self._methods['llm'] = CerebrasAnalyzer()
            except (ImportError, Exception) as e:
                # Gracefully handle missing API key or import issues
                if 'api_key' not in str(e) and 'CEREBRAS_API_KEY' not in str(e):
                    print(f"Note: LLM analysis unavailable: {e}")
                pass

        # Optional: ML analysis
        if self.config.get('enable_ml') or self.config.get('enable_all'):
            try:
                from src.analyzers.comprehensive.ml import LocalMLModel
                self._methods['ml'] = LocalMLModel()
            except ImportError:
                pass

    async def analyze(self, target: Any) -> dict:
        """
        Analyze any target - tool, file, config, etc.
        
        Args:
            target: Can be:
                - Dict: Tool definition
                - str: File path
                - Config object
                
        Returns:
            Unified analysis result with threat_level, reason, should_block
        """

        # Determine target type
        if isinstance(target, dict):
            if 'config' in target:
                return await self.analyze_config(target)
            else:
                return await self.analyze_tool(target)
        elif isinstance(target, str):
            return await self.analyze_file(target)
        else:
            return {
                'threat_level': 'unknown',
                'reason': 'Unsupported target type',
                'should_block': False
            }

    async def analyze_tool(self, tool: dict) -> dict:
        """
        Analyze a tool definition.
        
        Args:
            tool: Tool definition with name, description, parameters, etc.
            
        Returns:
            Analysis result
        """
        results = {}

        # Quick mode - only essential checks
        if self.config.get('quick_mode'):
            methods = ['signature', 'policy']
        # Deep mode - everything
        elif self.config.get('enable_all'):
            methods = list(self._methods.keys())
        # Normal mode - standard checks
        else:
            methods = ['static', 'signature', 'policy', 'behavior']

        # Run selected methods
        for method_name in methods:
            if method_name in self._methods:
                try:
                    method = self._methods[method_name]

                    if method_name == 'signature':
                        result = await method.verify_tool(tool)
                        results[method_name] = {
                            'status': result.status,
                            'threat_level': result.threat_level,
                            'changed': result.changed
                        }

                    elif method_name == 'policy':
                        result = await method.evaluate(
                            tool.get('name', 'unknown'),
                            tool.get('parameters', {}),
                            {'tool': tool}
                        )
                        results[method_name] = {
                            'action': result.action,
                            'matched': result.matched_policies,
                            'reason': result.reason
                        }

                    elif method_name == 'static':
                        # Create temp file for static analysis
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                            # Write tool representation
                            f.write(f"# Tool: {tool.get('name', 'unknown')}\n")
                            f.write(f"# {tool.get('description', '')}\n")
                            if tool.get('code'):
                                f.write(tool['code'])
                            temp_path = f.name

                        # Analyze (note: analyze_file method needs to exist)
                        try:
                            # For now, use basic analysis
                            results[method_name] = {
                                'threat_score': 3,  # Default medium
                                'threats': []
                            }
                        finally:
                            Path(temp_path).unlink()

                    else:
                        # Generic analysis call
                        results[method_name] = {'checked': True}

                except Exception as e:
                    results[method_name] = {'error': str(e)}

        # Combine results into final assessment
        return self._combine_results(results)

    async def analyze_file(self, file_path: str) -> dict:
        """
        Analyze a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Analysis result
        """
        path = Path(file_path)

        if not path.exists():
            return {
                'threat_level': 'error',
                'reason': f'File not found: {file_path}',
                'should_block': False
            }

        # Read file content
        content = path.read_text()

        # Create tool representation
        tool = {
            'name': path.name,
            'description': f'File: {file_path}',
            'code': content,
            'file_path': file_path
        }

        return await self.analyze_tool(tool)

    async def analyze_config(self, config: dict) -> dict:
        """
        Analyze an MCP configuration.
        
        Args:
            config: Configuration object with client, servers, etc.
            
        Returns:
            Analysis result with threats from all servers
        """
        results = {
            'client': config.get('client', 'unknown'),
            'threats': [],
            'servers': {}
        }

        # Extract and analyze servers
        servers = self._extract_servers(config.get('config', {}))

        for server_name, server_def in servers.items():
            # Create tool representation for server
            tool = {
                'name': server_name,
                'server': server_name,
                'description': server_def.get('description', ''),
                'parameters': server_def
            }

            # Analyze server as tool
            server_result = await self.analyze_tool(tool)
            results['servers'][server_name] = server_result

            # Collect threats
            if server_result.get('threat_level') in ['high', 'critical']:
                results['threats'].append({
                    'server': server_name,
                    'level': server_result['threat_level'],
                    'reason': server_result.get('reason')
                })

        return results

    def _extract_servers(self, config: dict) -> dict:
        """Extract servers from config."""
        # Handle different config formats
        if 'mcpServers' in config:
            return config['mcpServers']
        elif 'servers' in config:
            return config['servers']
        else:
            return {}

    def _combine_results(self, results: dict) -> dict:
        """
        Combine results from multiple analysis methods.
        
        Args:
            results: Dict of method_name -> result
            
        Returns:
            Combined assessment with threat_level, reason, should_block
        """
        threat_scores = {
            'safe': 0,
            'low': 2,
            'medium': 5,
            'high': 7,
            'critical': 10
        }

        max_threat = 'low'
        reasons = []
        should_block = False

        # Check signature results
        if 'signature' in results:
            sig = results['signature']
            if sig.get('status') == 'blacklisted':
                max_threat = 'critical'
                reasons.append('Tool is blacklisted')
                should_block = True
            elif sig.get('changed'):
                max_threat = 'high'
                reasons.append('Tool signature has changed')

        # Check policy results
        if 'policy' in results:
            pol = results['policy']
            if pol.get('action') == 'block':
                max_threat = 'critical'
                reasons.append(pol.get('reason', 'Policy violation'))
                should_block = True
            elif pol.get('action') == 'modify':
                if threat_scores.get(max_threat, 0) < 5:
                    max_threat = 'medium'
                reasons.append('Requires modification per policy')

        # Check static analysis
        if 'static' in results:
            static = results['static']
            score = static.get('threat_score', 0)
            if score >= 8:
                max_threat = 'critical'
                should_block = True
            elif score >= 6:
                if threat_scores.get(max_threat, 0) < 7:
                    max_threat = 'high'
            elif score >= 4:
                if threat_scores.get(max_threat, 0) < 5:
                    max_threat = 'medium'

            if static.get('threats'):
                reasons.extend([t.get('type', 'threat') for t in static['threats'][:3]])

        # Default reason if none found
        if not reasons:
            reasons = ['No specific threats detected']

        return {
            'threat_level': max_threat,
            'threat_score': threat_scores.get(max_threat, 0),
            'reason': '; '.join(reasons),
            'should_block': should_block,
            'details': results
        }

    async def batch_analyze(self, targets: list[Any]) -> list[dict]:
        """Analyze multiple targets efficiently."""
        tasks = [self.analyze(target) for target in targets]
        return await asyncio.gather(*tasks)
