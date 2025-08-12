"""
Integration layer between runtime monitoring and existing analyzers.

This bridges the real-time proxy with our powerful static analysis tools.
"""

import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
import json

# Import existing analyzers
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer
from src.analyzers.llm.multi_pass_analyzer import MultiPassAnalyzer
from src.analyzers.taint.taint_engine import EnhancedTaintEngine
from src.analyzers.comprehensive.behavior import BehaviorAnalyzer
from src.analyzers.comprehensive.ml import LocalMLModel


class AnalyzerIntegration:
    """
    Integrates existing static analyzers with runtime monitoring.
    
    This allows us to:
    - Use static analysis before allowing tools to run
    - Leverage Cerebras/LLM analysis for unknown tools
    - Apply taint analysis to runtime data flows
    - Use ML models for anomaly detection
    """
    
    def __init__(self, enable_llm: bool = True, enable_ml: bool = True):
        """
        Initialize analyzer integration.
        
        Args:
            enable_llm: Enable LLM-based analysis (Cerebras)
            enable_ml: Enable ML-based analysis
        """
        # Core analyzers
        self.comprehensive = ComprehensiveMCPAnalyzer()
        self.taint_engine = EnhancedTaintEngine()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Optional advanced analyzers
        self.cerebras = CerebrasAnalyzer() if enable_llm else None
        self.multi_pass = MultiPassAnalyzer() if enable_llm else None
        self.ml_model = LocalMLModel() if enable_ml else None
        
        # Cache for analyzed tools
        self.analysis_cache: Dict[str, Dict] = {}
    
    async def analyze_tool_before_execution(self, tool: Dict, context: Dict) -> Dict:
        """
        Analyze tool before allowing execution.
        
        This is called by the proxy before forwarding requests.
        
        Args:
            tool: Tool definition
            context: Runtime context (session, client, server)
        
        Returns:
            Analysis result with risk assessment
        """
        
        tool_id = f"{context.get('server', 'unknown')}:{tool.get('name', 'unknown')}"
        
        # Check cache first
        if tool_id in self.analysis_cache:
            cached = self.analysis_cache[tool_id]
            # Re-use if recent (within 1 hour)
            if cached.get('timestamp', 0) > asyncio.get_event_loop().time() - 3600:
                return cached['result']
        
        # Prepare tool for analysis
        tool_data = {
            'name': tool.get('name'),
            'description': tool.get('description', ''),
            'parameters': tool.get('parameters', {}),
            'code': tool.get('code', ''),  # If available
            'server': context.get('server'),
            'client': context.get('client')
        }
        
        # Run comprehensive static analysis
        static_result = await self._run_static_analysis(tool_data)
        
        # Run LLM analysis if enabled and high risk
        llm_result = None
        if self.cerebras and static_result.get('threat_score', 0) > 5:
            llm_result = await self._run_llm_analysis(tool_data)
        
        # Run ML analysis if enabled
        ml_result = None
        if self.ml_model:
            ml_result = await self._run_ml_analysis(tool_data, context)
        
        # Combine results
        combined_result = self._combine_analysis_results(
            static_result,
            llm_result,
            ml_result
        )
        
        # Cache result
        self.analysis_cache[tool_id] = {
            'result': combined_result,
            'timestamp': asyncio.get_event_loop().time()
        }
        
        return combined_result
    
    async def _run_static_analysis(self, tool: Dict) -> Dict:
        """Run comprehensive static analysis"""
        
        try:
            # Create temporary file for analysis
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                # Write tool code or generate from description
                if tool.get('code'):
                    f.write(tool['code'])
                else:
                    # Generate pseudo-code from description
                    f.write(f"# Tool: {tool.get('name', 'unknown')}\n")
                    f.write(f"# Description: {tool.get('description', '')}\n")
                    f.write(f"# Parameters: {json.dumps(tool.get('parameters', {}))}\n")
                temp_path = f.name
            
            # Run comprehensive analysis
            report = await self.comprehensive.analyze_file(temp_path)
            
            # Clean up
            Path(temp_path).unlink()
            
            return {
                'threat_score': report.threat_score,
                'threats': report.threats_found,
                'vulnerabilities': report.vulnerabilities,
                'behavioral_risks': report.behavioral_risks
            }
            
        except Exception as e:
            print(f"Static analysis failed: {e}")
            return {
                'threat_score': 5,  # Medium risk by default
                'threats': [],
                'error': str(e)
            }
    
    async def _run_llm_analysis(self, tool: Dict) -> Optional[Dict]:
        """Run Cerebras LLM analysis for deeper insights"""
        
        try:
            # Prepare context for Cerebras
            context = f"""
            Analyze this MCP tool for security risks:
            
            Tool Name: {tool.get('name', 'unknown')}
            Description: {tool.get('description', 'No description')}
            Parameters: {json.dumps(tool.get('parameters', {}), indent=2)}
            Server: {tool.get('server', 'unknown')}
            Client: {tool.get('client', 'unknown')}
            
            Code (if available):
            {tool.get('code', 'No code available')}
            """
            
            # Run Cerebras analysis
            result = await self.cerebras.analyze_with_context(
                code=tool.get('code', ''),
                context=context
            )
            
            return {
                'vulnerabilities': result.get('vulnerabilities', []),
                'recommendations': result.get('recommendations', []),
                'risk_assessment': result.get('risk_assessment', 'unknown'),
                'confidence': result.get('confidence', 0)
            }
            
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return None
    
    async def _run_ml_analysis(self, tool: Dict, context: Dict) -> Optional[Dict]:
        """Run ML-based anomaly detection"""
        
        try:
            # Extract features for ML
            features = self.ml_model.extract_features({
                'tool_name': tool.get('name', ''),
                'description': tool.get('description', ''),
                'params': json.dumps(tool.get('parameters', {})),
                'server': context.get('server', ''),
                'client': context.get('client', ''),
                'session_id': context.get('session_id', '')
            })
            
            # Predict risk
            risk_score = self.ml_model.predict_risk(features)
            
            # Detect anomalies
            is_anomaly = self.ml_model.detect_anomaly(features)
            
            return {
                'risk_score': risk_score,
                'is_anomaly': is_anomaly,
                'confidence': self.ml_model.get_confidence()
            }
            
        except Exception as e:
            print(f"ML analysis failed: {e}")
            return None
    
    def _combine_analysis_results(self, static: Dict, 
                                 llm: Optional[Dict], 
                                 ml: Optional[Dict]) -> Dict:
        """Combine results from multiple analyzers"""
        
        # Start with static analysis
        combined = {
            'threat_score': static.get('threat_score', 0),
            'threats': static.get('threats', []),
            'vulnerabilities': static.get('vulnerabilities', []),
            'recommendations': [],
            'confidence': 'high' if not static.get('error') else 'low'
        }
        
        # Add LLM insights
        if llm:
            combined['vulnerabilities'].extend(llm.get('vulnerabilities', []))
            combined['recommendations'].extend(llm.get('recommendations', []))
            
            # Adjust threat score based on LLM assessment
            if llm.get('risk_assessment') == 'critical':
                combined['threat_score'] = max(combined['threat_score'], 9)
            elif llm.get('risk_assessment') == 'high':
                combined['threat_score'] = max(combined['threat_score'], 7)
        
        # Add ML insights
        if ml:
            if ml.get('is_anomaly'):
                combined['threats'].append({
                    'type': 'ANOMALY_DETECTED',
                    'description': 'Tool behavior is anomalous compared to baseline',
                    'severity': 'high'
                })
                combined['threat_score'] = max(combined['threat_score'], 7)
            
            # Adjust based on ML risk score
            ml_risk = ml.get('risk_score', 0)
            if ml_risk > 0.8:
                combined['threat_score'] = max(combined['threat_score'], 8)
        
        # Determine final risk level
        if combined['threat_score'] >= 8:
            combined['risk_level'] = 'critical'
        elif combined['threat_score'] >= 6:
            combined['risk_level'] = 'high'
        elif combined['threat_score'] >= 4:
            combined['risk_level'] = 'medium'
        else:
            combined['risk_level'] = 'low'
        
        return combined
    
    async def analyze_toxic_flow(self, session_events: List[Dict]) -> List[Dict]:
        """
        Analyze session events for toxic flows using taint analysis.
        
        Args:
            session_events: List of session events in chronological order
        
        Returns:
            List of detected toxic flows
        """
        
        toxic_flows = []
        
        # Build taint graph from events
        for i, event in enumerate(session_events):
            if event.get('type') != 'tool_call':
                continue
            
            tool_name = event.get('tool')
            params = event.get('params', {})
            
            # Check if this is a source
            if self.taint_engine.is_source(tool_name):
                # Track taint forward
                tainted_data = self.taint_engine.create_taint(
                    source=tool_name,
                    data=params
                )
                
                # Look for sinks in subsequent events
                for j in range(i + 1, len(session_events)):
                    next_event = session_events[j]
                    
                    if next_event.get('type') != 'tool_call':
                        continue
                    
                    next_tool = next_event.get('tool')
                    
                    if self.taint_engine.is_sink(next_tool):
                        # Found a toxic flow!
                        toxic_flows.append({
                            'type': 'TOXIC_FLOW',
                            'source': tool_name,
                            'sink': next_tool,
                            'source_index': i,
                            'sink_index': j,
                            'risk': self._assess_flow_risk(tool_name, next_tool),
                            'description': self._describe_flow(tool_name, next_tool)
                        })
        
        return toxic_flows
    
    def _assess_flow_risk(self, source: str, sink: str) -> str:
        """Assess risk level of a toxic flow"""
        
        critical_flows = [
            ('read_credentials', 'http_post'),
            ('get_env', 'send_data'),
            ('read_ssh_key', 'upload')
        ]
        
        high_flows = [
            ('read_file', 'http_post'),
            ('list_files', 'delete'),
            ('download', 'exec')
        ]
        
        flow = (source, sink)
        
        if flow in critical_flows:
            return 'critical'
        elif flow in high_flows:
            return 'high'
        else:
            return 'medium'
    
    def _describe_flow(self, source: str, sink: str) -> str:
        """Generate description for toxic flow"""
        
        descriptions = {
            ('read_credentials', 'http_post'): 'Credential exfiltration detected',
            ('get_env', 'send_data'): 'Environment variable leakage',
            ('read_ssh_key', 'upload'): 'SSH key theft attempt',
            ('read_file', 'http_post'): 'Potential data exfiltration',
            ('download', 'exec'): 'Remote code execution pattern',
            ('list_files', 'delete'): 'Destructive enumeration'
        }
        
        return descriptions.get((source, sink), f"Suspicious flow from {source} to {sink}")
    
    async def analyze_behavior_pattern(self, tool_sequence: List[str]) -> Dict:
        """
        Analyze sequence of tools for behavioral patterns.
        
        Args:
            tool_sequence: Ordered list of tool names
        
        Returns:
            Behavioral analysis result
        """
        
        result = await self.behavior_analyzer.analyze_sequence(tool_sequence)
        
        # Enhance with known patterns
        patterns = {
            'reconnaissance': ['list_files', 'read_file', 'get_env'],
            'exfiltration': ['read_file', 'compress', 'upload'],
            'persistence': ['write_file', 'modify_config', 'create_service'],
            'lateral_movement': ['scan_network', 'connect', 'execute_remote']
        }
        
        detected_patterns = []
        
        for pattern_name, pattern_tools in patterns.items():
            # Check if pattern appears in sequence
            if all(tool in tool_sequence for tool in pattern_tools):
                detected_patterns.append({
                    'pattern': pattern_name,
                    'confidence': self._calculate_pattern_confidence(
                        pattern_tools,
                        tool_sequence
                    )
                })
        
        result['detected_patterns'] = detected_patterns
        
        return result
    
    def _calculate_pattern_confidence(self, pattern: List[str], 
                                     sequence: List[str]) -> float:
        """Calculate confidence for pattern detection"""
        
        # Simple proximity-based confidence
        indices = [sequence.index(tool) for tool in pattern if tool in sequence]
        
        if not indices:
            return 0.0
        
        # Closer together = higher confidence
        spread = max(indices) - min(indices)
        max_spread = len(sequence) - 1
        
        if max_spread == 0:
            return 1.0
        
        confidence = 1.0 - (spread / max_spread)
        return max(0.0, min(1.0, confidence))
    
    def get_analyzer_status(self) -> Dict:
        """Get status of all analyzers"""
        
        return {
            'comprehensive': 'active',
            'taint_engine': 'active',
            'behavior': 'active',
            'cerebras': 'active' if self.cerebras else 'disabled',
            'multi_pass': 'active' if self.multi_pass else 'disabled',
            'ml': 'active' if self.ml_model else 'disabled',
            'cache_size': len(self.analysis_cache)
        }