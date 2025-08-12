#!/usr/bin/env python3
"""
Smart Context Optimizer for LLM Analysis
Intelligently ranks files for maximum threat detection with SOTA models
"""

from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass, field
import re
import math
from enum import Enum

class FileImportance(Enum):
    """File importance levels for LLM analysis"""
    CRITICAL = 5  # Must analyze - entry points, handlers
    HIGH = 4      # Should analyze - has threats, network ops
    MEDIUM = 3    # Good to analyze - complex logic
    LOW = 2       # Optional - utilities
    MINIMAL = 1   # Skip unless needed

@dataclass
class FileRankingScore:
    """Detailed ranking score for a file"""
    file_path: str
    total_score: float
    importance: FileImportance
    
    # Scoring components
    threat_score: float = 0.0      # Based on static analysis threats
    complexity_score: float = 0.0   # Code complexity metrics
    sensitivity_score: float = 0.0  # Handles sensitive operations
    mcp_relevance: float = 0.0      # MCP-specific patterns
    network_score: float = 0.0      # Network operations
    obfuscation_score: float = 0.0  # Potential hiding
    dependency_score: float = 0.0   # How many files depend on this
    
    # Metadata for LLM
    risk_indicators: List[str] = field(default_factory=list)
    key_functions: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)
    
    def get_context_summary(self) -> Dict[str, Any]:
        """Get context summary for LLM"""
        return {
            'importance': self.importance.name,
            'scores': {
                'threat': self.threat_score,
                'complexity': self.complexity_score,
                'sensitivity': self.sensitivity_score,
                'mcp': self.mcp_relevance
            },
            'risks': self.risk_indicators,
            'key_functions': self.key_functions[:5],  # Top 5
            'external_calls': self.external_calls[:5]
        }

@dataclass 
class AnalysisTracker:
    """Track LLM analysis progress and results"""
    total_files: int
    analyzed_files: int = 0
    findings_by_file: Dict[str, List[Any]] = field(default_factory=dict)
    aggregate_risk_score: float = 0.0
    critical_findings: List[Any] = field(default_factory=list)
    
    def add_file_result(self, file_path: str, findings: List[Any], risk_score: float):
        """Add analysis result for a file"""
        self.analyzed_files += 1
        self.findings_by_file[file_path] = findings
        
        # Update aggregate risk (weighted average)
        self.aggregate_risk_score = (
            (self.aggregate_risk_score * (self.analyzed_files - 1) + risk_score) 
            / self.analyzed_files
        )
        
        # Track critical findings
        for finding in findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                self.critical_findings.append({
                    'file': file_path,
                    'finding': finding
                })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary"""
        return {
            'progress': f"{self.analyzed_files}/{self.total_files}",
            'aggregate_risk': self.aggregate_risk_score,
            'critical_count': len(self.critical_findings),
            'files_with_issues': len([f for f in self.findings_by_file.values() if f])
        }

class SmartFileRanker:
    """Intelligent file ranking for optimal LLM analysis"""
    
    def __init__(self):
        self.pattern_weights = {
            # Critical patterns that need LLM review
            'tool_definition': (r'@tool|class.*Tool|def.*handle_tool', 0.9),
            'command_exec': (r'exec\(|eval\(|subprocess\.|os\.system', 0.85),
            'network_ops': (r'requests\.|urlopen|socket\.|httpx', 0.7),
            'file_ops': (r'open\(|Path\(.*\)\..*write|shutil\.|os\.remove', 0.6),
            'credential_access': (r'\.env|api_key|secret|password|token', 0.8),
            'prompt_patterns': (r'system:|Human:|Assistant:|<\|.*\|>', 0.75),
            'obfuscation': (r'base64|marshal\.loads|pickle\.loads|exec.*decode', 0.8),
            'mcp_handlers': (r'handle_|execute_|process_request|on_message', 0.7),
        }
        
    def rank_files_for_analysis(
        self,
        files: Dict[str, str],  # file_path -> content
        static_threats: List[Any],
        semantic_graph: Optional[Any] = None,
        max_files: Optional[int] = None,  # Optional limit, defaults to None (all files)
        min_score_threshold: float = 0.01  # Minimum score to include
    ) -> List[FileRankingScore]:
        """Rank files by importance for LLM analysis
        
        Args:
            files: Map of file paths to content
            static_threats: List of detected threats
            semantic_graph: Optional dependency graph
            max_files: Optional limit on number of files (None = no limit)
            min_score_threshold: Minimum score to include file (filters out noise)
        
        Returns:
            Sorted list of FileRankingScore objects
        """
        
        rankings = []
        threat_map = self._build_threat_map(static_threats)
        dependency_map = self._build_dependency_map(semantic_graph) if semantic_graph else {}
        
        for file_path, content in files.items():
            # Skip non-code files
            if not self._is_code_file(file_path):
                continue
                
            # Calculate detailed scoring
            ranking = self._calculate_ranking(
                file_path,
                content,
                threat_map.get(file_path, []),
                dependency_map.get(file_path, 0)
            )
            
            # Only include files above minimum threshold
            if ranking.total_score >= min_score_threshold:
                rankings.append(ranking)
        
        # Sort by total score (highest first)
        rankings.sort(key=lambda x: x.total_score, reverse=True)
        
        # Apply optional limit
        if max_files is not None:
            return rankings[:max_files]
        return rankings
    
    def _calculate_ranking(
        self,
        file_path: str,
        content: str,
        threats: List[Any],
        dependency_count: int
    ) -> FileRankingScore:
        """Calculate detailed ranking for a file"""
        
        ranking = FileRankingScore(file_path=file_path, total_score=0.0, importance=FileImportance.LOW)
        
        # Deprioritize test and package files using shared constants
        try:
            from src.analyzers.shared_constants import should_skip_for_llm
        except ImportError:
            # Fallback import
            import sys
            from pathlib import Path as PathLib
            sys.path.append(str(PathLib(__file__).parent.parent.parent))
            from src.analyzers.shared_constants import should_skip_for_llm
        
        # Check if this file should be deprioritized
        should_deprioritize = should_skip_for_llm(file_path)
        
        if should_deprioritize:
            # Test/package/vendor files get minimal priority
            ranking.total_score = 0.01
            ranking.importance = FileImportance.MINIMAL
            return ranking
        
        # No reduction for important files
        priority_reduction = 1.0
        
        # 1. Threat Score (0-1)
        if threats:
            critical = sum(1 for t in threats if self._get_severity(t) == 'CRITICAL')
            high = sum(1 for t in threats if self._get_severity(t) == 'HIGH')
            ranking.threat_score = min(1.0, (critical * 0.3 + high * 0.15))
            ranking.risk_indicators = [self._get_attack_vector(t) for t in threats[:5]]
        
        # 2. Complexity Score (0-1)
        ranking.complexity_score = self._calculate_complexity(content)
        
        # 3. Sensitivity Score (0-1)
        sensitive_patterns = 0
        for pattern_name, (pattern, weight) in self.pattern_weights.items():
            if re.search(pattern, content, re.IGNORECASE):
                sensitive_patterns += weight
                ranking.risk_indicators.append(pattern_name)
        ranking.sensitivity_score = min(1.0, sensitive_patterns / 3)
        
        # 4. MCP Relevance (0-1)
        mcp_indicators = [
            'tool' in file_path.lower(),
            'handler' in file_path.lower(),
            'mcp' in file_path.lower(),
            '@tool' in content,
            'handle_' in content,
            'execute_' in content
        ]
        ranking.mcp_relevance = sum(mcp_indicators) / len(mcp_indicators)
        
        # 5. Network Score (0-1)
        network_patterns = ['requests', 'urllib', 'socket', 'http', 'websocket']
        ranking.network_score = sum(1 for p in network_patterns if p in content.lower()) / len(network_patterns)
        
        # 6. Obfuscation Score (0-1)
        ranking.obfuscation_score = self._detect_obfuscation_level(content)
        
        # 7. Dependency Score (0-1)
        ranking.dependency_score = min(1.0, dependency_count / 10)
        
        # Extract key functions and calls
        ranking.key_functions = self._extract_functions(content)
        ranking.external_calls = self._extract_external_calls(content)
        
        # Calculate total score with weights
        weights = {
            'threat': 0.25,
            'complexity': 0.10,
            'sensitivity': 0.20,
            'mcp': 0.15,
            'network': 0.10,
            'obfuscation': 0.15,
            'dependency': 0.05
        }
        
        ranking.total_score = (
            weights['threat'] * ranking.threat_score +
            weights['complexity'] * ranking.complexity_score +
            weights['sensitivity'] * ranking.sensitivity_score +
            weights['mcp'] * ranking.mcp_relevance +
            weights['network'] * ranking.network_score +
            weights['obfuscation'] * ranking.obfuscation_score +
            weights['dependency'] * ranking.dependency_score
        ) * priority_reduction  # Apply reduction for pkg files
        
        # Determine importance level
        if ranking.total_score >= 0.7:
            ranking.importance = FileImportance.CRITICAL
        elif ranking.total_score >= 0.5:
            ranking.importance = FileImportance.HIGH
        elif ranking.total_score >= 0.3:
            ranking.importance = FileImportance.MEDIUM
        elif ranking.total_score >= 0.15:
            ranking.importance = FileImportance.LOW
        else:
            ranking.importance = FileImportance.MINIMAL
        
        return ranking
    
    def _calculate_complexity(self, content: str) -> float:
        """Calculate code complexity score"""
        lines = content.split('\n')
        
        # Simple complexity metrics
        metrics = {
            'lines': len(lines),
            'functions': len(re.findall(r'\bdef\s+\w+', content)),
            'classes': len(re.findall(r'\bclass\s+\w+', content)),
            'conditionals': len(re.findall(r'\bif\s+|elif\s+|else:', content)),
            'loops': len(re.findall(r'\bfor\s+|\bwhile\s+', content)),
            'try_blocks': len(re.findall(r'\btry:', content)),
        }
        
        # Normalize to 0-1 score
        complexity = 0.0
        
        # Lines of code contribution
        if 50 < metrics['lines'] < 500:
            complexity += 0.3
        elif metrics['lines'] >= 500:
            complexity += 0.2
        
        # Cyclomatic complexity approximation
        cyclomatic = metrics['conditionals'] + metrics['loops']
        if cyclomatic > 10:
            complexity += 0.3
        elif cyclomatic > 5:
            complexity += 0.2
        
        # Multiple classes/functions
        if metrics['classes'] > 2 or metrics['functions'] > 5:
            complexity += 0.2
        
        # Error handling
        if metrics['try_blocks'] > 2:
            complexity += 0.2
        
        return min(1.0, complexity)
    
    def _detect_obfuscation_level(self, content: str) -> float:
        """Detect obfuscation level in code"""
        score = 0.0
        
        # Check for obfuscation indicators
        indicators = {
            'single_char_vars': len(re.findall(r'\b[a-z_]\s*=', content)) / max(content.count('='), 1),
            'hex_strings': len(re.findall(r'\\x[0-9a-f]{2}', content)) / 100,
            'base64': 1.0 if 'base64' in content else 0,
            'eval_exec': (content.count('eval') + content.count('exec')) / 10,
            'long_strings': len(re.findall(r'["\'][^"\']{200,}["\']', content)) / 5,
            'unicode_escapes': len(re.findall(r'\\u[0-9a-f]{4}', content)) / 50
        }
        
        # Weight and sum indicators
        weights = {
            'single_char_vars': 0.2,
            'hex_strings': 0.2,
            'base64': 0.15,
            'eval_exec': 0.25,
            'long_strings': 0.1,
            'unicode_escapes': 0.1
        }
        
        for indicator, value in indicators.items():
            score += weights[indicator] * min(1.0, value)
        
        return min(1.0, score)
    
    def _extract_functions(self, content: str) -> List[str]:
        """Extract function names from code"""
        # Python functions
        functions = re.findall(r'def\s+(\w+)', content)
        # JavaScript functions
        functions.extend(re.findall(r'function\s+(\w+)', content))
        functions.extend(re.findall(r'(\w+)\s*:\s*(?:async\s+)?function', content))
        return list(set(functions))
    
    def _extract_external_calls(self, content: str) -> List[str]:
        """Extract external API/library calls"""
        calls = []
        
        # Common dangerous calls
        patterns = [
            r'requests\.\w+',
            r'urllib\.\w+',
            r'subprocess\.\w+',
            r'os\.\w+',
            r'eval\(',
            r'exec\(',
            r'__import__',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            calls.extend(matches)
        
        return list(set(calls))
    
    def _build_threat_map(self, threats: List[Any]) -> Dict[str, List[Any]]:
        """Build map of threats by file"""
        threat_map = {}
        for threat in threats:
            file_path = getattr(threat, 'file_path', None) or threat.get('file_path')
            if file_path:
                if file_path not in threat_map:
                    threat_map[file_path] = []
                threat_map[file_path].append(threat)
        return threat_map
    
    def _build_dependency_map(self, semantic_graph: Any) -> Dict[str, int]:
        """Build map of file dependencies"""
        # Placeholder - would use actual graph analysis
        return {}
    
    def _is_code_file(self, file_path: str) -> bool:
        """Check if file is a code file"""
        # Skip test files and vendor files
        if any(x in file_path.lower() for x in ['_test.', '/test/', '/tests/', '/vendor/', '/.git/']):
            return False
            
        try:
            from src.analyzers.shared_constants import is_code_file
        except ImportError:
            # Try relative import
            import sys
            from pathlib import Path
            sys.path.append(str(Path(__file__).parent.parent))
            from shared_constants import is_code_file
        return is_code_file(file_path)
    
    def _get_severity(self, threat: Any) -> str:
        """Extract severity from threat object"""
        if hasattr(threat, 'severity'):
            return str(threat.severity)
        return threat.get('severity', 'MEDIUM')
    
    def _get_attack_vector(self, threat: Any) -> str:
        """Extract attack vector from threat"""
        if hasattr(threat, 'attack_vector'):
            return str(threat.attack_vector)
        return threat.get('attack_vector', 'unknown')