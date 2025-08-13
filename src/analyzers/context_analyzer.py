"""
Context-aware analysis for reducing false positives in security scanning.
Detects test code, examples, security tools, and other contexts.
"""

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any
import fnmatch


@dataclass
class FileContext:
    """Context information about a file being analyzed"""
    is_test: bool = False
    is_example: bool = False
    is_security_tool: bool = False
    is_generated: bool = False
    has_security_imports: bool = False
    purpose: str = "unknown"
    confidence: float = 0.0
    indicators: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []


class ContextAnalyzer:
    """Analyzes file context to adjust threat detection sensitivity"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self._compile_patterns()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from JSON file"""
        if config_path is None:
            # Look for config in standard locations
            for path in [
                Path(__file__).parent.parent.parent / "scan_config.json",
                Path.cwd() / "scan_config.json",
                Path.home() / ".secure-toolings" / "scan_config.json"
            ]:
                if path.exists():
                    config_path = path
                    break
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # Default minimal config if no file found
        return {
            "context_detection": {
                "test_indicators": {
                    "path_patterns": ["/test/", "/tests/", "_test.py", "test_"],
                    "content_patterns": ["import pytest", "import unittest"]
                },
                "example_indicators": {
                    "path_patterns": ["/example", "/demo", "_example.py"]
                },
                "security_tool_indicators": {
                    "imports": ["ast", "inspect", "bandit"],
                    "class_patterns": ["Analyzer", "Scanner", "Detector"],
                    "function_patterns": ["detect_", "scan_", "analyze_"]
                }
            }
        }
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency"""
        self.compiled_patterns = {}
        
        indicators = self.config.get("context_detection", {})
        
        # Compile function patterns
        if "security_tool_indicators" in indicators:
            func_patterns = indicators["security_tool_indicators"].get("function_patterns", [])
            self.compiled_patterns["functions"] = [
                re.compile(rf"{p}\w+") for p in func_patterns
            ]
            
            class_patterns = indicators["security_tool_indicators"].get("class_patterns", [])
            self.compiled_patterns["classes"] = [
                re.compile(rf"class\s+.*{p}.*\(") for p in class_patterns
            ]
    
    def get_file_context(self, file_path: str, content: Optional[str] = None) -> FileContext:
        """Analyze a file and return its context"""
        context = FileContext()
        file_path = str(file_path)
        
        # Path-based detection
        context.is_test = self._is_test_file(file_path)
        if context.is_test:
            context.indicators.append("test_path")
            
        context.is_example = self._is_example_file(file_path)
        if context.is_example:
            context.indicators.append("example_path")
            
        context.is_generated = self._is_generated_file(file_path)
        if context.is_generated:
            context.indicators.append("generated_path")
        
        # Content-based detection if content provided
        if content:
            # Parse AST safely
            try:
                tree = ast.parse(content)
                context.is_security_tool = self._detect_security_tool(tree, content)
                context.has_security_imports = self._check_security_imports(tree)
                
                # Check content patterns for test code
                if not context.is_test:
                    context.is_test = self._detect_test_content(content)
                    if context.is_test:
                        context.indicators.append("test_content")
                        
            except (SyntaxError, ValueError):
                # If we can't parse, use simpler string matching
                context.is_security_tool = self._detect_security_tool_simple(content)
                context.has_security_imports = any(
                    imp in content for imp in 
                    self.config["context_detection"]["security_tool_indicators"]["imports"]
                )
        
        # Determine purpose
        if context.is_test:
            context.purpose = "testing"
            context.confidence = 0.95
        elif context.is_example:
            context.purpose = "example"
            context.confidence = 0.9
        elif context.is_security_tool:
            context.purpose = "security_analysis"
            context.confidence = 0.85
        elif context.is_generated:
            context.purpose = "generated"
            context.confidence = 0.9
        else:
            context.purpose = "production"
            context.confidence = 0.7
            
        return context
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file based on path"""
        indicators = self.config["context_detection"]["test_indicators"]["path_patterns"]
        return any(pattern in file_path.lower() for pattern in indicators)
    
    def _is_example_file(self, file_path: str) -> bool:
        """Check if file is an example file based on path"""
        indicators = self.config["context_detection"]["example_indicators"]["path_patterns"]
        path_lower = file_path.lower()
        # Check if any pattern is found in the path
        for pattern in indicators:
            if pattern in path_lower:
                return True
        # Check if 'examples' or 'example' appears as a directory name
        path_parts = path_lower.split('/')
        for part in path_parts:
            if part in ['examples', 'example', 'demo', 'demos', 'sample', 'samples']:
                return True
        return False
    
    def _is_generated_file(self, file_path: str) -> bool:
        """Check if file is generated code"""
        if "generated_code_indicators" not in self.config["context_detection"]:
            return False
        indicators = self.config["context_detection"]["generated_code_indicators"]["path_patterns"]
        return any(pattern in file_path.lower() for pattern in indicators)
    
    def _detect_test_content(self, content: str) -> bool:
        """Detect test code from content patterns"""
        patterns = self.config["context_detection"]["test_indicators"]["content_patterns"]
        return any(pattern in content for pattern in patterns)
    
    def _detect_security_tool(self, ast_tree: ast.AST, content: str) -> bool:
        """Detect if this is a security analysis tool"""
        indicators = self.config["context_detection"]["security_tool_indicators"]
        
        # Check imports
        security_imports = 0
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in indicators["imports"]:
                        security_imports += 1
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in indicators["imports"]:
                    security_imports += 1
        
        # Lower threshold for imports combined with other indicators
        if security_imports >= 1:
            # Check class names
            for class_pattern in indicators["class_patterns"]:
                if class_pattern in content:
                    return True
            
            # Check function patterns
            for func_pattern in indicators["function_patterns"]:
                if func_pattern in content:
                    return True
        
        # Check class names even without imports
        for pattern in self.compiled_patterns.get("classes", []):
            if pattern.search(content):
                return True
        
        # Check function names
        security_functions = 0
        for pattern in self.compiled_patterns.get("functions", []):
            if pattern.search(content):
                security_functions += 1
        
        # Lower threshold if content contains security terms
        if "vulnerability" in content.lower() or "scanner" in content.lower() or "analyzer" in content.lower():
            return security_functions >= 2
        
        return security_functions >= 3
    
    def _detect_security_tool_simple(self, content: str) -> bool:
        """Simple string-based detection when AST parsing fails"""
        indicators = self.config["context_detection"]["security_tool_indicators"]
        
        # Count security-related terms
        security_terms = 0
        for term in ["analyzer", "scanner", "detector", "security", "vulnerability", "threat"]:
            security_terms += content.lower().count(term)
        
        return security_terms >= 5
    
    def _check_security_imports(self, ast_tree: ast.AST) -> bool:
        """Check if file has security-related imports"""
        indicators = self.config["context_detection"]["security_tool_indicators"]["imports"]
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in indicators:
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in indicators:
                    return True
        
        return False
    
    def should_exclude_file(self, file_path: str, profile: str = "production") -> tuple[bool, str]:
        """Check if file should be excluded based on profile"""
        if profile not in self.config.get("scan_profiles", {}):
            return False, "Unknown profile"
        
        exclude_patterns = self.config["scan_profiles"][profile].get("exclude_paths", [])
        
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(f"**/{file_path}", pattern):
                return True, f"Excluded by pattern: {pattern}"
        
        return False, "Not excluded"
    
    def get_severity_adjustment(self, context: FileContext, profile: str = "production") -> str:
        """Get severity adjustment action based on context and profile"""
        if profile not in self.config.get("scan_profiles", {}):
            return "none"
        
        adjustments = self.config["scan_profiles"][profile].get("severity_adjustments", {})
        
        if context.is_test and "test_code" in adjustments:
            return adjustments["test_code"]
        elif context.is_example and "example_code" in adjustments:
            return adjustments["example_code"]
        elif context.is_generated and "generated_code" in adjustments:
            return adjustments["generated_code"]
        elif context.is_security_tool and "security_tool_patterns" in adjustments:
            return adjustments["security_tool_patterns"]
        
        return "none"