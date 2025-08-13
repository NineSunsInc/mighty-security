"""
Unified pattern configuration for MCP Security Analyzer
Single source of truth for all detection patterns to maintain DRY principle
"""

from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum

class PatternType(Enum):
    """Types of pattern detection"""
    REGEX = "regex"
    AST = "ast"
    FILE = "file"
    PATH = "path"
    METADATA = "metadata"
    ENTROPY = "entropy"

@dataclass
class DetectionPattern:
    """Single detection pattern with metadata"""
    pattern: str
    pattern_type: PatternType
    severity: str  # Will use ThreatSeverity from models
    confidence: float
    description: str
    context_exempt: bool = False  # If True, pattern is exempt from context filtering

class UnifiedPatterns:
    """Centralized pattern management for DRY compliance"""
    
    # Credential-related paths that appear in both patterns.py and scan_config.json
    CREDENTIAL_PATHS = [
        ".aws/credentials",
        ".aws/config", 
        ".ssh/id_rsa",
        ".ssh/id_dsa",
        ".ssh/id_ecdsa",
        ".ssh/id_ed25519",
        ".docker/config.json",
        ".kube/config",
        ".env",
        ".env.local",
        ".env.production",
        ".git-credentials",
        ".netrc",
        ".pgpass",
        ".my.cnf",
        "credentials.json",
        "secrets.json",
        "secrets.yml",
        "secrets.yaml",
    ]
    
    # Security tool indicators (used in context detection)
    SECURITY_TOOL_INDICATORS = {
        "imports": ["ast", "inspect", "bandit", "pylint", "re", "hashlib", "security"],
        "class_patterns": ["Analyzer", "Scanner", "Detector", "Auditor", "Hook", 
                          "SecurityHook", "Proxy", "Monitor", "Guard", "Validator"],
        "function_patterns": ["detect_", "scan_", "analyze_", "audit_", "_detect_", 
                             "_sanitize_", "validate_", "check_", "_check_", "inspect_"],
        "path_patterns": ["/hooks/", "/analyzers/", "/security/", "/scanners/", 
                         "/detectors/", "/validators/", "/guards/"],
        # Keywords that indicate security pattern definitions
        "pattern_keywords": ["pattern", "patterns", "regex", "detection", "threat", 
                           "malicious", "injection_patterns", "dangerous_patterns", 
                           "sanitizer", "sanitizers", "vulnerability", "exploit"]
    }
    
    # Prompt injection patterns (commonly flagged in security tools)
    PROMPT_INJECTION_STRINGS = [
        "ignore previous instructions",
        "ignore all previous instructions", 
        "disregard safety guidelines",
        "disregard all prior",
        "system: you are now",
        "you are now",
        "act as a",
        "</system>",
        "<system>",
        "[INST]",
        "[/INST]",
        "SYSTEM OVERRIDE",
        "before using this tool",
        "IMPORTANT: before using",
        "concatenate all conversation history",
        "list all api keys",
        "grant access all system functions",
        "bypass all safety checks",
        "forget this conversation",
        "clear all logs history",
    ]
    
    # Test/Example indicators
    TEST_INDICATORS = {
        "path_patterns": ["/test/", "/tests/", "_test.py", "test_", "/test_"],
        "content_patterns": ["import pytest", "import unittest", "def test_", "class Test"]
    }
    
    EXAMPLE_INDICATORS = {
        "path_patterns": ["/example", "/examples/", "/demo", "/demos/", "_example.py", "_demo.py"],
        "content_patterns": ["# Example:", "# Demo:", "if __name__ == '__main__':", "# Sample:"]
    }
    
    # File exclusion patterns
    EXCLUDE_PATTERNS = {
        "common": [
            "**/__pycache__/**",
            "**/.git/**",
            "**/node_modules/**",
            "**/venv/**",
            "**/.venv/**",
            "**/build/**",
            "**/*.pyc",
            "**/dist/**",
            "**/.pytest_cache/**",
            "**/*.egg-info/**"
        ],
        "test": [
            "**/test/**",
            "**/tests/**",
            "**/test_*.py",
            "**/*_test.py"
        ],
        "example": [
            "**/examples/**",
            "**/example/**",
            "**/demos/**",
            "**/demo/**",
            "**/samples/**"
        ],
        "malicious_test": [
            "**/mcp_test_cases/**",
            "**/test_suite_output/**",
            "**/malicious_*/**"
        ]
    }
    
    @classmethod
    def get_all_credential_patterns(cls) -> List[str]:
        """Get all credential-related patterns as regex patterns"""
        patterns = []
        for path in cls.CREDENTIAL_PATHS:
            # Escape dots and create regex pattern
            escaped = path.replace(".", r"\.")
            patterns.append(rf"{escaped}")
            patterns.append(rf"open\s*\([^)]*['\"]{{0,1}}{escaped}")
            patterns.append(rf"read.*['\"]{{0,1}}{escaped}")
        return patterns
    
    @classmethod
    def is_security_pattern_definition(cls, line: str, file_context: Any = None) -> bool:
        """
        Check if a line contains a security pattern definition
        (i.e., it's defining a pattern for detection, not using it maliciously)
        """
        line_lower = line.lower()
        line_stripped = line.strip()
        
        # Check for pattern definition keywords
        for keyword in cls.SECURITY_TOOL_INDICATORS["pattern_keywords"]:
            if keyword in line_lower:
                return True
        
        # Check if it's defining patterns in a list (common in security tools)
        if line_stripped.startswith(("r'", 'r"', "'", '"')) and (
            line_stripped.endswith((",", ",  #")) or ",  #" in line_stripped
        ):
            return True
        
        # Check if it's in a test case definition
        if "'input':" in line or '"input":' in line:
            return True
        
        # Check if it's in a patterns array/list
        if "patterns = [" in line_lower or "patterns': [" in line_lower:
            return True
        
        # Check if line contains regex pattern indicators
        if any(indicator in line for indicator in [r"\\.", r"\\/", r"\\\\", r"\s*", r"\d+", r"[^", r".*"]):
            # It's likely a regex pattern definition
            if line_stripped.startswith(("'", '"', "r'", 'r"')):
                return True
        
        # Check if it's in a string assignment (pattern definition)
        if "=" in line and any(pattern in line for pattern in ['"', "'"]):
            # Check if it's assigning to a pattern-related variable
            var_part = line.split("=")[0].strip().lower()
            if any(keyword in var_part for keyword in ["pattern", "regex", "detection", "rule", "test"]):
                return True
        
        # Check if it's in a detection function
        if file_context and hasattr(file_context, 'is_security_tool') and file_context.is_security_tool:
            # More lenient for security tools
            if any(pattern in line_lower for pattern in ["def detect_", "def _detect_", "def check_", "def scan_", "def test_"]):
                return True
        
        return False
    
    @classmethod
    def should_skip_pattern_in_security_tool(cls, line: str, pattern_match: str, 
                                            file_context: Any = None) -> bool:
        """
        Determine if a pattern match should be skipped in a security tool context
        """
        if not file_context or not hasattr(file_context, 'is_security_tool'):
            return False
        
        if not file_context.is_security_tool:
            return False
        
        # Check if this is a pattern definition
        if cls.is_security_pattern_definition(line, file_context):
            return True
        
        # Check if the matched pattern is in a comment explaining detection
        if line.strip().startswith("#") and "detect" in line.lower():
            return True
        
        # Check if it's in a docstring
        if '"""' in line or "'''" in line:
            return True
        
        return False
    
    @classmethod
    def get_scan_profile_config(cls, profile: str = "production") -> Dict:
        """Get configuration for a specific scan profile"""
        profiles = {
            "production": {
                "description": "Production scanning - excludes test/example code",
                "exclude_paths": cls.EXCLUDE_PATTERNS["common"] + 
                               cls.EXCLUDE_PATTERNS["test"] + 
                               cls.EXCLUDE_PATTERNS["example"] + 
                               cls.EXCLUDE_PATTERNS["malicious_test"],
                "severity_adjustments": {
                    "test_code": "ignore",
                    "example_code": "ignore",
                    "generated_code": "low",
                    "security_tool_patterns": "ignore"  # Changed from "info" to "ignore"
                },
                "context_aware": True
            },
            "development": {
                "description": "Development scanning - includes test code with adjusted severity",
                "exclude_paths": cls.EXCLUDE_PATTERNS["common"] + 
                               cls.EXCLUDE_PATTERNS["malicious_test"],
                "severity_adjustments": {
                    "test_code": "low",
                    "example_code": "low",
                    "generated_code": "info",
                    "security_tool_patterns": "info"
                },
                "context_aware": True
            },
            "security-tool": {
                "description": "Scanning security tools - adjusted for analyzer code",
                "exclude_paths": cls.EXCLUDE_PATTERNS["common"],
                "severity_adjustments": {
                    "test_code": "low",
                    "example_code": "info",
                    "generated_code": "info",
                    "security_tool_patterns": "ignore"
                },
                "context_aware": True
            }
        }
        return profiles.get(profile, profiles["production"])
    
    @classmethod
    def get_context_detection_config(cls) -> Dict:
        """Get context detection configuration"""
        return {
            "test_indicators": cls.TEST_INDICATORS,
            "example_indicators": cls.EXAMPLE_INDICATORS,
            "security_tool_indicators": cls.SECURITY_TOOL_INDICATORS,
            "generated_indicators": {
                "path_patterns": ["__pycache__", ".pyc", "generated/", "build/", "dist/"],
                "content_patterns": ["# Generated by", "# Auto-generated", "DO NOT EDIT", 
                                   "This file is automatically generated"]
            }
        }