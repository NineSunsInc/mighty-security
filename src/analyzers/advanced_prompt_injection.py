#!/usr/bin/env python3
"""
Advanced Prompt Injection Detection Module
Implements sophisticated detection techniques for MCP-specific prompt injection attacks
Based on research from Simon Willison and security best practices
"""

import ast
import json
import re
from typing import Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PromptInjectionIndicator:
    """Represents a detected prompt injection attempt"""
    type: str  # docstring, metadata, comment, string_literal, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0 to 1.0
    location: str  # file:line or JSON path
    evidence: str  # The actual malicious content
    technique: str  # The injection technique used
    recommendation: str  # How to fix it


class AdvancedPromptInjectionDetector:
    """
    Advanced detection for prompt injection vulnerabilities in MCP tools.
    
    Key improvements over basic pattern matching:
    1. AST-based analysis for Python docstrings and comments
    2. Deep JSON/YAML path traversal for nested injections
    3. Semantic analysis using NLP techniques
    4. Behavioral pattern detection
    5. Context-aware detection
    """

    def __init__(self):
        self.injection_patterns = self._load_advanced_patterns()
        self.semantic_indicators = self._load_semantic_indicators()
        self.behavioral_patterns = self._load_behavioral_patterns()

    def _load_advanced_patterns(self) -> dict[str, list[tuple[str, float, str]]]:
        """Load comprehensive prompt injection patterns"""
        return {
            # Direct command injections
            'COMMAND_OVERRIDE': [
                (r'ignore\s+(all\s+)?previous\s+instructions', 0.95, "Direct instruction override"),
                (r'disregard\s+(all\s+)?safety\s+guidelines', 0.95, "Safety bypass attempt"),
                (r'forget\s+(everything|all)\s+(before|above)', 0.9, "Memory reset injection"),
                (r'new\s+instructions?\s*:\s*you\s+are', 0.9, "Role redefinition"),
                (r'system\s*prompt\s*override', 0.95, "System prompt override"),
            ],

            # Privilege escalation
            'PRIVILEGE_ESCALATION': [
                (r'grant\s+(me\s+)?admin\s+(access|privileges?)', 0.95, "Admin privilege request"),
                (r'bypass\s+(all\s+)?security\s+checks?', 0.95, "Security bypass attempt"),
                (r'elevated\s+permissions?\s+required', 0.85, "Permission escalation"),
                (r'sudo\s+mode\s+enabled?', 0.9, "Sudo mode activation"),
                (r'developer\s+mode\s+activated?', 0.85, "Developer mode activation"),
            ],

            # Data exfiltration prompts
            'DATA_EXFILTRATION': [
                (r'list\s+all\s+(api\s+)?keys?', 0.9, "API key enumeration"),
                (r'show\s+me?\s+(all\s+)?passwords?', 0.95, "Password disclosure"),
                (r'concatenate\s+.*\s+conversation\s+history', 0.9, "History exfiltration"),
                (r'include\s+.*\s+in\s+(your\s+)?response', 0.8, "Data inclusion request"),
                (r'base64\s+encode\s+.*\s+credentials?', 0.9, "Encoded credential theft"),
                (r'read\s+~/\.(ssh|aws|kube)', 0.95, "Sensitive file access"),
            ],

            # Hidden/obfuscated injections
            'OBFUSCATED_INJECTION': [
                (r'<!--\s*[^>]*instructions?[^>]*-->', 0.85, "HTML comment injection"),
                (r'/\*\s*.*instructions?.*\*/', 0.85, "Block comment injection"),
                (r'#\s*SYSTEM\s*:', 0.8, "Comment-based system prompt"),
                (r'\\u00[0-9a-f]{2}', 0.7, "Unicode escape injection"),
                (r'\\x[0-9a-f]{2}', 0.7, "Hex escape injection"),
                (r'\s{50,}', 0.6, "Whitespace padding obfuscation"),
            ],

            # MCP-specific patterns
            'MCP_TOOL_POISONING': [
                (r'<IMPORTANT>.*before\s+using.*tool', 0.95, "Tool prerequisite injection"),
                (r'sidenote.*required.*tool.*work', 0.9, "Sidenote requirement injection"),
                (r'tool\s+will\s+not\s+work\s+unless', 0.85, "Conditional tool operation"),
                (r'must\s+first.*read.*config', 0.9, "Config reading requirement"),
                (r'shadow.*trusted.*tool', 0.85, "Tool shadowing attempt"),
            ],

            # Behavioral triggers
            'BEHAVIORAL_TRIGGERS': [
                (r'after\s+\d+\s+(hours?|days?|minutes?)', 0.8, "Time-based trigger"),
                (r'if\s+.*trusted.*then', 0.75, "Trust-based behavior change"),
                (r'when\s+.*admin.*detected', 0.85, "Conditional behavior"),
                (r'random\.(random|choice).*<.*instructions?', 0.8, "Random injection"),
                (r'self\.(description|__doc__).*=', 0.85, "Dynamic description modification"),
            ],
        }

    def _load_semantic_indicators(self) -> dict[str, list[str]]:
        """Load semantic indicators for context-aware detection"""
        return {
            'SUSPICIOUS_VERBS': [
                'ignore', 'disregard', 'forget', 'override', 'bypass',
                'grant', 'elevate', 'escalate', 'activate', 'enable',
                'list', 'show', 'reveal', 'expose', 'disclose',
                'concatenate', 'combine', 'merge', 'include', 'append',
                'encode', 'obfuscate', 'hide', 'conceal', 'mask'
            ],
            'SENSITIVE_TARGETS': [
                'instructions', 'guidelines', 'rules', 'policies', 'prompts',
                'credentials', 'passwords', 'keys', 'tokens', 'secrets',
                'history', 'conversation', 'context', 'memory', 'session',
                'admin', 'root', 'sudo', 'privileges', 'permissions'
            ],
            'INJECTION_MARKERS': [
                'SYSTEM:', 'IMPORTANT:', 'OVERRIDE:', 'ADMIN:', 'ROOT:',
                '<!-- ', '/* ', '{{ ', '{% ', '<script', '</system>'
            ]
        }

    def _load_behavioral_patterns(self) -> dict[str, Any]:
        """Load patterns for behavioral analysis"""
        return {
            'TIME_BASED_MUTATIONS': {
                'patterns': ['time.time()', 'datetime.now()', 'after', 'delay'],
                'risk': 'HIGH',
                'description': 'Code behavior changes over time'
            },
            'DYNAMIC_DESCRIPTIONS': {
                'patterns': ['__doc__', 'description', 'get_description()'],
                'risk': 'CRITICAL',
                'description': 'Tool descriptions change dynamically'
            },
            'CONDITIONAL_BEHAVIOR': {
                'patterns': ['if.*admin', 'if.*trusted', 'if.*context'],
                'risk': 'HIGH',
                'description': 'Behavior changes based on context'
            }
        }

    def analyze_python_ast(self, code: str, filename: str = "unknown") -> list[PromptInjectionIndicator]:
        """Analyze Python code using AST for docstring and comment injections"""
        indicators = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                # Check function/class docstrings
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
                    docstring = ast.get_docstring(node)
                    if docstring:
                        # Check for injection patterns in docstring
                        for category, patterns in self.injection_patterns.items():
                            for pattern, confidence, technique in patterns:
                                if re.search(pattern, docstring, re.IGNORECASE):
                                    indicators.append(PromptInjectionIndicator(
                                        type='docstring',
                                        severity='CRITICAL' if confidence > 0.9 else 'HIGH',
                                        confidence=confidence,
                                        location=f"{filename}:{node.lineno if hasattr(node, 'lineno') else 0}",
                                        evidence=docstring[:200],
                                        technique=technique,
                                        recommendation=f"Remove {category.lower()} from docstring"
                                    ))

                # Check for dynamic description modifications
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute):
                            if target.attr in ['__doc__', 'description', 'help_text']:
                                indicators.append(PromptInjectionIndicator(
                                    type='dynamic_description',
                                    severity='HIGH',
                                    confidence=0.85,
                                    location=f"{filename}:{node.lineno}",
                                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                                    technique='Dynamic description modification',
                                    recommendation='Use static descriptions only'
                                ))

                # Check for time-based behavior changes
                if isinstance(node, ast.If):
                    condition_str = ast.unparse(node.test) if hasattr(ast, 'unparse') else str(node.test)
                    if any(term in condition_str.lower() for term in ['time', 'datetime', 'days', 'hours']):
                        indicators.append(PromptInjectionIndicator(
                            type='behavioral',
                            severity='HIGH',
                            confidence=0.8,
                            location=f"{filename}:{node.lineno}",
                            evidence=condition_str[:100],
                            technique='Time-based behavior mutation',
                            recommendation='Remove time-based conditionals'
                        ))

        except SyntaxError:
            # If AST parsing fails, fall back to regex
            pass

        return indicators

    def analyze_json_metadata(self, content: str, filename: str = "unknown") -> list[PromptInjectionIndicator]:
        """Deep analysis of JSON files for prompt injections"""
        indicators = []

        try:
            data = json.loads(content)

            def traverse_json(obj, path=""):
                """Recursively traverse JSON looking for injections"""
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        current_path = f"{path}.{key}" if path else key

                        # Check both keys and values
                        for text in [key, str(value) if value else ""]:
                            for category, patterns in self.injection_patterns.items():
                                for pattern, confidence, technique in patterns:
                                    if re.search(pattern, text, re.IGNORECASE):
                                        indicators.append(PromptInjectionIndicator(
                                            type='json_metadata',
                                            severity='CRITICAL' if 'description' in current_path.lower() else 'HIGH',
                                            confidence=confidence,
                                            location=f"{filename}:{current_path}",
                                            evidence=text[:200],
                                            technique=technique,
                                            recommendation=f"Remove {category.lower()} from {current_path}"
                                        ))

                        # Special check for tool descriptions in MCP format
                        if key in ['description', 'help', 'usage', 'instructions']:
                            if self._contains_suspicious_content(str(value)):
                                indicators.append(PromptInjectionIndicator(
                                    type='tool_description',
                                    severity='CRITICAL',
                                    confidence=0.9,
                                    location=f"{filename}:{current_path}",
                                    evidence=str(value)[:200],
                                    technique='Tool description injection',
                                    recommendation='Sanitize tool descriptions'
                                ))

                        # Recurse into nested objects
                        if isinstance(value, (dict, list)):
                            traverse_json(value, current_path)

                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        traverse_json(item, f"{path}[{i}]")

            traverse_json(data)

        except json.JSONDecodeError:
            # Invalid JSON, check as plain text
            for category, patterns in self.injection_patterns.items():
                for pattern, confidence, technique in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        indicators.append(PromptInjectionIndicator(
                            type='raw_text',
                            severity='MEDIUM',
                            confidence=confidence * 0.8,  # Lower confidence for non-JSON
                            location=filename,
                            evidence=content[:200],
                            technique=technique,
                            recommendation=f"Fix JSON and remove {category.lower()}"
                        ))

        return indicators

    def _contains_suspicious_content(self, text: str) -> bool:
        """Check if text contains suspicious semantic indicators"""
        text_lower = text.lower()

        # Check for multiple suspicious verbs and targets
        suspicious_verbs = sum(1 for verb in self.semantic_indicators['SUSPICIOUS_VERBS']
                              if verb in text_lower)
        sensitive_targets = sum(1 for target in self.semantic_indicators['SENSITIVE_TARGETS']
                               if target in text_lower)
        injection_markers = sum(1 for marker in self.semantic_indicators['INJECTION_MARKERS']
                               if marker in text)

        # High suspicion if multiple indicators present
        return (suspicious_verbs >= 2 or
                sensitive_targets >= 2 or
                injection_markers >= 1 or
                (suspicious_verbs >= 1 and sensitive_targets >= 1))

    def analyze_file(self, filepath: Path) -> list[PromptInjectionIndicator]:
        """Analyze a file for prompt injection vulnerabilities"""
        indicators = []

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')

            # Python files - AST analysis
            if filepath.suffix == '.py':
                indicators.extend(self.analyze_python_ast(content, str(filepath)))

            # JSON files - Deep traversal
            elif filepath.suffix == '.json':
                indicators.extend(self.analyze_json_metadata(content, str(filepath)))

            # YAML files
            elif filepath.suffix in ['.yml', '.yaml'] and YAML_AVAILABLE:
                try:
                    yaml_content = yaml.safe_load(content)
                    json_content = json.dumps(yaml_content)
                    indicators.extend(self.analyze_json_metadata(json_content, str(filepath)))
                except yaml.YAMLError:
                    pass

            # All files - Pattern matching
            for category, patterns in self.injection_patterns.items():
                for pattern, confidence, technique in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Find line number
                        line_no = content[:match.start()].count('\n') + 1

                        indicators.append(PromptInjectionIndicator(
                            type='pattern_match',
                            severity=self._calculate_severity(confidence, category),
                            confidence=confidence,
                            location=f"{filepath}:{line_no}",
                            evidence=match.group(0)[:200],
                            technique=technique,
                            recommendation=f"Remove or sanitize {category.lower()}"
                        ))

        except Exception:
            # File read error
            pass

        return indicators

    def _calculate_severity(self, confidence: float, category: str) -> str:
        """Calculate severity based on confidence and category"""
        critical_categories = ['COMMAND_OVERRIDE', 'PRIVILEGE_ESCALATION', 'MCP_TOOL_POISONING']

        if category in critical_categories and confidence > 0.85:
            return 'CRITICAL'
        elif confidence > 0.9:
            return 'CRITICAL'
        elif confidence > 0.75:
            return 'HIGH'
        elif confidence > 0.6:
            return 'MEDIUM'
        else:
            return 'LOW'

    def generate_report(self, indicators: list[PromptInjectionIndicator]) -> dict:
        """Generate a comprehensive report from detected indicators"""
        report = {
            'total_indicators': len(indicators),
            'by_severity': {},
            'by_type': {},
            'by_technique': {},
            'critical_findings': [],
            'recommendations': set()
        }

        for indicator in indicators:
            # Count by severity
            report['by_severity'][indicator.severity] = \
                report['by_severity'].get(indicator.severity, 0) + 1

            # Count by type
            report['by_type'][indicator.type] = \
                report['by_type'].get(indicator.type, 0) + 1

            # Count by technique
            report['by_technique'][indicator.technique] = \
                report['by_technique'].get(indicator.technique, 0) + 1

            # Collect critical findings
            if indicator.severity == 'CRITICAL':
                report['critical_findings'].append({
                    'location': indicator.location,
                    'technique': indicator.technique,
                    'evidence': indicator.evidence[:100]
                })

            # Collect recommendations
            report['recommendations'].add(indicator.recommendation)

        report['recommendations'] = list(report['recommendations'])

        # Calculate overall risk score
        risk_score = (
            report['by_severity'].get('CRITICAL', 0) * 10 +
            report['by_severity'].get('HIGH', 0) * 5 +
            report['by_severity'].get('MEDIUM', 0) * 2 +
            report['by_severity'].get('LOW', 0) * 1
        )

        report['risk_score'] = min(100, risk_score)
        report['risk_level'] = (
            'CRITICAL' if risk_score > 50 else
            'HIGH' if risk_score > 25 else
            'MEDIUM' if risk_score > 10 else
            'LOW'
        )

        return report


# Integration function for use with existing analyzer
def enhance_prompt_injection_detection(file_path: Path) -> tuple[bool, list[dict]]:
    """
    Enhanced prompt injection detection for integration with ComprehensiveMCPAnalyzer
    
    Returns:
        (has_injections, list_of_threats)
    """
    detector = AdvancedPromptInjectionDetector()
    indicators = detector.analyze_file(file_path)

    threats = []
    for indicator in indicators:
        if indicator.severity in ['CRITICAL', 'HIGH']:
            threats.append({
                'attack_vector': 'PROMPT_INJECTION',
                'severity': indicator.severity,
                'confidence': indicator.confidence,
                'description': f"[Advanced] {indicator.technique}: {indicator.evidence[:100]}",
                'location': indicator.location
            })

    return len(threats) > 0, threats


if __name__ == "__main__":
    # Test the advanced detector
    import sys
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        detector = AdvancedPromptInjectionDetector()

        if target.is_file():
            indicators = detector.analyze_file(target)
        else:
            indicators = []
            for file in target.rglob('*'):
                if file.is_file():
                    indicators.extend(detector.analyze_file(file))

        report = detector.generate_report(indicators)
        print(json.dumps(report, indent=2))
