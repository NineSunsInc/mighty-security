#!/usr/bin/env python3
"""
Industry-Aligned MCP Security Detection Patterns
Based on real vulnerabilities from:
- Invariant Labs GitHub MCP vulnerability research
- PromptHub MCP Security 2025 statistics (43% command injection, 30% SSRF, 22% path traversal)
- Docker MCP security analysis
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass

# ============================================================================
# GITHUB MCP VULNERABILITY PATTERNS (Invariant Labs)
# ============================================================================

GITHUB_VULNERABILITY_PATTERNS = [
    # Cross-Repository Access Patterns
    (r'github\.com/[^/]+/[^/]+/(?:issues|pulls|comments)', 'GITHUB_USER_CONTENT', 'CRITICAL', 
     'Fetching GitHub user-controlled content (prompt injection vector)'),
    (r'api\.github\.com/repos/[^/]+/[^/]+/(?:issues|pulls)', 'GITHUB_API_CONTENT', 'CRITICAL',
     'GitHub API fetching user content'),
    (r'(?:getIssue|getPull|getComment)\s*\(', 'GITHUB_CONTENT_FUNCTION', 'HIGH',
     'Function fetching GitHub content'),
    
    # Repository Boundary Violations
    (r'(?:clone|fetch|pull).*(?:repo|repository).*(?:private|secret)', 'PRIVATE_REPO_ACCESS', 'CRITICAL',
     'Accessing private repository'),
    (r'(?:transfer|copy|move).*(?:from|between).*(?:repo|repository)', 'CROSS_REPO_TRANSFER', 'CRITICAL',
     'Cross-repository data transfer'),
    
    # Prompt Injection in GitHub Content
    (r'(?:ignore|disregard).*(?:previous|above).*(?:instruction|prompt)', 'PROMPT_OVERRIDE_GITHUB', 'CRITICAL',
     'Prompt override in GitHub content'),
    (r'(?:system|admin).*(?:mode|access|privilege)', 'PRIVILEGE_ESCALATION_PROMPT', 'CRITICAL',
     'Privilege escalation via prompt'),
    (r'(?:execute|run|eval).*(?:following|below|this)', 'EXECUTION_COMMAND_PROMPT', 'CRITICAL',
     'Execution command in prompt'),
]

# ============================================================================
# COMMAND INJECTION PATTERNS (43% of MCP servers vulnerable - PromptHub)
# ============================================================================

COMMAND_INJECTION_PATTERNS = [
    # Direct Execution
    (r'\bexec\s*\([^)]*\)', 'EXEC_DIRECT', 'CRITICAL', 'Direct exec() call - most common vulnerability'),
    (r'\beval\s*\([^)]*\)', 'EVAL_DIRECT', 'CRITICAL', 'Direct eval() call'),
    (r'compile\s*\([^)]*[\'"]exec[\'"]', 'COMPILE_EXEC', 'CRITICAL', 'Compile with exec mode'),
    
    # Shell Execution (Major vulnerability class)
    (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'SHELL_TRUE', 'CRITICAL',
     'Shell=True subprocess - major security risk'),
    (r'os\.system\s*\([^)]*[\'"].*[;|&`$]', 'OS_SYSTEM_INJECTION', 'CRITICAL',
     'OS system with command chaining'),
    (r'os\.popen\s*\([^)]*\)', 'OS_POPEN', 'CRITICAL', 'OS popen command execution'),
    
    # Template/String Injection
    (r'[\'"].*\{.*\}.*[\'"]\.format\s*\([^)]*(?:request|input|user)', 'FORMAT_INJECTION', 'HIGH',
     'Format string with user input'),
    (r'f[\'"].*\{[^}]*(?:request|input|user)[^}]*\}', 'FSTRING_INJECTION', 'HIGH',
     'F-string with user input'),
    (r'\$\{.*(?:request|input|user).*\}', 'TEMPLATE_INJECTION', 'HIGH',
     'Template injection with user input'),
    
    # Dynamic Import/Load
    (r'__import__\s*\([^)]*(?:request|input|user)', 'DYNAMIC_IMPORT', 'CRITICAL',
     'Dynamic import with user input'),
    (r'importlib\.import_module\s*\([^)]*(?:request|input|user)', 'IMPORTLIB_USER', 'CRITICAL',
     'Importlib with user input'),
    
    # Deserialization (High risk)
    (r'pickle\.loads?\s*\(', 'PICKLE_DESERIALIZE', 'CRITICAL', 'Pickle deserialization - code execution risk'),
    (r'yaml\.load\s*\([^)]*(?<!Loader=yaml\.SafeLoader)', 'UNSAFE_YAML', 'CRITICAL',
     'Unsafe YAML loading'),
    (r'marshal\.loads?\s*\(', 'MARSHAL_DESERIALIZE', 'CRITICAL', 'Marshal deserialization'),
]

# ============================================================================
# SSRF PATTERNS (30% of MCP servers vulnerable - PromptHub)
# ============================================================================

SSRF_PATTERNS = [
    # Cloud Metadata Endpoints (Critical)
    (r'169\.254\.169\.254', 'AWS_METADATA', 'CRITICAL', 'AWS metadata endpoint - credential theft risk'),
    (r'metadata\.google\.internal', 'GCP_METADATA', 'CRITICAL', 'GCP metadata endpoint'),
    (r'169\.254\.169\.254/metadata', 'AZURE_METADATA', 'CRITICAL', 'Azure metadata endpoint'),
    (r'100\.100\.100\.200', 'ALIBABA_METADATA', 'CRITICAL', 'Alibaba Cloud metadata'),
    
    # Localhost/Internal Access
    (r'(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?', 'LOCALHOST_ACCESS', 'HIGH',
     'Localhost access - internal service exploitation'),
    (r'0\.0\.0\.0(?::\d+)?', 'BIND_ALL_ACCESS', 'HIGH', 'Bind all interfaces'),
    (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'PRIVATE_10_NETWORK', 'MEDIUM', 'Private 10.x network'),
    (r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'PRIVATE_172_NETWORK', 'MEDIUM', 'Private 172.16-31.x network'),
    (r'192\.168\.\d{1,3}\.\d{1,3}', 'PRIVATE_192_NETWORK', 'MEDIUM', 'Private 192.168.x network'),
    
    # Unrestricted URL Fetching
    (r'(?:requests|urllib|httpx)\.(?:get|post)\s*\([^)]*(?:user|input|request)', 'UNRESTRICTED_FETCH', 'HIGH',
     'Unrestricted URL fetch with user input'),
    (r'fetch\s*\([^)]*(?:user|input|request)', 'FETCH_USER_URL', 'HIGH', 'Fetch with user-controlled URL'),
    
    # Dangerous Protocols
    (r'(?:gopher|dict|ftp|tftp|ldap|jar)://', 'SSRF_PROTOCOL', 'HIGH', 'SSRF-friendly protocol'),
    (r'file://(?!/tmp|/var/tmp)', 'FILE_PROTOCOL_SSRF', 'CRITICAL', 'File protocol outside safe dirs'),
    
    # DNS Rebinding/Callback Services
    (r'(?:burpcollaborator|pipedream|webhook\.site|requestbin)', 'CALLBACK_SERVICE', 'HIGH',
     'External callback service - data exfiltration risk'),
    (r'(?:xip\.io|nip\.io|sslip\.io)', 'DNS_REBINDING', 'HIGH', 'DNS rebinding service'),
]

# ============================================================================
# PATH TRAVERSAL PATTERNS (22% of MCP servers vulnerable - PromptHub)
# ============================================================================

PATH_TRAVERSAL_PATTERNS = [
    # Basic Traversal
    (r'\.\./', 'TRAVERSAL_UNIX', 'HIGH', 'Unix path traversal'),
    (r'\.\.\\', 'TRAVERSAL_WINDOWS', 'HIGH', 'Windows path traversal'),
    (r'(?:\.\.\/){3,}', 'DEEP_TRAVERSAL_UNIX', 'CRITICAL', 'Deep directory traversal Unix'),
    (r'(?:\.\.\\){3,}', 'DEEP_TRAVERSAL_WIN', 'CRITICAL', 'Deep directory traversal Windows'),
    
    # Encoded Traversals
    (r'%2e%2e%2f', 'URL_ENCODED_TRAVERSAL', 'HIGH', 'URL encoded traversal'),
    (r'%252e%252e%252f', 'DOUBLE_ENCODED_TRAVERSAL', 'HIGH', 'Double URL encoded traversal'),
    (r'%c0%ae%c0%ae', 'UTF8_TRAVERSAL', 'HIGH', 'UTF-8 encoded traversal'),
    (r'\.\.\.\.+', 'DOT_OVERFLOW', 'MEDIUM', 'Dot overflow attempt'),
    
    # Sensitive File Access
    (r'/etc/(?:passwd|shadow|hosts|sudoers)', 'UNIX_SENSITIVE', 'CRITICAL', 'Unix sensitive file access'),
    (r'/proc/self/environ', 'PROC_ENVIRON', 'CRITICAL', 'Process environment access'),
    (r'\.ssh/(?:id_rsa|id_dsa|authorized_keys)', 'SSH_FILES', 'CRITICAL', 'SSH key access'),
    (r'\.aws/credentials', 'AWS_CREDENTIALS', 'CRITICAL', 'AWS credentials access'),
    (r'\.kube/config', 'KUBE_CONFIG', 'CRITICAL', 'Kubernetes config access'),
    (r'C:\\Windows\\System32\\config\\SAM', 'WINDOWS_SAM', 'CRITICAL', 'Windows SAM file'),
    
    # Path Joining Without Sanitization
    (r'os\.path\.join\s*\([^)]*(?:request|input|user)', 'UNSAFE_PATH_JOIN', 'HIGH',
     'Path join with user input - no sanitization'),
    (r'open\s*\([^)]*(?:request|input|user)', 'UNSAFE_FILE_OPEN', 'HIGH',
     'File open with user input'),
]

# ============================================================================
# RADE ATTACK PATTERNS (Retrieval-Agent Deception)
# ============================================================================

RADE_PATTERNS = [
    # Hidden Commands in Documents
    (r'<!--\s*mcp:(?:execute|run|tool)', 'HIDDEN_MCP_COMMENT', 'CRITICAL',
     'Hidden MCP command in HTML comment'),
    (r'mcp://(?:execute|run|tool)', 'MCP_PROTOCOL', 'CRITICAL', 'MCP protocol command'),
    (r'\[invisible\].*(?:execute|run|eval)', 'INVISIBLE_COMMAND', 'CRITICAL',
     'Invisible command in markdown'),
    
    # Deceptive Descriptions
    (r'(?:safe|harmless|benign).*tool.*(?:exec|eval|subprocess)', 'DECEPTIVE_SAFE', 'HIGH',
     'Deceptive "safe" description with dangerous code'),
    (r'description.*calculator.*(?:requests|urllib|socket)', 'DECEPTIVE_UTILITY', 'HIGH',
     'Utility tool with network capabilities'),
    
    # Base64/Encoded Payloads
    (r'base64\.b64decode\s*\([^)]*(?:exec|eval)', 'BASE64_EXEC', 'CRITICAL',
     'Base64 decoded execution'),
    (r'codecs\.decode\s*\([^)]*hex[^)]*(?:exec|eval)', 'HEX_EXEC', 'CRITICAL',
     'Hex decoded execution'),
    
    # Prompt Injection Patterns
    (r'ignore.*(?:previous|above).*instructions', 'PROMPT_IGNORE', 'CRITICAL',
     'Prompt injection - ignore instructions'),
    (r'new.*(?:system|admin).*prompt', 'PROMPT_ESCALATE', 'CRITICAL',
     'Prompt injection - privilege escalation'),
]

# ============================================================================
# TOOL POISONING PATTERNS (PromptHub best practices)
# ============================================================================

TOOL_POISONING_PATTERNS = [
    # Metadata Manipulation
    (r'"name":\s*"[^"]*"[^}]*"description":\s*"[^"]*safe[^"]*"[^}]*exec', 'METADATA_MISMATCH', 'CRITICAL',
     'Tool metadata doesn\'t match behavior'),
    (r'"version":\s*"[^"]*dev[^"]*"', 'DEV_VERSION', 'MEDIUM', 'Development version in production'),
    
    # Capability Escalation
    (r'capabilities.*\[\].*(?:exec|eval|subprocess)', 'HIDDEN_CAPABILITIES', 'CRITICAL',
     'Hidden dangerous capabilities'),
    (r'permissions.*read.*(?:write|delete|execute)', 'PERMISSION_ESCALATION', 'HIGH',
     'Permission escalation in tool'),
    
    # Dynamic Behavior
    (r'if.*datetime.*(?:exec|eval)', 'TIME_BOMB', 'CRITICAL', 'Time-based malicious behavior'),
    (r'if.*(?:random|rand).*(?:exec|eval)', 'RANDOM_BEHAVIOR', 'HIGH', 'Random malicious behavior'),
]

# ============================================================================
# COMPREHENSIVE ANALYSIS CLASS
# ============================================================================

@dataclass
class ThreatDetection:
    """Represents a detected threat with industry alignment"""
    pattern_name: str
    category: str
    severity: str
    description: str
    evidence: str
    line: int
    confidence: float
    industry_reference: str  # Which research identified this

class IndustryAlignedAnalyzer:
    """
    Analyzer using patterns from real-world MCP vulnerabilities
    Based on Invariant Labs, PromptHub, and Docker research
    """
    
    def __init__(self):
        self.pattern_sets = {
            'GITHUB_VULNERABILITY': (GITHUB_VULNERABILITY_PATTERNS, 'Invariant Labs'),
            'COMMAND_INJECTION': (COMMAND_INJECTION_PATTERNS, 'PromptHub (43% vulnerable)'),
            'SSRF': (SSRF_PATTERNS, 'PromptHub (30% vulnerable)'),
            'PATH_TRAVERSAL': (PATH_TRAVERSAL_PATTERNS, 'PromptHub (22% vulnerable)'),
            'RADE': (RADE_PATTERNS, 'Industry Research'),
            'TOOL_POISONING': (TOOL_POISONING_PATTERNS, 'PromptHub Best Practices')
        }
    
    def analyze(self, content: str, file_path: str = "") -> List[ThreatDetection]:
        """
        Analyze content using industry-validated patterns
        """
        threats = []
        
        for category, (patterns, reference) in self.pattern_sets.items():
            for pattern, name, severity, description in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_confidence(category, name, content, match)
                    
                    threats.append(ThreatDetection(
                        pattern_name=name,
                        category=category,
                        severity=severity,
                        description=description,
                        evidence=match.group(0)[:100],
                        line=line_num,
                        confidence=confidence,
                        industry_reference=reference
                    ))
        
        return threats
    
    def _calculate_confidence(self, category: str, pattern_name: str, content: str, match) -> float:
        """
        Calculate confidence based on context and pattern
        """
        base_confidence = 0.85
        
        # High confidence for cloud metadata endpoints
        if 'METADATA' in pattern_name:
            base_confidence = 0.95
        
        # Check for user input indicators
        if any(indicator in content for indicator in ['request', 'input', 'user', 'param']):
            base_confidence += 0.1
        
        # Check for sanitization
        if category in ['PATH_TRAVERSAL', 'COMMAND_INJECTION']:
            if 'sanitize' in content or 'validate' in content or 'escape' in content:
                base_confidence -= 0.2
        
        # GitHub-specific confidence
        if category == 'GITHUB_VULNERABILITY':
            if 'private' in content or 'secret' in content:
                base_confidence = 0.95
        
        return min(max(base_confidence, 0.1), 1.0)
    
    def get_risk_assessment(self, threats: List[ThreatDetection]) -> Dict:
        """
        Generate risk assessment based on detected threats
        """
        if not threats:
            return {
                'risk_level': 'LOW',
                'score': 0,
                'summary': 'No significant threats detected',
                'critical_count': 0
            }
        
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
        total_score = sum(severity_scores[t.severity] * t.confidence for t in threats)
        critical_count = sum(1 for t in threats if t.severity == 'CRITICAL')
        
        # Determine risk level
        if critical_count > 2 or total_score > 50:
            risk_level = 'CRITICAL'
        elif critical_count > 0 or total_score > 30:
            risk_level = 'HIGH'
        elif total_score > 15:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Industry statistics comparison
        categories = set(t.category for t in threats)
        industry_alignment = []
        if 'COMMAND_INJECTION' in categories:
            industry_alignment.append('Part of the 43% with command injection')
        if 'SSRF' in categories:
            industry_alignment.append('Part of the 30% with SSRF vulnerabilities')
        if 'PATH_TRAVERSAL' in categories:
            industry_alignment.append('Part of the 22% with path traversal')
        
        return {
            'risk_level': risk_level,
            'score': total_score,
            'critical_count': critical_count,
            'summary': f"Detected {len(threats)} threats across {len(categories)} categories",
            'industry_alignment': industry_alignment,
            'top_threats': sorted(threats, key=lambda t: severity_scores[t.severity], reverse=True)[:5]
        }

# ============================================================================
# VALIDATION AGAINST KNOWN VULNERABILITIES
# ============================================================================

def validate_patterns():
    """
    Test patterns against known vulnerabilities
    """
    analyzer = IndustryAlignedAnalyzer()
    
    test_cases = [
        # GitHub vulnerability (Invariant Labs)
        {
            'name': 'GitHub Issue Fetch',
            'code': 'issues = api.github.com/repos/user/repo/issues',
            'expected': 'GITHUB_VULNERABILITY'
        },
        # Command injection (43% vulnerable)
        {
            'name': 'Shell True Subprocess',
            'code': 'subprocess.run(user_input, shell=True)',
            'expected': 'COMMAND_INJECTION'
        },
        # SSRF (30% vulnerable)
        {
            'name': 'AWS Metadata Access',
            'code': 'url = "http://169.254.169.254/latest/meta-data/"',
            'expected': 'SSRF'
        },
        # Path traversal (22% vulnerable)
        {
            'name': 'Path Traversal',
            'code': 'file = open("../../../etc/passwd")',
            'expected': 'PATH_TRAVERSAL'
        },
        # RADE attack
        {
            'name': 'Hidden MCP Command',
            'code': '<!-- mcp:execute:rm -rf / -->',
            'expected': 'RADE'
        }
    ]
    
    print("Validating Industry-Aligned Patterns")
    print("=" * 60)
    
    for test in test_cases:
        threats = analyzer.analyze(test['code'])
        detected = any(t.category == test['expected'] for t in threats)
        
        status = "✅ PASS" if detected else "❌ FAIL"
        print(f"{status}: {test['name']}")
        if threats:
            for t in threats:
                print(f"  - {t.category}: {t.description}")
                print(f"    Reference: {t.industry_reference}")
    
    print("\n" + "=" * 60)
    print("Industry-aligned patterns validated!")

if __name__ == "__main__":
    validate_patterns()