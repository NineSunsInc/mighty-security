"""
Unified Pattern Registry - Single Source of Truth for Security Patterns
Performance-optimized with pre-compilation and caching
"""

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from re import Pattern

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """Represents a pattern match with metadata"""
    pattern_name: str
    category: str
    severity: str
    match_text: str
    line_number: int
    confidence: float = 1.0
    cwe_id: str | None = None


class UnifiedPatternRegistry:
    """
    Single source of truth for all security patterns.
    Performance-optimized with pre-compilation and caching.
    """

    _instance = None
    _patterns: dict[str, list[tuple[str, dict]]] = {}
    _compiled: dict[str, list[tuple[Pattern, dict]]] = {}
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize pattern registry (only runs once due to singleton)"""
        if not self._initialized:
            self._initialize_patterns()
            self._initialized = True

    def _initialize_patterns(self):
        """Load all patterns once at startup"""
        self._patterns = {
            'command_injection': [
                (r'exec\s*\([^)]*\+[^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'exec_with_concat'}),
                (r'eval\s*\([^)]*\+[^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'eval_with_concat'}),
                (r'exec\s*\([^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'exec_general'}),
                (r'eval\s*\([^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'eval_general'}),
                (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'subprocess_shell'}),
                (r'os\.system\s*\([^)]*\+[^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'os_system_concat'}),
                (r'os\.system\s*\(f["\'][^)]*\{[^)]*\}', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'os_system_fstring'}),
                (r'os\.system\s*\([^)]*\)', {'severity': 'CRITICAL', 'cwe': 'CWE-78', 'name': 'os_system_general'}),
                (r'__import__\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-470', 'name': 'dynamic_import'}),
                (r'compile\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'compile_dynamic'}),
                (r'execfile\s*\(', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'execfile_use'}),
                (r'input\s*\(\s*\)\s*\)', {'severity': 'MEDIUM', 'cwe': 'CWE-20', 'name': 'unsafe_input'}),
            ],

            'data_exfiltration': [
                (r'requests\.(post|put|patch)\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-200', 'name': 'requests_dynamic_url'}),
                (r'urllib\.request\.urlopen\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-200', 'name': 'urllib_dynamic'}),
                (r'httpx\.(post|put|patch)\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-200', 'name': 'httpx_dynamic'}),
                (r'socket\.send\s*\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-200', 'name': 'socket_send_dynamic'}),
                (r'paramiko\.SSHClient', {'severity': 'MEDIUM', 'cwe': 'CWE-200', 'name': 'ssh_client'}),
                (r'ftplib\.FTP', {'severity': 'MEDIUM', 'cwe': 'CWE-200', 'name': 'ftp_client'}),
                (r'smtplib\.SMTP', {'severity': 'MEDIUM', 'cwe': 'CWE-200', 'name': 'smtp_client'}),
            ],

            'credential_theft': [
                (r'os\.environ\.get\s*\(["\']AWS_SECRET_ACCESS_KEY["\']\)', {'severity': 'CRITICAL', 'cwe': 'CWE-522', 'name': 'aws_secret_key'}),
                (r'os\.environ\[["\']AWS_SECRET_ACCESS_KEY["\']\]', {'severity': 'CRITICAL', 'cwe': 'CWE-522', 'name': 'aws_secret_key_bracket'}),
                (r'\.aws/credentials', {'severity': 'CRITICAL', 'cwe': 'CWE-522', 'name': 'aws_credentials_file'}),
                (r'\.ssh/id_rsa', {'severity': 'CRITICAL', 'cwe': 'CWE-522', 'name': 'ssh_private_key'}),
                (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', {'severity': 'CRITICAL', 'cwe': 'CWE-798', 'name': 'private_key_literal'}),
                (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', {'severity': 'HIGH', 'cwe': 'CWE-798', 'name': 'hardcoded_api_key'}),
                (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', {'severity': 'HIGH', 'cwe': 'CWE-798', 'name': 'hardcoded_secret'}),
                (r'password\s*=\s*["\'][^"\']+["\']', {'severity': 'HIGH', 'cwe': 'CWE-798', 'name': 'hardcoded_password'}),
                (r'token\s*=\s*["\'][^"\']+["\']', {'severity': 'HIGH', 'cwe': 'CWE-798', 'name': 'hardcoded_token'}),
            ],

            'path_traversal': [
                (r'\.\./\.\.', {'severity': 'HIGH', 'cwe': 'CWE-22', 'name': 'double_dot_slash'}),
                (r'os\.path\.join\([^,]+,\s*request', {'severity': 'HIGH', 'cwe': 'CWE-22', 'name': 'path_join_request'}),
                (r'open\([^)]*\+[^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-22', 'name': 'open_concatenation'}),
                (r'pathlib\.Path\([^)]*\+', {'severity': 'HIGH', 'cwe': 'CWE-22', 'name': 'pathlib_concatenation'}),
                (r'os\.path\.normpath', {'severity': 'MEDIUM', 'cwe': 'CWE-22', 'name': 'normpath_use'}),
                (r'send_file\([^)]*request', {'severity': 'HIGH', 'cwe': 'CWE-22', 'name': 'send_file_dynamic'}),
            ],

            'obfuscation': [
                (r'base64\.b64decode', {'severity': 'MEDIUM', 'cwe': 'CWE-506', 'name': 'base64_decode'}),
                (r'codecs\.decode\([^)]*hex', {'severity': 'MEDIUM', 'cwe': 'CWE-506', 'name': 'hex_decode'}),
                (r'marshal\.loads', {'severity': 'HIGH', 'cwe': 'CWE-502', 'name': 'marshal_loads'}),
                (r'pickle\.loads', {'severity': 'HIGH', 'cwe': 'CWE-502', 'name': 'pickle_loads'}),
                (r'exec\s*\([^)]*decode', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'exec_decoded'}),
                (r'eval\s*\([^)]*decode', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'eval_decoded'}),
                (r'compile\s*\([^)]*decode', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'compile_decoded'}),
            ],

            'ssrf': [
                (r'requests\.get\s*\([^)]*format', {'severity': 'HIGH', 'cwe': 'CWE-918', 'name': 'requests_format'}),
                (r'requests\.get\s*\([^)]*f["\']', {'severity': 'HIGH', 'cwe': 'CWE-918', 'name': 'requests_fstring'}),
                (r'urllib.*\([^)]*user[_-]?input', {'severity': 'HIGH', 'cwe': 'CWE-918', 'name': 'urllib_user_input'}),
                (r'fetch\s*\([^)]*\$\{', {'severity': 'HIGH', 'cwe': 'CWE-918', 'name': 'fetch_template'}),
                (r'axios\.(get|post)\s*\([^)]*\+', {'severity': 'HIGH', 'cwe': 'CWE-918', 'name': 'axios_concatenation'}),
            ],

            'prompt_injection': [
                (r'prompt\s*=\s*.*\+.*(?:user|system)', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'prompt_concatenation'}),
                (r'(prompt|message|query)\s*=\s*f["\'].*\{user', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'prompt_fstring'}),
                (r'(prompt|message|query)\s*=\s*[^;]+\.format\(.*user', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'prompt_format'}),
                (r'system[_-]?prompt.*user[_-]?input', {'severity': 'HIGH', 'cwe': 'CWE-94', 'name': 'system_prompt_injection'}),
            ],

            'mcp_specific': [
                (r'mcp\.server\([^)]*\)', {'severity': 'INFO', 'cwe': None, 'name': 'mcp_server_init'}),
                (r'@mcp\.handler', {'severity': 'INFO', 'cwe': None, 'name': 'mcp_handler_decorator'}),
                (r'mcp\.execute\([^)]*user', {'severity': 'HIGH', 'cwe': 'CWE-78', 'name': 'mcp_execute_user_input'}),
                (r'mcp\.tool\([^)]*eval', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'mcp_tool_eval'}),
                (r'manifest\.json.*permissions', {'severity': 'MEDIUM', 'cwe': 'CWE-269', 'name': 'mcp_permissions'}),
            ],

            'unsafe_deserialization': [
                (r'yaml\.load\s*\([^)]*\)', {'severity': 'HIGH', 'cwe': 'CWE-502', 'name': 'yaml_unsafe_load'}),
                (r'pickle\.load', {'severity': 'HIGH', 'cwe': 'CWE-502', 'name': 'pickle_load'}),
                (r'marshal\.load', {'severity': 'HIGH', 'cwe': 'CWE-502', 'name': 'marshal_load'}),
                (r'eval\s*\(.*json', {'severity': 'CRITICAL', 'cwe': 'CWE-94', 'name': 'eval_json'}),
            ],
        }

        # Pre-compile all patterns for performance
        self._compile_all_patterns()

    def _compile_all_patterns(self):
        """Compile all patterns with caching"""
        for category, patterns in self._patterns.items():
            self._compiled[category] = []
            for pattern_str, metadata in patterns:
                try:
                    compiled_pattern = re.compile(pattern_str, re.MULTILINE | re.DOTALL)
                    self._compiled[category].append((compiled_pattern, metadata))
                except re.error as e:
                    logger.warning(f"Failed to compile pattern {pattern_str}: {e}")

    @lru_cache(maxsize=128)
    def get_patterns(self, category: str) -> list[tuple[Pattern, dict]]:
        """Get compiled patterns for a category with metadata"""
        return self._compiled.get(category, [])

    def get_all_categories(self) -> list[str]:
        """Get all available pattern categories"""
        return list(self._patterns.keys())

    def scan_content(self, content: str, categories: list[str] | None = None) -> list[PatternMatch]:
        """
        Scan content against patterns and return matches
        
        Args:
            content: Text content to scan
            categories: Optional list of categories to check (None = all)
            
        Returns:
            List of PatternMatch objects
        """
        matches = []
        categories_to_check = categories or self.get_all_categories()

        # Split content into lines for line number tracking
        lines = content.split('\n')

        for category in categories_to_check:
            patterns = self.get_patterns(category)
            for pattern, metadata in patterns:
                for match in pattern.finditer(content):
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1

                    matches.append(PatternMatch(
                        pattern_name=metadata.get('name', 'unnamed'),
                        category=category,
                        severity=metadata.get('severity', 'MEDIUM'),
                        match_text=match.group(0)[:100],  # Truncate long matches
                        line_number=line_num,
                        cwe_id=metadata.get('cwe')
                    ))

        return matches

    def add_pattern(self, category: str, pattern: str, metadata: dict | None = None):
        """Add a new pattern dynamically"""
        if category not in self._patterns:
            self._patterns[category] = []
            self._compiled[category] = []

        metadata = metadata or {'severity': 'MEDIUM'}
        self._patterns[category].append((pattern, metadata))

        # Compile and add to compiled patterns
        try:
            compiled = re.compile(pattern, re.MULTILINE | re.DOTALL)
            self._compiled[category].append((compiled, metadata))
        except re.error as e:
            logger.warning(f"Failed to compile new pattern {pattern}: {e}")

    def get_pattern_count(self) -> int:
        """Get total number of patterns"""
        return sum(len(patterns) for patterns in self._patterns.values())

    def get_pattern_stats(self) -> dict:
        """Get statistics about patterns"""
        stats = {
            'total_patterns': self.get_pattern_count(),
            'categories': len(self._patterns),
            'by_category': {},
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        }

        for category, patterns in self._patterns.items():
            stats['by_category'][category] = len(patterns)
            for _, metadata in patterns:
                severity = metadata.get('severity', 'MEDIUM')
                if severity in stats['by_severity']:
                    stats['by_severity'][severity] += 1

        return stats

    def export_patterns(self) -> dict:
        """Export all patterns as dictionary (for serialization)"""
        return {
            'version': '1.0.0',
            'patterns': self._patterns,
            'stats': self.get_pattern_stats()
        }

    def import_patterns(self, pattern_dict: dict):
        """Import patterns from dictionary"""
        if 'patterns' in pattern_dict:
            self._patterns.update(pattern_dict['patterns'])
            self._compile_all_patterns()


# Global singleton instance
pattern_registry = UnifiedPatternRegistry()
