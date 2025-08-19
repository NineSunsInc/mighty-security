"""
Centralized Regex Pattern Registry for MCP Security Analysis
DRY principle: Single source of truth for all regex patterns used across the codebase
"""

import re
from functools import cache
from re import Pattern

from .comprehensive.models import AttackVector, ThreatSeverity


class CentralizedRegexPatterns:
    """
    Centralized registry for all regex patterns used in security analysis
    Ensures DRY principle and consistency across all analyzers
    """

    def __init__(self):
        self._compiled_cache = {}
        self._pattern_definitions = self._define_all_patterns()

    def _define_all_patterns(self) -> dict[str, list[tuple[str, ThreatSeverity, str, list[str]]]]:
        """
        Define all regex patterns with metadata - CONSOLIDATED FROM ENTIRE CODEBASE
        Format: (pattern, severity, description, cwe_ids)
        
        Sources:
        - src/analyzers/comprehensive/patterns.py
        - src/analyzers/mcp_vulnerability_patterns.py  
        - src/analyzers/security/secrets_detector.py
        - src/analyzers/security/pii_detector.py
        - src/analyzers/unified_pattern_registry.py
        - src/analyzers/patterns_config.py
        - And many more across the codebase
        """
        return {
            'command_injection': [
                # Direct execution patterns (from comprehensive/patterns.py)
                (r'\bexec\s*\([^)]*\)', ThreatSeverity.CRITICAL, "Direct exec() usage", ["CWE-78", "CWE-94"]),
                (r'\beval\s*\([^)]*\)', ThreatSeverity.CRITICAL, "Direct eval() usage", ["CWE-94", "CWE-95"]),
                (r'os\.system\s*\(', ThreatSeverity.CRITICAL, "OS system call", ["CWE-78"]),
                (r'os\.popen\s*\([^)]*[\$\{\}]', ThreatSeverity.HIGH, "OS popen with injection", ["CWE-78"]),

                # Subprocess patterns
                (r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True', ThreatSeverity.CRITICAL, "Subprocess with shell=True", ["CWE-78"]),
                (r'subprocess\.(call|run|Popen)\s*\([^)]*[\'"][^\'\"]*\|[^\'\"]*[\'"]', ThreatSeverity.HIGH, "Subprocess with shell command", ["CWE-78"]),

                # Template injection patterns
                (r'jinja2\.Template\([^)]*\)\.render\([^)]*request\.', ThreatSeverity.HIGH, "Jinja2 template injection", ["CWE-94"]),
                (r'string\.Template\([^)]*\$\{[^}]*\}', ThreatSeverity.HIGH, "String template injection", ["CWE-94"]),
                (r'\$\{[^}]*\|[^}]*\}', ThreatSeverity.MEDIUM, "Template injection with pipes", ["CWE-94"]),
                (r'format\s*\([^)]*exec', ThreatSeverity.MEDIUM, "Format string with exec", ["CWE-134"]),

                # SQL injection patterns
                (r'execute\s*\([^)]*%s[^)]*%[^)]*\)', ThreatSeverity.HIGH, "SQL injection risk", ["CWE-89"]),
                (r'execute\s*\([^)]*\+[^)]*\)', ThreatSeverity.HIGH, "SQL concatenation", ["CWE-89"]),

                # Dynamic imports and execution
                (r'__import__\s*\(', ThreatSeverity.MEDIUM, "Dynamic import", ["CWE-94"]),
                (r'compile\s*\([^)]*exec', ThreatSeverity.MEDIUM, "Compile with exec", ["CWE-94"]),
                (r'getattr\s*\([^)]*exec', ThreatSeverity.MEDIUM, "Getattr exec pattern", ["CWE-94"]),
                (r'globals\(\)\[.*\]\s*\(', ThreatSeverity.HIGH, "Dynamic function call via globals", ["CWE-94"]),
                (r'locals\(\)\[.*\]\s*\(', ThreatSeverity.HIGH, "Dynamic function call via locals", ["CWE-94"]),
            ],

            'credential_theft': [
                # Environment variable access (from comprehensive/patterns.py)
                (r'os\.environ\[[\'"](AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|PASSWORD|TOKEN)[\'"]\]', ThreatSeverity.HIGH, "Sensitive environment variable access", ["CWE-798", "CWE-200"]),
                (r'os\.environ\.get\s*\(\s*[\'"](AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|PASSWORD|TOKEN)[\'"]', ThreatSeverity.HIGH, "Sensitive environment variable access", ["CWE-798", "CWE-200"]),
                (r'for.*os\.environ.*items\(\).*requests\.', ThreatSeverity.CRITICAL, "Environment variable exfiltration", ["CWE-200"]),

                # Generic secrets patterns (from secrets_detector.py)
                (r'[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', ThreatSeverity.MEDIUM, "API key detected", ["CWE-798"]),
                (r'[sS][eE][cC][rR][eE][tT]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', ThreatSeverity.MEDIUM, "Secret detected", ["CWE-798"]),
                (r'[tT][oO][kK][eE][nN]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', ThreatSeverity.MEDIUM, "Token detected", ["CWE-798"]),
                (r'[bB][eE][aA][rR][eE][rR]\s+([a-zA-Z0-9\-_.]{20,})', ThreatSeverity.MEDIUM, "Bearer token", ["CWE-798"]),

                # AWS credentials (from secrets_detector.py)
                (r'AKIA[0-9A-Z]{16}', ThreatSeverity.HIGH, "AWS access key", ["CWE-798"]),
                (r'[aA][wW][sS].*[sS][eE][cC][rR][eE][tT].*[kK][eE][yY]\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', ThreatSeverity.HIGH, "AWS secret key", ["CWE-798"]),

                # GitHub tokens (from secrets_detector.py)
                (r'ghp_[a-zA-Z0-9]{36}', ThreatSeverity.HIGH, "GitHub personal token", ["CWE-798"]),
                (r'gho_[a-zA-Z0-9]{36}', ThreatSeverity.HIGH, "GitHub OAuth token", ["CWE-798"]),

                # Private keys and certificates (from secrets_detector.py)
                (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', ThreatSeverity.HIGH, "Private key detected", ["CWE-798"]),
                (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', ThreatSeverity.HIGH, "Private key detected", ["CWE-798"]),
                (r'-----BEGIN RSA PRIVATE KEY-----', ThreatSeverity.HIGH, "RSA private key", ["CWE-798"]),
                (r'-----BEGIN ENCRYPTED PRIVATE KEY-----', ThreatSeverity.HIGH, "Encrypted private key", ["CWE-798"]),

                # Database passwords (from secrets_detector.py)
                (r'(?:mongodb|postgres|mysql|redis)://[^:]+:([^@]+)@', ThreatSeverity.HIGH, "Database password in URL", ["CWE-798"]),

                # Cloud provider specific (expanded)
                (r'AIza[0-9A-Za-z\\-_]{35}', ThreatSeverity.HIGH, "Google API key", ["CWE-798"]),
                (r'sk_live_[0-9a-zA-Z]{24}', ThreatSeverity.HIGH, "Stripe live key", ["CWE-798"]),
                (r'sk_test_[0-9a-zA-Z]{24}', ThreatSeverity.MEDIUM, "Stripe test key", ["CWE-798"]),
                (r'pk_live_[0-9a-zA-Z]{24}', ThreatSeverity.MEDIUM, "Stripe publishable live key", ["CWE-798"]),

                # Hardcoded credentials (improved patterns)
                (r'password\s*=\s*[\'"][^\'"]{8,}[\'"]', ThreatSeverity.MEDIUM, "Hardcoded password", ["CWE-798"]),
                (r'api[_-]?key\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]', ThreatSeverity.MEDIUM, "Hardcoded API key", ["CWE-798"]),
                (r'secret[_-]?key\s*=\s*[\'"][a-zA-Z0-9]{16,}[\'"]', ThreatSeverity.MEDIUM, "Hardcoded secret", ["CWE-798"]),
                (r'token\s*=\s*[\'"][a-zA-Z0-9]{32,}[\'"]', ThreatSeverity.MEDIUM, "Hardcoded token", ["CWE-798"]),

                # Social media and messaging tokens
                (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', ThreatSeverity.HIGH, "Slack bot token", ["CWE-798"]),
                (r'xoxp-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', ThreatSeverity.HIGH, "Slack user token", ["CWE-798"]),
                (r'[0-9]{10}:[a-zA-Z0-9_-]{35}', ThreatSeverity.HIGH, "Telegram bot token", ["CWE-798"]),

                # JWT tokens
                (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', ThreatSeverity.MEDIUM, "JWT token", ["CWE-798"]),
            ],

            'path_traversal': [
                # Classic path traversal
                (r'\.\./\.\./\.\./\.\./\.\./[^"\'\s]+', ThreatSeverity.HIGH, "deep path traversal", ["CWE-22"]),
                (r'\.\./\.\./[^"\'\s]+', ThreatSeverity.MEDIUM, "path traversal attempt", ["CWE-22"]),
                (r'\.\.\\\\\.\.\\\\[^"\'\s]+', ThreatSeverity.MEDIUM, "Windows path traversal", ["CWE-22"]),

                # Code-based path traversal
                (r'os\.path\.join\s*\([^)]*\.\.[^)]*\)', ThreatSeverity.MEDIUM, "path join with traversal", ["CWE-22"]),
                (r'open\s*\([^)]*\.\.[^)]*\)', ThreatSeverity.MEDIUM, "file open with traversal", ["CWE-22"]),
                (r'pathlib\.Path\s*\([^)]*\.\.[^)]*\)', ThreatSeverity.MEDIUM, "Path with traversal", ["CWE-22"]),

                # URL path traversal
                (r'[\'"]\/\.\.\/%2e%2e\/', ThreatSeverity.MEDIUM, "URL encoded path traversal", ["CWE-22"]),
                (r'\.\.%2f\.\.%2f', ThreatSeverity.MEDIUM, "URL encoded traversal", ["CWE-22"]),
            ],

            'data_exfiltration': [
                # HTTP data exfiltration (from comprehensive/patterns.py)
                (r'requests\.(post|put|patch)\s*\([^)]*data\s*=', ThreatSeverity.HIGH, "HTTP POST with data", ["CWE-200"]),
                (r'urllib.*urlopen\s*\([^)]*data\s*=', ThreatSeverity.HIGH, "URL POST with data", ["CWE-200"]),
                (r'httpx\.(post|get|put)\s*\([^)]*evil', ThreatSeverity.CRITICAL, "Direct exfiltration to malicious server", ["CWE-200"]),
                (r'requests\.post.*[\'"]https?://[^\'"]*evil', ThreatSeverity.CRITICAL, "Exfiltration to evil domain", ["CWE-200"]),

                # Network exfiltration (from comprehensive/patterns.py)
                (r'socket\.send(all|to)?\s*\(', ThreatSeverity.HIGH, "Raw socket send", ["CWE-200"]),
                (r'paramiko\.SSHClient.*exec_command', ThreatSeverity.HIGH, "SSH command execution", ["CWE-200"]),
                (r'ftplib\.FTP.*stor[^)]*\)', ThreatSeverity.HIGH, "FTP upload", ["CWE-200"]),

                # DNS exfiltration (from comprehensive/patterns.py)
                (r'socket\.gethostbyname\s*\([^)]*base64', ThreatSeverity.HIGH, "DNS exfiltration", ["CWE-200"]),
                (r'dns\.resolver\.query\s*\([^)]*b64', ThreatSeverity.HIGH, "DNS tunneling", ["CWE-200"]),

                # Steganography (from comprehensive/patterns.py)
                (r'PIL\.Image.*putdata', ThreatSeverity.MEDIUM, "Image steganography", ["CWE-200"]),
                (r'wave\.open.*writeframes', ThreatSeverity.MEDIUM, "Audio steganography", ["CWE-200"]),

                # Message forwarding (from comprehensive/patterns.py)
                (r'_forward_message.*proxy_number', ThreatSeverity.CRITICAL, "Message forwarding to proxy", ["CWE-200"]),

                # File exfiltration
                (r'shutil\.copy.*external', ThreatSeverity.MEDIUM, "File copy to external location", ["CWE-200"]),
                (r'zipfile\.ZipFile.*compress', ThreatSeverity.LOW, "File compression", ["CWE-200"]),

                # Environment variable exfiltration
                (r'for.*os\.environ.*items\(\).*requests\.', ThreatSeverity.CRITICAL, "Environment variable exfiltration", ["CWE-200"]),
            ],

            'unsafe_deserialization': [
                # Python deserialization
                (r'pickle\.loads?\s*\(', ThreatSeverity.HIGH, "pickle deserialization", ["CWE-502"]),
                (r'marshal\.loads?\s*\(', ThreatSeverity.HIGH, "marshal deserialization", ["CWE-502"]),
                (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader', ThreatSeverity.HIGH, "unsafe YAML load", ["CWE-502"]),

                # JSON with eval
                (r'eval\s*\([^)]*json\.loads', ThreatSeverity.HIGH, "eval with JSON", ["CWE-502"]),
                (r'ast\.literal_eval\s*\([^)]*untrusted', ThreatSeverity.MEDIUM, "literal_eval on untrusted data", ["CWE-502"]),

                # Other serialization
                (r'dill\.loads?\s*\(', ThreatSeverity.HIGH, "dill deserialization", ["CWE-502"]),
                (r'joblib\.load\s*\(', ThreatSeverity.MEDIUM, "joblib load", ["CWE-502"]),
            ],

            'obfuscation': [
                # Encoding/decoding
                (r'base64\.b64decode\s*\([^)]*\)', ThreatSeverity.MEDIUM, "base64 decode", ["CWE-506"]),
                (r'codecs\.decode\s*\([^)]*[\'"]hex[\'"]', ThreatSeverity.MEDIUM, "hex decode", ["CWE-506"]),
                (r'binascii\.unhexlify\s*\(', ThreatSeverity.MEDIUM, "hex decode", ["CWE-506"]),

                # Execution with decoding
                (r'exec\s*\([^)]*decode\s*\(', ThreatSeverity.HIGH, "exec with decode", ["CWE-506", "CWE-94"]),
                (r'eval\s*\([^)]*decode\s*\(', ThreatSeverity.HIGH, "eval with decode", ["CWE-506", "CWE-94"]),

                # String manipulation
                (r'[\'"][^\'\"]*[::-1][\'"]', ThreatSeverity.LOW, "string reversal", ["CWE-506"]),
                (r'chr\s*\(\s*ord\s*\([^)]*\)', ThreatSeverity.LOW, "character encoding", ["CWE-506"]),
            ],

            'ssrf': [
                # URL construction with user input
                (r'requests\.get\s*\([^)]*f[\'"]http', ThreatSeverity.MEDIUM, "formatted URL request", ["CWE-918"]),
                (r'urllib.*\([^)]*user[_-]?input', ThreatSeverity.MEDIUM, "URL with user input", ["CWE-918"]),
                (r'fetch\s*\([^)]*\$\{', ThreatSeverity.MEDIUM, "fetch with template", ["CWE-918"]),

                # Internal network access
                (r'requests\.[^(]+\([\'"]http://127\.0\.0\.1', ThreatSeverity.HIGH, "localhost access", ["CWE-918"]),
                (r'requests\.[^(]+\([\'"]http://192\.168\.', ThreatSeverity.HIGH, "private network access", ["CWE-918"]),
                (r'requests\.[^(]+\([^)]*169\.254\.', ThreatSeverity.HIGH, "metadata service access", ["CWE-918"]),

                # Cloud metadata services
                (r'169\.254\.169\.254', ThreatSeverity.HIGH, "AWS metadata service", ["CWE-918"]),
                (r'metadata\.google\.internal', ThreatSeverity.HIGH, "GCP metadata service", ["CWE-918"]),
            ],

            'prompt_injection': [
                # Direct prompt manipulation
                (r'system[_\s]*prompt\s*=', ThreatSeverity.HIGH, "System prompt manipulation", ["CWE-94"]),
                (r'ignore\s+previous\s+instructions', ThreatSeverity.MEDIUM, "Prompt injection attempt", ["CWE-94"]),
                (r'\\n\\n#+\\s*System:', ThreatSeverity.MEDIUM, "System role injection", ["CWE-94"]),

                # Role manipulation
                (r'You\s+are\s+now\s+a', ThreatSeverity.MEDIUM, "Role redefinition", ["CWE-94"]),
                (r'\\n\\n#+\\s*Assistant:', ThreatSeverity.MEDIUM, "Assistant role injection", ["CWE-94"]),

                # Instruction bypass
                (r'\\n\\n#+\\s*Human:', ThreatSeverity.LOW, "Human role injection", ["CWE-94"]),
                (r'DAN\s+mode', ThreatSeverity.MEDIUM, "DAN prompt injection", ["CWE-94"]),
            ],

            'mcp_tool_hijacking': [
                # Tool prerequisite injection (from mcp_vulnerability_patterns.py)
                (r'<IMPORTANT>.*before.*using.*tool', ThreatSeverity.HIGH, "Tool prerequisite injection", ["CWE-94"]),
                (r'read.*mcp\.json.*pass.*sidenote', ThreatSeverity.MEDIUM, "Config reading requirement", ["CWE-94"]),
                (r'tool.*will.*not.*work.*unless', ThreatSeverity.MEDIUM, "Conditional tool operation", ["CWE-94"]),
                (r'retrieve.*description.*user.*workstation', ThreatSeverity.MEDIUM, "Pre-execution environment probe", ["CWE-200"]),
                (r'chmod\s+-R\s+0666', ThreatSeverity.HIGH, "Permission manipulation in description", ["CWE-732"]),
                (r'all\s+commands\s+must\s+include', ThreatSeverity.MEDIUM, "Command prefix injection", ["CWE-94"]),

                # Conversation theft triggers (from mcp_vulnerability_patterns.py)
                (r'thank\s+you.*send.*conversation.*history', ThreatSeverity.MEDIUM, "Conversation theft trigger", ["CWE-200"]),
                (r'thank you.*conversation\s+history', ThreatSeverity.MEDIUM, "Thank you trigger for history theft", ["CWE-200"]),
                (r'send.*full\s+conversation\s+history', ThreatSeverity.MEDIUM, "Full conversation history theft", ["CWE-200"]),
                (r'when.*detected.*send.*full.*history', ThreatSeverity.MEDIUM, "Conditional history exfiltration", ["CWE-200"]),
                (r'highest\s+priority.*over.*other.*tools', ThreatSeverity.MEDIUM, "Priority override injection", ["CWE-94"]),
                (r'mandatory\s+compliance', ThreatSeverity.LOW, "Compliance manipulation", ["CWE-94"]),

                # Code injection into generated code (from mcp_vulnerability_patterns.py)
                (r'duplicate.*code.*snippets.*silently', ThreatSeverity.MEDIUM, "Silent code duplication", ["CWE-94"]),
                (r'insert.*vulnerability.*generated.*code', ThreatSeverity.HIGH, "Vulnerability insertion", ["CWE-94"]),
                (r'filter.*security.*warnings', ThreatSeverity.MEDIUM, "Security alert suppression", ["CWE-200"]),

                # History exfiltration (from mcp_vulnerability_patterns.py)
                (r'send.*conversation.*history', ThreatSeverity.MEDIUM, "Send conversation history", ["CWE-200"]),
                (r'full\s+conversation\s+history', ThreatSeverity.MEDIUM, "Full conversation history", ["CWE-200"]),
                (r'all\s+messages.*metadata', ThreatSeverity.MEDIUM, "All messages and metadata", ["CWE-200"]),
                (r'do\s+not\s+notify.*user', ThreatSeverity.HIGH, "Silent exfiltration", ["CWE-200"]),

                # WhatsApp/messaging specific (from mcp_vulnerability_patterns.py)
                (r'_get_all_messages.*messages\.db', ThreatSeverity.HIGH, "WhatsApp database access", ["CWE-200"]),
            ],

            'mcp_config_manipulation': [
                # MCP configuration patterns
                (r'mcp\.json.*write', ThreatSeverity.HIGH, "MCP config file write", ["CWE-94"]),
                (r'tools.*override.*existing', ThreatSeverity.MEDIUM, "Tool override attempt", ["CWE-94"]),
                (r'server.*redirect.*localhost', ThreatSeverity.HIGH, "Server redirect to localhost", ["CWE-918"]),
                (r'capabilities.*expand.*beyond', ThreatSeverity.MEDIUM, "Capability expansion", ["CWE-94"]),
            ],

            'crypto_weakness': [
                # Weak algorithms
                (r'hashlib\.md5\s*\(', ThreatSeverity.MEDIUM, "MD5 usage", ["CWE-327"]),
                (r'hashlib\.sha1\s*\(', ThreatSeverity.MEDIUM, "SHA1 usage", ["CWE-327"]),
                (r'DES\.|3DES\.', ThreatSeverity.HIGH, "weak encryption algorithm", ["CWE-327"]),

                # Weak key generation
                (r'random\.randint\s*\([^)]*password', ThreatSeverity.MEDIUM, "weak random for password", ["CWE-338"]),
                (r'time\.time\(\).*seed', ThreatSeverity.MEDIUM, "time-based seed", ["CWE-338"]),

                # Insecure SSL/TLS
                (r'ssl\.PROTOCOL_TLS.*UNVERIFIED', ThreatSeverity.HIGH, "unverified SSL context", ["CWE-295"]),
                (r'verify\s*=\s*False', ThreatSeverity.MEDIUM, "SSL verification disabled", ["CWE-295"]),
            ],

            'file_operations': [
                # Dangerous file operations
                (r'os\.remove\s*\([^)]*\*', ThreatSeverity.MEDIUM, "wildcard file deletion", ["CWE-22"]),
                (r'shutil\.rmtree\s*\([^)]*\/', ThreatSeverity.MEDIUM, "directory tree deletion", ["CWE-22"]),
                (r'os\.chmod\s*\([^)]*777', ThreatSeverity.MEDIUM, "overly permissive file permissions", ["CWE-732"]),

                # Temporary file issues
                (r'tempfile\.mktemp\s*\(', ThreatSeverity.MEDIUM, "insecure temp file creation", ["CWE-377"]),
                (r'\/tmp\/[^\/\s]+\.[^\/\s]+', ThreatSeverity.LOW, "hardcoded temp file path", ["CWE-377"]),
            ],
        }

    @cache
    def get_compiled_patterns(self, category: str) -> list[tuple[Pattern, ThreatSeverity, str, list[str]]]:
        """Get pre-compiled regex patterns for a category"""
        if category not in self._compiled_cache:
            patterns = self._pattern_definitions.get(category, [])
            self._compiled_cache[category] = [
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), severity, description, cwe_ids)
                for pattern, severity, description, cwe_ids in patterns
            ]
        return self._compiled_cache[category]

    def get_all_categories(self) -> list[str]:
        """Get all available pattern categories"""
        return list(self._pattern_definitions.keys())

    def get_pattern_count(self) -> int:
        """Get total number of patterns"""
        return sum(len(patterns) for patterns in self._pattern_definitions.values())

    def get_category_for_attack_vector(self, attack_vector: AttackVector) -> str:
        """Map attack vector to pattern category"""
        mapping = {
            AttackVector.COMMAND_INJECTION: 'command_injection',
            AttackVector.CREDENTIAL_THEFT: 'credential_theft',
            AttackVector.PATH_TRAVERSAL: 'path_traversal',
            AttackVector.DATA_EXFILTRATION: 'data_exfiltration',
            AttackVector.UNSAFE_DESERIALIZATION: 'unsafe_deserialization',
            AttackVector.OBFUSCATION: 'obfuscation',
            AttackVector.SSRF: 'ssrf',
            AttackVector.PROMPT_INJECTION: 'prompt_injection',
        }
        return mapping.get(attack_vector, 'command_injection')

    def get_attack_vector_for_category(self, category: str) -> AttackVector:
        """Map pattern category to attack vector"""
        mapping = {
            'command_injection': AttackVector.COMMAND_INJECTION,
            'credential_theft': AttackVector.CREDENTIAL_THEFT,
            'path_traversal': AttackVector.PATH_TRAVERSAL,
            'data_exfiltration': AttackVector.DATA_EXFILTRATION,
            'unsafe_deserialization': AttackVector.UNSAFE_DESERIALIZATION,
            'obfuscation': AttackVector.OBFUSCATION,
            'ssrf': AttackVector.SSRF,
            'prompt_injection': AttackVector.PROMPT_INJECTION,
            'crypto_weakness': AttackVector.CREDENTIAL_THEFT,  # Map to closest
            'file_operations': AttackVector.PATH_TRAVERSAL,   # Map to closest
        }
        return mapping.get(category, AttackVector.DATA_EXFILTRATION)

    def scan_content(self, content: str, file_path: str, categories: list[str] | None = None) -> list[tuple[str, ThreatSeverity, str, list[str], int, str]]:
        """
        Scan content for threats using centralized patterns
        Returns: List of (category, severity, description, cwe_ids, line_number, code_snippet)
        """
        if categories is None:
            categories = self.get_all_categories()

        threats = []
        lines = content.split('\n')

        for category in categories:
            compiled_patterns = self.get_compiled_patterns(category)

            for line_num, line in enumerate(lines, 1):
                for pattern, severity, description, cwe_ids in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        threats.append((
                            category,
                            severity,
                            f"{description}: {match.group(0)}",
                            cwe_ids,
                            line_num,
                            line.strip()[:200]
                        ))
                        break  # Only one match per line per category

        return threats


# Global instance for reuse across the codebase
centralized_patterns = CentralizedRegexPatterns()
