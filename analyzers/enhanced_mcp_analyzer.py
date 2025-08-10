#!/usr/bin/env python3
"""
Enhanced MCP Security Analyzer - Comprehensive threat detection for MCP tools
Improves upon the working analyzer with deeper MCP-specific analysis
"""

import hashlib
import json
import re
import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict, Counter
import ast
import base64

# No external dependencies - using subprocess for git operations

@dataclass
class Threat:
    """Enhanced threat indicator with MCP context"""
    type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # EXEC, CREDENTIAL, NETWORK, FILESYSTEM, etc.
    file: str
    line: int = 0
    description: str = ""
    evidence: str = ""  # Code snippet that triggered detection
    confidence: float = 0.8
    mcp_specific: bool = False  # Is this MCP-specific threat?

@dataclass
class MCPManifest:
    """MCP manifest analysis results"""
    name: str = ""
    description: str = ""
    tools: List[Dict] = field(default_factory=list)
    prompt_injection_risk: bool = False
    dangerous_capabilities: List[str] = field(default_factory=list)
    suspicious_descriptions: List[str] = field(default_factory=list)

@dataclass 
class Report:
    """Enhanced security report"""
    url: str
    threat_level: str
    score: float
    confidence: float  # Overall confidence in assessment
    threats: List[Threat]
    mcp_manifest: Optional[MCPManifest]
    sha512: str
    files_scanned: int
    recommendations: List[str]
    
    def to_json(self):
        """Convert to JSON-serializable dict"""
        return {
            'url': self.url,
            'threat_level': self.threat_level,
            'score': self.score,
            'confidence': self.confidence,
            'threats': [asdict(t) for t in self.threats],
            'mcp_manifest': asdict(self.mcp_manifest) if self.mcp_manifest else None,
            'sha512': self.sha512,
            'files_scanned': self.files_scanned,
            'recommendations': self.recommendations
        }

class EnhancedMCPAnalyzer:
    """
    Comprehensive MCP security analyzer with improved detection
    """
    
    def __init__(self):
        # Enhanced critical patterns for code execution
        self.critical_patterns = [
            # Direct code execution
            (r'\bexec\s*\([^)]*\)', 'EXEC_CALL', 'EXEC', 'Code execution via exec()'),
            (r'\beval\s*\([^)]*\)', 'EVAL_CALL', 'EXEC', 'Code execution via eval()'),
            (r'compile\s*\([^)]*exec[^)]*\)', 'COMPILE_EXEC', 'EXEC', 'Compile with exec mode'),
            
            # Shell command execution
            (r'subprocess.*shell\s*=\s*True', 'SHELL_TRUE', 'EXEC', 'Shell command with shell=True'),
            (r'os\.system\s*\([^)]*\)', 'OS_SYSTEM', 'EXEC', 'Direct OS command execution'),
            (r'os\.popen\s*\([^)]*\)', 'OS_POPEN', 'EXEC', 'OS popen command execution'),
            (r'commands\.get[a-z]*\s*\(', 'COMMANDS_MODULE', 'EXEC', 'Commands module usage'),
            
            # Credential theft patterns
            (r'\.aws[/\\]credentials', 'AWS_CREDS', 'CREDENTIAL', 'Accessing AWS credentials'),
            (r'\.ssh[/\\]id_[rd]sa', 'SSH_KEYS', 'CREDENTIAL', 'Accessing SSH private keys'),
            (r'\.docker[/\\]config\.json', 'DOCKER_CONFIG', 'CREDENTIAL', 'Accessing Docker credentials'),
            (r'\.kube[/\\]config', 'KUBE_CONFIG', 'CREDENTIAL', 'Accessing Kubernetes config'),
            (r'\.git[/\\]config', 'GIT_CONFIG', 'CREDENTIAL', 'Accessing git configuration'),
            (r'\.npmrc|\.pypirc', 'PACKAGE_CREDS', 'CREDENTIAL', 'Accessing package manager credentials'),
            (r'os\.environ.*(?:PASSWORD|TOKEN|KEY|SECRET|API)', 'ENV_SECRETS', 'CREDENTIAL', 'Reading secrets from environment'),
            (r'keyring\.get_password', 'KEYRING_ACCESS', 'CREDENTIAL', 'Accessing system keyring'),
            
            # Data exfiltration patterns
            (r'(?:open|read).*requests\.(?:post|put)', 'EXFIL_HTTP', 'NETWORK', 'Read and HTTP exfiltration pattern'),
            (r'socket.*(?:send|sendall|sendto)', 'EXFIL_SOCKET', 'NETWORK', 'Socket-based data exfiltration'),
            (r'smtplib.*send(?:mail|_message)', 'EXFIL_EMAIL', 'NETWORK', 'Email-based exfiltration'),
            (r'ftplib.*stor[a-z]*', 'EXFIL_FTP', 'NETWORK', 'FTP upload pattern'),
            
            # Persistence/backdoor patterns
            (r'(?:socket|ServerSocket).*(?:bind|listen|accept)', 'BACKDOOR_BIND', 'NETWORK', 'Network backdoor binding'),
            (r'base64\.b64decode.*(?:exec|eval)', 'ENCODED_EXEC', 'EXEC', 'Executing base64 decoded code'),
            (r'pickle\.loads', 'PICKLE_DESERIALIZE', 'EXEC', 'Unsafe pickle deserialization'),
            (r'yaml\.load\s*\([^,)]*\)', 'YAML_UNSAFE', 'EXEC', 'Unsafe YAML load without Loader'),
            
            # Filesystem destruction
            (r'shutil\.rmtree.*[/\\]', 'RMTREE_ROOT', 'FILESYSTEM', 'Recursive directory deletion'),
            (r'os\.remove.*\*', 'WILDCARD_DELETE', 'FILESYSTEM', 'Wildcard file deletion'),
            
            # Process manipulation
            (r'ptrace|process_vm_[rw]', 'PROCESS_INJECT', 'EXEC', 'Process injection/debugging'),
            (r'ctypes.*(?:windll|cdll).*LoadLibrary', 'DLL_INJECTION', 'EXEC', 'DLL/library injection'),
        ]
        
        self.high_patterns = [
            # Network operations
            (r'requests\.(?:post|put|patch)', 'HTTP_WRITE', 'NETWORK', 'Sending data via HTTP'),
            (r'urllib.*urlopen.*data\s*=', 'URLLIB_POST', 'NETWORK', 'URLLib data sending'),
            (r'websocket.*send', 'WEBSOCKET_SEND', 'NETWORK', 'WebSocket communication'),
            
            # File operations
            (r'open\s*\([^,)]*["\']w', 'FILE_WRITE', 'FILESYSTEM', 'Writing to files'),
            (r'chmod.*777', 'CHMOD_DANGEROUS', 'FILESYSTEM', 'Setting dangerous permissions'),
            
            # Import patterns
            (r'__import__', 'DYNAMIC_IMPORT', 'EXEC', 'Dynamic module import'),
            (r'importlib\.import_module', 'IMPORTLIB', 'EXEC', 'Dynamic import via importlib'),
            
            # Registry/system modification (Windows)
            (r'winreg|_winreg', 'REGISTRY_ACCESS', 'FILESYSTEM', 'Windows registry access'),
            
            # Database operations
            (r'(?:DROP|DELETE|TRUNCATE)\s+(?:TABLE|DATABASE)', 'SQL_DESTRUCTIVE', 'DATABASE', 'Destructive SQL operations'),
        ]
        
        self.medium_patterns = [
            # Imports that could be dangerous
            (r'import\s+os(?:\s|$|;)', 'IMPORT_OS', 'IMPORT', 'Potentially dangerous import: os'),
            (r'import\s+subprocess', 'IMPORT_SUBPROCESS', 'IMPORT', 'Potentially dangerous import: subprocess'),
            (r'import\s+socket', 'IMPORT_SOCKET', 'IMPORT', 'Network capability import'),
            
            # Encoding/decoding
            (r'base64\.b64decode', 'BASE64_DECODE', 'ENCODING', 'Base64 decoding'),
            (r'codecs\.decode.*hex', 'HEX_DECODE', 'ENCODING', 'Hex decoding'),
            
            # Logging/debugging
            (r'logging\.(?:debug|info).*(?:password|token|key)', 'LOG_SECRETS', 'CREDENTIAL', 'Potential secret logging'),
        ]
        
        # MCP-specific patterns
        self.mcp_tool_patterns = [
            # Dangerous tool capabilities
            (r'"name":\s*"(?:execute|run|shell|cmd|exec)"', 'MCP_EXEC_TOOL', 'MCP', 'MCP tool with execution capability'),
            (r'"name":\s*"(?:read|get|fetch).*(?:file|config|cred)"', 'MCP_READ_TOOL', 'MCP', 'MCP tool reading sensitive data'),
            (r'"name":\s*"(?:write|save|store|delete|remove)"', 'MCP_WRITE_TOOL', 'MCP', 'MCP tool with write capability'),
        ]
        
        # Enhanced prompt injection patterns
        self.prompt_injection_patterns = [
            # Direct instruction override
            r'ignore\s+(?:all\s+)?previous\s+instructions',
            r'disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:instructions|rules)',
            r'forget\s+everything',
            
            # Role reassignment
            r'you\s+are\s+now\s+(?:a|an)',
            r'act\s+as\s+(?:a|an)',
            r'pretend\s+(?:to\s+be|you\s+are)',
            r'system\s*:\s*you\s+(?:are|must)',
            
            # Instruction injection
            r'</(?:system|instruction|user)>',
            r'<(?:system|instruction|admin)>',
            r'\[INST\]|\[/INST\]',
            r'###\s*(?:System|Instruction)',
            
            # Safety bypass
            r'(?:disable|ignore|bypass)\s+(?:all\s+)?(?:safety|security)',
            r'(?:no\s+)?(?:ethical|safety)\s+(?:guidelines|restrictions)',
            
            # Hidden instructions
            r'<!--.*(?:system|execute|run).*-->',
            r'/\*.*(?:system|execute|run).*\*/',
            r'[\x00-\x08\x0B\x0C\x0E-\x1F]',  # Control characters
        ]
        
        # Obfuscation indicators
        self.obfuscation_patterns = [
            (r'[A-Za-z0-9+/]{100,}={0,2}', 'BASE64_BLOB', 'Large base64 encoded block'),
            (r'(?:\\x[0-9a-f]{2}){20,}', 'HEX_ENCODED', 'Hex encoded string'),
            (r'(?:chr\s*\(\s*\d+\s*\)[\s\+]*){10,}', 'CHR_OBFUSCATION', 'Character code obfuscation'),
            (r'(?:_){5,}', 'UNDERSCORE_OBFUSCATION', 'Excessive underscores'),
            (r'(?:[Il1]{6,}|[O0]{6,})', 'HOMOGLYPH_OBFUSCATION', 'Potential homoglyph obfuscation'),
        ]
        
        # Dangerous MCP tool descriptions
        self.dangerous_descriptions = [
            'execute', 'run', 'shell', 'command', 'system',
            'credential', 'password', 'token', 'secret', 'key',
            'delete', 'remove', 'destroy', 'wipe', 'clear',
            'upload', 'download', 'exfiltrate', 'send', 'post',
            'inject', 'modify', 'alter', 'change', 'write'
        ]
        
        # External content fetching patterns (vulnerability to prompt injection)
        self.external_content_patterns = [
            # GitHub API patterns that fetch user-controlled content
            (r'github\.com/repos/[^/]+/[^/]+/issues', 'GITHUB_ISSUE_FETCH', 'EXTERNAL', 'Fetching GitHub issues (potential prompt injection)'),
            (r'api\.github\.com/.*(?:issues|pulls|comments)', 'GITHUB_API_CONTENT', 'EXTERNAL', 'GitHub API fetching user content'),
            (r'/repos/.*/issues/.*/comments', 'GITHUB_COMMENTS', 'EXTERNAL', 'Fetching issue comments'),
            (r'/repos/.*/pulls/.*/comments', 'GITHUB_PR_COMMENTS', 'EXTERNAL', 'Fetching PR comments'),
            
            # Generic external content fetching
            (r'fetch.*(?:body|description|content|text).*(?:issue|comment|pr|pull)', 'FETCH_USER_CONTENT', 'EXTERNAL', 'Fetching user-generated content'),
            (r'(?:get|fetch|read).*(?:Issue|Comment|PR|PullRequest)', 'API_USER_CONTENT', 'EXTERNAL', 'API call for user content'),
            
            # Unsafe content handling
            (r'innerHTML\s*=', 'UNSAFE_HTML', 'EXTERNAL', 'Direct innerHTML assignment'),
            (r'dangerouslySetInnerHTML', 'REACT_UNSAFE_HTML', 'EXTERNAL', 'React unsafe HTML rendering'),
            (r'v-html\s*=', 'VUE_UNSAFE_HTML', 'EXTERNAL', 'Vue unsafe HTML directive'),
        ]
        
        # Secret exposure patterns
        self.secret_exposure_patterns = [
            # Patterns that might expose secrets in responses
            (r'(?:return|send|response).*process\.env', 'ENV_IN_RESPONSE', 'SECRET_EXPOSURE', 'Environment variables in response'),
            (r'JSON\.stringify.*process\.env', 'ENV_STRINGIFY', 'SECRET_EXPOSURE', 'Stringifying environment variables'),
            (r'console\.(?:log|error|info).*(?:token|key|secret|password)', 'LOG_SECRETS', 'SECRET_EXPOSURE', 'Logging potential secrets'),
            (r'(?:res|response)\.(?:send|json|write).*(?:env|config|credentials)', 'RESPONSE_SECRETS', 'SECRET_EXPOSURE', 'Sending config/credentials in response'),
            
            # Template injection risks
            (r'\$\{.*\}', 'TEMPLATE_INJECTION', 'SECRET_EXPOSURE', 'Template literal with user input risk'),
            (r'eval.*template', 'TEMPLATE_EVAL', 'SECRET_EXPOSURE', 'Evaluating templates'),
        ]
    
    def analyze(self, repo_url: str) -> Report:
        """Main analysis function"""
        print(f"\n[SCAN] Analyzing: {repo_url}")
        
        # Clone repository
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "repo"
            
            try:
                print("[SCAN] Cloning repository...")
                subprocess.run(['git', 'clone', '--depth', '1', repo_url, str(repo_path)], 
                             check=True, capture_output=True, text=True)
            except Exception as e:
                print(f"[ERROR] Clone failed: {e}")
                return Report(
                    url=repo_url,
                    threat_level="ERROR",
                    score=0,
                    confidence=0,
                    threats=[],
                    mcp_manifest=None,
                    sha512="",
                    files_scanned=0,
                    recommendations=["Failed to clone repository"]
                )
            
            return self._analyze_repo(repo_path, repo_url)
    
    def _analyze_repo(self, repo_path: Path, repo_url: str) -> Report:
        """Comprehensive repository analysis"""
        threats = []
        files_scanned = 0
        all_content = []
        mcp_manifest = None
        
        # Import smart file filter
        try:
            from smart_file_filter import get_files_to_scan, SKIP_DIRS
        except ImportError:
            # Fallback to basic filtering
            SKIP_DIRS = {'node_modules', 'venv', '.venv', 'site-packages', 
                        'virtualenvs', '__pycache__', '.git', 'dist', 'build',
                        'Library', 'Caches', '.cache', 'vendor'}
        
        # First, analyze MCP manifest files
        for manifest_name in ['mcp.json', 'manifest.json', 'package.json']:
            manifest_path = repo_path / manifest_name
            if manifest_path.exists():
                print(f"[SCAN] Analyzing manifest: {manifest_name}")
                mcp_manifest = self._analyze_mcp_manifest(manifest_path, repo_path)
                if mcp_manifest.prompt_injection_risk:
                    threats.append(Threat(
                        type='MCP_PROMPT_INJECTION',
                        severity='CRITICAL',
                        category='MCP',
                        file=manifest_name,
                        description='Prompt injection in MCP manifest',
                        confidence=0.95,
                        mcp_specific=True
                    ))
                
                # Check for dangerous capabilities
                for capability in mcp_manifest.dangerous_capabilities:
                    threats.append(Threat(
                        type='MCP_DANGEROUS_CAPABILITY',
                        severity='HIGH',
                        category='MCP',
                        file=manifest_name,
                        description=f'Dangerous capability declared: {capability}',
                        confidence=0.85,
                        mcp_specific=True
                    ))
        
        # Scan all code files with smart filtering
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.go', '.rs', '.java', '.rb'}
        
        # Try to use smart filter if available
        try:
            from smart_file_filter import get_files_to_scan
            files_to_scan = get_files_to_scan(repo_path)
            print(f"[SCAN] Smart filter: Found {len(files_to_scan)} files to analyze")
        except ImportError:
            # Fallback to basic filtering
            files_to_scan = []
            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and file_path.suffix in extensions:
                    # Skip common directories that shouldn't be scanned
                    skip_this = False
                    for parent in file_path.parents:
                        if parent.name in SKIP_DIRS:
                            skip_this = True
                            break
                    if not skip_this:
                        files_to_scan.append(file_path)
        
        # Scan the filtered files
        for file_path in files_to_scan:
            if file_path.suffix in extensions:
                relative_path = file_path.relative_to(repo_path)
                
                # Skip if path is too deep (likely in dependencies)
                if len(relative_path.parts) > 5:
                    continue
                    
                print(f"[SCAN] Scanning: {relative_path}")
                files_scanned += 1
                
                if file_path.suffix == '.py':
                    file_threats = self._scan_python_file(file_path, repo_path)
                elif file_path.suffix in {'.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'}:
                    file_threats = self._scan_javascript_file(file_path, repo_path)
                elif file_path.suffix == '.go':
                    file_threats = self._scan_go_file(file_path, repo_path)
                else:
                    # Generic scan for other languages
                    file_threats = self._scan_generic_file(file_path, repo_path)
                
                threats.extend(file_threats)
                
                # Collect for fingerprinting
                try:
                    with open(file_path, 'rb') as f:
                        all_content.append(f.read())
                except:
                    pass
        
        # Calculate SHA512 fingerprint
        combined = b''.join(all_content)
        sha512 = hashlib.sha512(combined).hexdigest() if combined else ""
        
        # Enhanced scoring and confidence calculation
        score, confidence = self._calculate_enhanced_score(threats, mcp_manifest)
        threat_level = self._get_threat_level(score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threats, mcp_manifest, threat_level)
        
        return Report(
            url=repo_url,
            threat_level=threat_level,
            score=score,
            confidence=confidence,
            threats=threats,
            mcp_manifest=mcp_manifest,
            sha512=sha512,
            files_scanned=files_scanned,
            recommendations=recommendations
        )
    
    def _analyze_mcp_manifest(self, manifest_path: Path, repo_path: Path) -> MCPManifest:
        """Deep analysis of MCP manifest file"""
        manifest = MCPManifest()
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except:
            return manifest
        
        # Extract basic info
        manifest.name = data.get('name', '')
        manifest.description = data.get('description', '')
        
        # Check for prompt injection in description
        description_lower = manifest.description.lower()
        for pattern in self.prompt_injection_patterns:
            if re.search(pattern, manifest.description, re.IGNORECASE):
                manifest.prompt_injection_risk = True
                break
        
        # Analyze tools if present
        if 'tools' in data:
            manifest.tools = data['tools'] if isinstance(data['tools'], list) else []
            
            for tool in manifest.tools:
                if isinstance(tool, dict):
                    tool_name = tool.get('name', '').lower()
                    tool_desc = tool.get('description', '').lower()
                    
                    # Check for dangerous capabilities
                    for dangerous_word in self.dangerous_descriptions:
                        if dangerous_word in tool_name or dangerous_word in tool_desc:
                            manifest.dangerous_capabilities.append(f"{tool.get('name', 'unknown')}: {dangerous_word}")
                    
                    # Check tool arguments for dangerous patterns
                    if 'arguments' in tool:
                        args_str = json.dumps(tool['arguments']).lower()
                        if any(word in args_str for word in ['command', 'shell', 'exec', 'code']):
                            manifest.dangerous_capabilities.append(f"{tool.get('name', 'unknown')}: dangerous arguments")
        
        # Check for suspicious patterns in entire manifest
        manifest_str = json.dumps(data).lower()
        suspicious_patterns = [
            'base64', 'decode', 'eval', 'exec', 'shell', 
            'subprocess', 'os.system', 'require("child_process")'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in manifest_str:
                manifest.suspicious_descriptions.append(pattern)
        
        return manifest
    
    def _scan_python_file(self, file_path: Path, repo_path: Path) -> List[Threat]:
        """Enhanced Python file scanning"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return threats
        
        relative_path = file_path.relative_to(repo_path)
        
        # Scan with all pattern categories
        for patterns, severity_override in [
            (self.critical_patterns, None),
            (self.high_patterns, None),
            (self.medium_patterns, None),
            (self.mcp_tool_patterns, 'HIGH')
        ]:
            for pattern_tuple in patterns:
                if len(pattern_tuple) == 4:
                    pattern, threat_type, category, description = pattern_tuple
                    severity = severity_override or 'CRITICAL'
                else:
                    continue
                
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    # Extract evidence (the matching line)
                    evidence_line = lines[line_num - 1] if line_num <= len(lines) else ""
                    
                    threats.append(Threat(
                        type=threat_type,
                        severity=severity if not severity_override else severity_override,
                        category=category,
                        file=str(relative_path),
                        line=line_num,
                        description=description,
                        evidence=evidence_line.strip()[:100],  # First 100 chars of evidence
                        confidence=0.95 if severity == 'CRITICAL' else 0.85,
                        mcp_specific=(category == 'MCP')
                    ))
        
        # Enhanced AST analysis
        try:
            tree = ast.parse(content)
            ast_threats = self._analyze_ast_enhanced(tree, relative_path, lines)
            threats.extend(ast_threats)
        except:
            pass
        
        # Check for obfuscation
        obfuscation_score = self._check_obfuscation(content)
        if obfuscation_score > 0.6:
            threats.append(Threat(
                type='CODE_OBFUSCATION',
                severity='HIGH' if obfuscation_score > 0.8 else 'MEDIUM',
                category='OBFUSCATION',
                file=str(relative_path),
                description=f'Code appears obfuscated (score: {obfuscation_score:.2f})',
                confidence=obfuscation_score,
                mcp_specific=False
            ))
        
        return threats
    
    def _scan_javascript_file(self, file_path: Path, repo_path: Path) -> List[Threat]:
        """Enhanced JavaScript/TypeScript file scanning"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return threats
        
        relative_path = file_path.relative_to(repo_path)
        
        # JavaScript-specific critical patterns
        js_patterns = [
            (r'\beval\s*\([^)]*\)', 'JS_EVAL', 'CRITICAL', 'EXEC', 'JavaScript eval() usage'),
            (r'new\s+Function\s*\([^)]*\)', 'JS_FUNCTION', 'HIGH', 'EXEC', 'Dynamic Function constructor'),
            (r'require\s*\(["\']child_process["\']\)', 'JS_CHILD_PROCESS', 'CRITICAL', 'EXEC', 'Node.js child process'),
            (r'\.exec\s*\([^)]*\)', 'JS_EXEC', 'CRITICAL', 'EXEC', 'Command execution'),
            (r'\.execSync\s*\([^)]*\)', 'JS_EXEC_SYNC', 'CRITICAL', 'EXEC', 'Synchronous command execution'),
            (r'fs\.(?:unlink|rmdir|rm)(?:Sync)?\s*\(', 'JS_DELETE', 'HIGH', 'FILESYSTEM', 'File deletion'),
            (r'process\.env\.[A-Z_]*(?:PASSWORD|TOKEN|KEY|SECRET)', 'JS_ENV_SECRETS', 'HIGH', 'CREDENTIAL', 'Reading secrets from env'),
            (r'require\s*\(["\']fs["\']\).*\.(?:read|write)', 'JS_FS_OPS', 'MEDIUM', 'FILESYSTEM', 'File system operations'),
            (r'fetch\s*\([^)]*method\s*:\s*["\'](?:POST|PUT)["\']', 'JS_FETCH_WRITE', 'MEDIUM', 'NETWORK', 'Sending data via fetch'),
            (r'XMLHttpRequest.*\.send\s*\(', 'JS_XHR_SEND', 'MEDIUM', 'NETWORK', 'XMLHttpRequest data sending'),
        ]
        
        for pattern, threat_type, severity, category, description in js_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                evidence_line = lines[line_num - 1] if line_num <= len(lines) else ""
                
                threats.append(Threat(
                    type=threat_type,
                    severity=severity,
                    category=category,
                    file=str(relative_path),
                    line=line_num,
                    description=description,
                    evidence=evidence_line.strip()[:100],
                    confidence=0.9 if severity == 'CRITICAL' else 0.8,
                    mcp_specific=False
                ))
        
        # Check for obfuscation
        if self._check_obfuscation(content) > 0.6:
            threats.append(Threat(
                type='JS_OBFUSCATION',
                severity='HIGH',
                category='OBFUSCATION',
                file=str(relative_path),
                description='JavaScript code appears obfuscated',
                confidence=0.75,
                mcp_specific=False
            ))
        
        return threats
    
    def _scan_go_file(self, file_path: Path, repo_path: Path) -> List[Threat]:
        """Scan Go files for security issues"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return threats
        
        relative_path = file_path.relative_to(repo_path)
        
        # Go-specific security patterns
        go_patterns = [
            # Command execution
            (r'exec\.Command\s*\([^)]*\)', 'GO_EXEC_COMMAND', 'CRITICAL', 'EXEC', 'Go command execution'),
            (r'os\.Exec\s*\([^)]*\)', 'GO_OS_EXEC', 'CRITICAL', 'EXEC', 'Go os.Exec usage'),
            (r'syscall\.Exec\s*\([^)]*\)', 'GO_SYSCALL_EXEC', 'CRITICAL', 'EXEC', 'Go syscall execution'),
            
            # Unsafe operations
            (r'unsafe\.Pointer', 'GO_UNSAFE_POINTER', 'HIGH', 'MEMORY', 'Unsafe pointer operations'),
            (r'reflect\.Value.*\.UnsafeAddr\(\)', 'GO_UNSAFE_ADDR', 'HIGH', 'MEMORY', 'Unsafe memory address access'),
            
            # File operations
            (r'os\.Remove\s*\([^)]*\)', 'GO_FILE_DELETE', 'MEDIUM', 'FILESYSTEM', 'File deletion'),
            (r'os\.RemoveAll\s*\([^)]*\)', 'GO_RECURSIVE_DELETE', 'HIGH', 'FILESYSTEM', 'Recursive deletion'),
            
            # Network operations
            (r'net/http.*Get\s*\([^)]*\)', 'GO_HTTP_GET', 'LOW', 'NETWORK', 'HTTP GET request'),
            (r'net/http.*Post\s*\([^)]*\)', 'GO_HTTP_POST', 'MEDIUM', 'NETWORK', 'HTTP POST request'),
            
            # Template execution
            (r'template\..*Execute\s*\([^)]*\)', 'GO_TEMPLATE_EXEC', 'MEDIUM', 'TEMPLATE', 'Template execution'),
            (r'template\.HTML\s*\([^)]*\)', 'GO_UNSAFE_HTML', 'HIGH', 'TEMPLATE', 'Unsafe HTML template'),
        ]
        
        # External content fetching patterns specific to Go
        go_external_patterns = [
            (r'github\.com/google/go-github', 'GO_GITHUB_CLIENT', 'HIGH', 'EXTERNAL', 'GitHub client library usage'),
            (r'Issues\.Get\s*\([^)]*\)', 'GO_GET_ISSUE', 'HIGH', 'EXTERNAL', 'Fetching GitHub issue'),
            (r'Issues\.ListComments', 'GO_LIST_COMMENTS', 'HIGH', 'EXTERNAL', 'Fetching issue comments'),
            (r'PullRequests\.Get', 'GO_GET_PR', 'HIGH', 'EXTERNAL', 'Fetching pull request'),
            (r'\.GetBody\(\)', 'GO_GET_BODY', 'HIGH', 'EXTERNAL', 'Getting issue/PR body content'),
        ]
        
        # Check all patterns
        all_patterns = go_patterns + go_external_patterns
        for pattern, threat_type, severity, category, description in all_patterns:
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                evidence_line = lines[line_num - 1] if line_num <= len(lines) else ""
                
                threats.append(Threat(
                    type=threat_type,
                    severity=severity,
                    category=category,
                    file=str(relative_path),
                    line=line_num,
                    description=description,
                    evidence=evidence_line.strip()[:100],
                    confidence=0.85,
                    mcp_specific=False
                ))
        
        # Check for external content patterns
        for pattern, threat_type, category, description in self.external_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(Threat(
                    type=threat_type,
                    severity='HIGH',
                    category=category,
                    file=str(relative_path),
                    description=description,
                    confidence=0.9,
                    mcp_specific=True
                ))
        
        # Check for secret exposure
        for pattern, threat_type, category, description in self.secret_exposure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(Threat(
                    type=threat_type,
                    severity='CRITICAL',
                    category=category,
                    file=str(relative_path),
                    description=description,
                    confidence=0.95,
                    mcp_specific=True
                ))
        
        return threats
    
    def _scan_generic_file(self, file_path: Path, repo_path: Path) -> List[Threat]:
        """Generic scanning for other language files"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return threats
        
        relative_path = file_path.relative_to(repo_path)
        
        # Check for external content patterns
        for pattern, threat_type, category, description in self.external_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(Threat(
                    type=threat_type,
                    severity='HIGH',
                    category=category,
                    file=str(relative_path),
                    description=description,
                    confidence=0.8,
                    mcp_specific=True
                ))
        
        # Check for secret exposure patterns
        for pattern, threat_type, category, description in self.secret_exposure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(Threat(
                    type=threat_type,
                    severity='CRITICAL',
                    category=category,
                    file=str(relative_path),
                    description=description,
                    confidence=0.85,
                    mcp_specific=True
                ))
        
        return threats
    
    def _analyze_ast_enhanced(self, tree: ast.AST, relative_path: Path, lines: List[str]) -> List[Threat]:
        """Enhanced AST analysis with more patterns"""
        threats = []
        
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, parent):
                self.parent = parent
                self.threats = []
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    if func_name in ['exec', 'eval']:
                        self.threats.append(Threat(
                            type=f'AST_{func_name.upper()}',
                            severity='CRITICAL',
                            category='EXEC',
                            file=str(relative_path),
                            line=getattr(node, 'lineno', 0),
                            description=f'AST confirmed {func_name}() call',
                            evidence=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            confidence=1.0,
                            mcp_specific=False
                        ))
                    
                    elif func_name in ['__import__', 'compile']:
                        self.threats.append(Threat(
                            type=f'AST_{func_name.upper()}',
                            severity='HIGH',
                            category='EXEC',
                            file=str(relative_path),
                            line=getattr(node, 'lineno', 0),
                            description=f'Dynamic {func_name}() usage',
                            evidence=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            confidence=0.9,
                            mcp_specific=False
                        ))
                
                # Check for subprocess with shell=True
                elif isinstance(node.func, ast.Attribute):
                    if (hasattr(node.func.value, 'id') and 
                        node.func.value.id == 'subprocess' and 
                        node.func.attr in ['run', 'call', 'Popen']):
                        
                        # Check for shell=True in arguments
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value is True:
                                    self.threats.append(Threat(
                                        type='AST_SHELL_TRUE',
                                        severity='CRITICAL',
                                        category='EXEC',
                                        file=str(relative_path),
                                        line=getattr(node, 'lineno', 0),
                                        description='AST confirmed shell=True',
                                        evidence=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                        confidence=1.0,
                                        mcp_specific=False
                                    ))
                
                self.generic_visit(node)
            
            def visit_Import(self, node):
                # Track dangerous imports
                for alias in node.names:
                    if alias.name in ['os', 'subprocess', 'socket', 'pickle', 'marshal']:
                        self.threats.append(Threat(
                            type=f'AST_IMPORT_{alias.name.upper()}',
                            severity='MEDIUM',
                            category='IMPORT',
                            file=str(relative_path),
                            line=getattr(node, 'lineno', 0),
                            description=f'Import of potentially dangerous module: {alias.name}',
                            confidence=0.7,
                            mcp_specific=False
                        ))
                
                self.generic_visit(node)
        
        visitor = SecurityVisitor(self)
        visitor.visit(tree)
        return visitor.threats
    
    def _check_obfuscation(self, content: str) -> float:
        """Calculate obfuscation score (0-1)"""
        if not content:
            return 0.0
        
        score = 0.0
        indicators = 0
        
        # Check each obfuscation pattern
        for pattern, _, description in self.obfuscation_patterns:
            matches = re.findall(pattern, content)
            if matches:
                indicators += 1
                # Weight by number of matches
                score += min(0.2, len(matches) * 0.05)
        
        # Check entropy (randomness)
        if len(content) > 100:
            # Simple entropy approximation
            char_freq = Counter(content)
            entropy = -sum((count/len(content)) * (count/len(content)) 
                          for count in char_freq.values() if count > 0)
            
            # High entropy suggests obfuscation
            if entropy > 5.5:
                score += 0.2
        
        # Check for suspicious variable names
        var_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]{15,}\b'
        long_vars = re.findall(var_pattern, content)
        if len(long_vars) > 10:
            score += 0.15
        
        # Check for excessive special characters
        special_ratio = sum(1 for c in content if not c.isalnum() and c not in ' \n\t') / len(content)
        if special_ratio > 0.4:
            score += 0.15
        
        return min(1.0, score)
    
    def _calculate_enhanced_score(self, threats: List[Threat], manifest: Optional[MCPManifest]) -> Tuple[float, float]:
        """Calculate threat score and confidence"""
        if not threats and (not manifest or not manifest.dangerous_capabilities):
            return 0.0, 1.0
        
        score = 0.0
        confidence_sum = 0.0
        confidence_count = 0
        
        # Weight by severity and category
        severity_weights = {
            'CRITICAL': 0.25,
            'HIGH': 0.12,
            'MEDIUM': 0.06,
            'LOW': 0.03
        }
        
        # Category multipliers (some categories are more dangerous)
        category_multipliers = {
            'EXEC': 1.5,       # Code execution is most dangerous
            'CREDENTIAL': 1.4,  # Credential theft is very dangerous
            'NETWORK': 1.2,     # Network operations are concerning
            'MCP': 1.3,        # MCP-specific threats are important
            'FILESYSTEM': 1.0,
            'DATABASE': 1.0,
            'OBFUSCATION': 1.1,
            'IMPORT': 0.8,
            'ENCODING': 0.7
        }
        
        # Process threats
        threat_categories = set()
        for threat in threats:
            weight = severity_weights.get(threat.severity, 0.05)
            multiplier = category_multipliers.get(threat.category, 1.0)
            
            # MCP-specific threats get a bonus
            if threat.mcp_specific:
                multiplier *= 1.2
            
            score += weight * multiplier * threat.confidence
            confidence_sum += threat.confidence
            confidence_count += 1
            threat_categories.add(threat.category)
        
        # Add manifest analysis
        if manifest:
            if manifest.prompt_injection_risk:
                score += 0.3
                confidence_sum += 0.95
                confidence_count += 1
            
            for _ in manifest.dangerous_capabilities:
                score += 0.1
                confidence_sum += 0.85
                confidence_count += 1
        
        # Bonus for multiple threat categories (indicates comprehensive malicious behavior)
        if len(threat_categories) >= 3:
            score *= 1.2
        
        # Calculate average confidence
        avg_confidence = confidence_sum / confidence_count if confidence_count > 0 else 0.5
        
        # Adjust confidence based on number of indicators
        if len(threats) < 2:
            avg_confidence *= 0.8  # Low confidence with few indicators
        elif len(threats) > 10:
            avg_confidence = min(1.0, avg_confidence * 1.1)  # Higher confidence with many indicators
        
        return min(1.0, score), avg_confidence
    
    def _get_threat_level(self, score: float) -> str:
        """Determine threat level from score"""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        elif score >= 0.2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_recommendations(self, threats: List[Threat], manifest: Optional[MCPManifest], threat_level: str) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Base recommendation on threat level
        if threat_level == 'CRITICAL':
            recommendations.append("⛔ DO NOT USE - Critical security vulnerabilities detected")
            recommendations.append("This tool shows clear signs of malicious intent")
        elif threat_level == 'HIGH':
            recommendations.append("⚠️ HIGH RISK - Extensive security review required before use")
            recommendations.append("Multiple dangerous patterns detected that could compromise security")
        elif threat_level == 'MEDIUM':
            recommendations.append("⚠️ MODERATE RISK - Review flagged issues before deployment")
            recommendations.append("Some concerning patterns found that need investigation")
        elif threat_level == 'LOW':
            recommendations.append("ℹ️ LOW RISK - Minor concerns detected")
            recommendations.append("Review flagged items but likely safe with precautions")
        else:
            recommendations.append("✅ MINIMAL RISK - No significant threats detected")
            recommendations.append("Standard security practices still recommended")
        
        # Specific recommendations based on threat categories
        threat_categories = {t.category for t in threats}
        
        if 'EXEC' in threat_categories:
            recommendations.append("• Code execution capabilities detected - verify all execution is sandboxed")
        
        if 'CREDENTIAL' in threat_categories:
            recommendations.append("• Credential access patterns found - ensure no sensitive data is exposed")
        
        if 'NETWORK' in threat_categories:
            recommendations.append("• Network operations detected - monitor all external communications")
        
        if 'OBFUSCATION' in threat_categories:
            recommendations.append("• Obfuscated code found - manual review required to understand intent")
        
        if 'EXTERNAL' in threat_categories:
            recommendations.append("⚠️ CRITICAL: Fetches external user content (GitHub issues/PRs/comments)")
            recommendations.append("  This can lead to prompt injection attacks that expose secrets!")
            recommendations.append("  Ensure all external content is properly sanitized before processing")
        
        if 'SECRET_EXPOSURE' in threat_categories:
            recommendations.append("⚠️ CRITICAL: Potential secret exposure patterns detected")
            recommendations.append("  Review how environment variables and configs are handled")
            recommendations.append("  Ensure secrets cannot be leaked through responses or logs")
        
        if manifest and manifest.prompt_injection_risk:
            recommendations.append("• Prompt injection risk in manifest - do not trust tool descriptions")
        
        # Add mitigation suggestions
        if threat_level in ['HIGH', 'CRITICAL']:
            recommendations.append("\nMitigation steps:")
            recommendations.append("1. Run in isolated environment only")
            recommendations.append("2. Monitor all file and network access")
            recommendations.append("3. Review source code manually before execution")
            recommendations.append("4. Consider using alternative tools")
        
        return recommendations

def display_report(report: Report):
    """Display comprehensive security report"""
    print("\n" + "="*70)
    print("SECURITY ANALYSIS REPORT")
    print("="*70)
    print(f"Target: {report.url}")
    print(f"Files Scanned: {report.files_scanned}")
    print(f"Confidence: {report.confidence:.1%}")
    
    print(f"\n📊 ASSESSMENT:")
    print(f"  Threat Level: {report.threat_level}")
    print(f"  Risk Score: {report.score:.2%}")
    
    print(f"\n🔐 SHA512 Fingerprint:")
    if report.sha512:
        print(f"  {report.sha512[:64]}")
        print(f"  {report.sha512[64:128] if len(report.sha512) > 64 else ''}")
    
    if report.threats:
        print(f"\n⚠️ THREATS DETECTED: {len(report.threats)}")
        
        # Group by severity
        by_severity = defaultdict(list)
        for threat in report.threats:
            by_severity[threat.severity].append(threat)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                print(f"\n{severity} SEVERITY ({len(by_severity[severity])} threats):")
                for threat in by_severity[severity][:5]:  # Show top 5
                    print(f"  • {threat.category}:{threat.type}")
                    print(f"    {threat.description}")
                    print(f"    File: {threat.file}, Line: {threat.line}")
                    if threat.evidence:
                        print(f"    Evidence:")
                        print(f"    {threat.evidence[:80]}...")
                
                if len(by_severity[severity]) > 5:
                    print(f"    ... and {len(by_severity[severity]) - 5} more")
    else:
        print("\n✅ No threats detected")
    
    # Display MCP manifest analysis
    if report.mcp_manifest:
        print(f"\n📦 MCP MANIFEST ANALYSIS:")
        print(f"  Name: {report.mcp_manifest.name}")
        if report.mcp_manifest.prompt_injection_risk:
            print(f"  ⚠️ PROMPT INJECTION DETECTED")
        if report.mcp_manifest.dangerous_capabilities:
            print(f"  Dangerous capabilities: {len(report.mcp_manifest.dangerous_capabilities)}")
            for cap in report.mcp_manifest.dangerous_capabilities[:3]:
                print(f"    - {cap}")
    
    # Display recommendations
    print(f"\n💡 SECURITY RECOMMENDATION:")
    for rec in report.recommendations:
        if rec.startswith("•") or rec.startswith("⛔") or rec.startswith("⚠️") or rec.startswith("✅"):
            print(f"  {rec}")
        else:
            print(f"  {rec}")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python enhanced_mcp_analyzer.py <github_url_or_local_path>")
        print("\nExample:")
        print("  python enhanced_mcp_analyzer.py https://github.com/example/mcp-tool")
        print("  python enhanced_mcp_analyzer.py /path/to/local/repo")
        sys.exit(1)
    
    target = sys.argv[1]
    
    analyzer = EnhancedMCPAnalyzer()
    
    # Check if it's a local path or URL
    if target.startswith('http://') or target.startswith('https://'):
        report = analyzer.analyze(target)
    else:
        # Analyze local path
        target_path = Path(target)
        if not target_path.exists():
            print(f"Error: Path {target} does not exist")
            sys.exit(1)
        report = analyzer._analyze_repo(target_path, str(target_path))
    
    # Display report
    display_report(report)
    
    # Save detailed report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f"security_report_{timestamp}.json"
    with open(report_file, 'w') as f:
        json.dump(report.to_json(), f, indent=2)
    
    print(f"\n📁 Detailed report saved to: {report_file}")

if __name__ == "__main__":
    main()