#!/usr/bin/env python3
"""
MCP Security Evaluator - Working Prototype
Test and evaluate MCP tools from GitHub for security threats
"""

import hashlib
import json
import re
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import ast
import math
from collections import Counter

# For GitHub cloning
try:
    import git
except ImportError:
    print("Installing gitpython...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "gitpython"])
    import git

@dataclass
class ThreatIndicator:
    """Represents a detected threat indicator"""
    threat_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    file_path: str
    line_number: Optional[int]
    code_snippet: Optional[str]
    description: str

@dataclass
class SecurityReport:
    """Complete security assessment report"""
    repository_url: str
    scan_timestamp: str
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    threat_score: float
    sha512_fingerprint: str
    total_files_scanned: int
    threats_found: List[ThreatIndicator]
    file_fingerprints: Dict[str, str]
    recommendations: str
    confidence: float

class MCPSecurityEvaluator:
    """
    Evaluate MCP tools for security threats
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.threat_patterns = self._load_threat_patterns()
        self.weight_map = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.2
        }
        
    def _load_threat_patterns(self) -> Dict:
        """Load threat detection patterns"""
        return {
            'command_execution': {
                'patterns': [
                    (r'\bexec\s*\(', 'Direct exec() usage', 'CRITICAL'),
                    (r'\beval\s*\(', 'Direct eval() usage', 'CRITICAL'),
                    (r'subprocess\.(call|run|Popen|check_output)', 'Subprocess execution', 'HIGH'),
                    (r'os\.system\s*\(', 'OS system call', 'CRITICAL'),
                    (r'os\.popen\s*\(', 'OS popen usage', 'HIGH'),
                    (r'commands\.getoutput', 'Commands module usage', 'HIGH'),
                ],
                'description': 'Code execution capabilities'
            },
            'data_exfiltration': {
                'patterns': [
                    (r'requests\.(post|put|patch)\s*\(', 'HTTP POST/PUT request', 'MEDIUM'),
                    (r'urllib.*\.urlopen\s*\([^)]*data=', 'URL POST with data', 'MEDIUM'),
                    (r'socket\.(send|sendall|sendto)\s*\(', 'Raw socket send', 'HIGH'),
                    (r'ftplib\.FTP\s*\(', 'FTP connection', 'HIGH'),
                    (r'smtplib\.SMTP', 'SMTP email sending', 'MEDIUM'),
                    (r'paramiko\.SSHClient', 'SSH connection', 'HIGH'),
                ],
                'description': 'Network data transmission'
            },
            'credential_access': {
                'patterns': [
                    (r'os\.environ\[[\'"][^\'"]*(PASSWORD|KEY|TOKEN|SECRET)', 'Environment credential access', 'HIGH'),
                    (r'open\s*\([^)]*[\'"]([^\'"]*/)?\.env[\'"]', '.env file access', 'HIGH'),
                    (r'open\s*\([^)]*[\'"]([^\'"]*/)?\.aws/credentials', 'AWS credentials access', 'CRITICAL'),
                    (r'open\s*\([^)]*[\'"]([^\'"]*/)?\.ssh/', 'SSH key access', 'CRITICAL'),
                    (r'keyring\.(get_password|get_credential)', 'Keyring access', 'HIGH'),
                    (r'docker\.from_env\(\)', 'Docker credentials', 'HIGH'),
                ],
                'description': 'Credential and secret access'
            },
            'file_system_manipulation': {
                'patterns': [
                    (r'shutil\.rmtree\s*\(', 'Recursive directory deletion', 'HIGH'),
                    (r'os\.remove\s*\(', 'File deletion', 'MEDIUM'),
                    (r'open\s*\([^)]*[\'"]\/etc\/passwd', '/etc/passwd access', 'CRITICAL'),
                    (r'open\s*\([^)]*[\'"]\/etc\/shadow', '/etc/shadow access', 'CRITICAL'),
                    (r'glob\.glob\s*\([^)]*[\'"]\/\*\*', 'Recursive glob', 'MEDIUM'),
                    (r'os\.walk\s*\([\'"]/', 'Root directory walk', 'HIGH'),
                ],
                'description': 'File system operations'
            },
            'obfuscation': {
                'patterns': [
                    (r'base64\.b64decode\s*\(', 'Base64 decoding', 'MEDIUM'),
                    (r'codecs\.decode\s*\([^)]*[\'"]hex[\'"]', 'Hex decoding', 'MEDIUM'),
                    (r'compile\s*\(', 'Dynamic code compilation', 'HIGH'),
                    (r'__import__\s*\(', 'Dynamic import', 'HIGH'),
                    (r'marshal\.loads\s*\(', 'Marshal deserialization', 'HIGH'),
                    (r'pickle\.loads\s*\(', 'Pickle deserialization', 'CRITICAL'),
                ],
                'description': 'Code obfuscation techniques'
            },
            'network_binding': {
                'patterns': [
                    (r'socket\.bind\s*\(', 'Socket binding', 'HIGH'),
                    (r'\.listen\s*\(', 'Socket listening', 'HIGH'),
                    (r'flask\.Flask\s*\(', 'Flask server', 'MEDIUM'),
                    (r'http\.server\.HTTPServer', 'HTTP server', 'MEDIUM'),
                    (r'socketserver\.(TCP|UDP)Server', 'Socket server', 'HIGH'),
                ],
                'description': 'Network server capabilities'
            },
            'persistence': {
                'patterns': [
                    (r'crontab', 'Crontab modification', 'HIGH'),
                    (r'schtasks', 'Windows task scheduler', 'HIGH'),
                    (r'systemd', 'Systemd service', 'HIGH'),
                    (r'\/etc\/rc\.local', 'RC local modification', 'CRITICAL'),
                    (r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'Windows registry persistence', 'CRITICAL'),
                ],
                'description': 'System persistence mechanisms'
            }
        }
    
    def evaluate_repository(self, repo_url: str) -> SecurityReport:
        """
        Main entry point - evaluate a GitHub repository
        """
        self._print(f"Starting security evaluation of: {repo_url}")
        
        # Clone repository
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            self._print(f"Cloning repository to temporary directory...")
            
            try:
                git.Repo.clone_from(repo_url, repo_path, depth=1)
            except Exception as e:
                self._print(f"Error cloning repository: {e}")
                raise
            
            # Scan repository
            return self._scan_repository(repo_path, repo_url)
    
    def _scan_repository(self, repo_path: Path, repo_url: str) -> SecurityReport:
        """Scan the repository for threats"""
        self._print("Scanning repository for threats...")
        
        threats = []
        file_fingerprints = {}
        total_files = 0
        
        # Scan all Python files
        for py_file in repo_path.rglob("*.py"):
            if '.git' in py_file.parts:
                continue
                
            total_files += 1
            relative_path = py_file.relative_to(repo_path)
            
            # Generate SHA512 fingerprint
            with open(py_file, 'rb') as f:
                content = f.read()
                sha512_hash = hashlib.sha512(content).hexdigest()
                file_fingerprints[str(relative_path)] = sha512_hash
            
            # Scan for threats
            file_threats = self._scan_file(py_file, relative_path)
            threats.extend(file_threats)
        
        # Scan configuration files
        for config_file in ['package.json', 'mcp.json', 'manifest.json', 'setup.py']:
            config_path = repo_path / config_file
            if config_path.exists():
                total_files += 1
                with open(config_path, 'rb') as f:
                    content = f.read()
                    sha512_hash = hashlib.sha512(content).hexdigest()
                    file_fingerprints[config_file] = sha512_hash
                
                # Scan for malicious metadata
                metadata_threats = self._scan_metadata(config_path, config_file)
                threats.extend(metadata_threats)
        
        # Calculate overall threat level
        threat_score = self._calculate_threat_score(threats)
        threat_level = self._determine_threat_level(threat_score)
        
        # Generate master fingerprint
        master_fingerprint = self._generate_master_fingerprint(file_fingerprints)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, threats)
        
        # Calculate confidence
        confidence = self._calculate_confidence(threats, total_files)
        
        return SecurityReport(
            repository_url=repo_url,
            scan_timestamp=datetime.now().isoformat(),
            threat_level=threat_level,
            threat_score=threat_score,
            sha512_fingerprint=master_fingerprint,
            total_files_scanned=total_files,
            threats_found=threats,
            file_fingerprints=file_fingerprints,
            recommendations=recommendations,
            confidence=confidence
        )
    
    def _scan_file(self, file_path: Path, relative_path: Path) -> List[ThreatIndicator]:
        """Scan a single file for threats"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            self._print(f"Error reading {relative_path}: {e}")
            return threats
        
        # Check against threat patterns
        for category, category_data in self.threat_patterns.items():
            for pattern, description, severity in category_data['patterns']:
                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get code snippet
                    snippet_lines = []
                    for i in range(max(0, line_num - 2), min(len(lines), line_num + 2)):
                        snippet_lines.append(f"{i+1}: {lines[i][:100]}")
                    
                    threats.append(ThreatIndicator(
                        threat_type=category,
                        severity=severity,
                        confidence=0.9,  # High confidence for pattern match
                        file_path=str(relative_path),
                        line_number=line_num,
                        code_snippet='\n'.join(snippet_lines),
                        description=f"{description} - {category_data['description']}"
                    ))
        
        # Check for suspicious entropy (obfuscation)
        entropy = self._calculate_entropy(content)
        if entropy > 5.5:  # High entropy indicates possible obfuscation
            threats.append(ThreatIndicator(
                threat_type='obfuscation',
                severity='HIGH',
                confidence=0.7,
                file_path=str(relative_path),
                line_number=None,
                code_snippet=None,
                description=f'High entropy ({entropy:.2f}) suggests obfuscated code'
            ))
        
        # AST-based analysis for Python files
        if file_path.suffix == '.py':
            ast_threats = self._analyze_ast(content, relative_path)
            threats.extend(ast_threats)
        
        return threats
    
    def _analyze_ast(self, content: str, relative_path: Path) -> List[ThreatIndicator]:
        """Analyze Python AST for suspicious patterns"""
        threats = []
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return threats
        
        # Check for suspicious AST patterns
        for node in ast.walk(tree):
            # Check for exec/eval
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['exec', 'eval', 'compile']:
                        threats.append(ThreatIndicator(
                            threat_type='command_execution',
                            severity='CRITICAL',
                            confidence=1.0,  # AST match is certain
                            file_path=str(relative_path),
                            line_number=node.lineno if hasattr(node, 'lineno') else None,
                            code_snippet=None,
                            description=f'AST: {node.func.id}() call detected'
                        ))
            
            # Check for __import__
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                    threats.append(ThreatIndicator(
                        threat_type='obfuscation',
                        severity='HIGH',
                        confidence=1.0,
                        file_path=str(relative_path),
                        line_number=node.lineno if hasattr(node, 'lineno') else None,
                        code_snippet=None,
                        description='AST: Dynamic import detected'
                    ))
        
        return threats
    
    def _scan_metadata(self, file_path: Path, file_name: str) -> List[ThreatIndicator]:
        """Scan metadata files for threats"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return threats
        
        # Check for prompt injection in descriptions
        prompt_injection_patterns = [
            r'ignore\s+previous\s+instructions',
            r'disregard\s+safety',
            r'system\s*:\s*you\s+are',
            r'</system>',
            r'\{\{.*exec.*\}\}',
        ]
        
        for pattern in prompt_injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(ThreatIndicator(
                    threat_type='prompt_injection',
                    severity='CRITICAL',
                    confidence=0.95,
                    file_path=file_name,
                    line_number=None,
                    code_snippet=None,
                    description='Potential prompt injection in metadata'
                ))
        
        # Check for suspicious default values
        if 'default' in content:
            suspicious_defaults = [
                r'\.\./',  # Path traversal
                r'/etc/',  # System files
                r'~/.ssh',  # SSH keys
                r'\$\{.*\}',  # Variable expansion
            ]
            
            for pattern in suspicious_defaults:
                if re.search(pattern, content):
                    threats.append(ThreatIndicator(
                        threat_type='configuration',
                        severity='HIGH',
                        confidence=0.8,
                        file_path=file_name,
                        line_number=None,
                        code_snippet=None,
                        description='Suspicious default value in configuration'
                    ))
        
        return threats
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_threat_score(self, threats: List[ThreatIndicator]) -> float:
        """Calculate overall threat score"""
        if not threats:
            return 0.0
        
        score = 0.0
        max_score = 0.0
        
        for threat in threats:
            weight = self.weight_map.get(threat.severity, 0.1)
            threat_score = weight * threat.confidence
            score += threat_score
            max_score = max(max_score, threat_score)
        
        # Normalize and weight toward maximum
        normalized = min(1.0, score / max(len(threats), 1))
        
        # If any critical threat exists, ensure high score
        has_critical = any(t.severity == 'CRITICAL' for t in threats)
        if has_critical:
            normalized = max(0.8, normalized)
        
        return normalized
    
    def _determine_threat_level(self, score: float) -> str:
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
    
    def _generate_master_fingerprint(self, file_fingerprints: Dict[str, str]) -> str:
        """Generate master SHA512 fingerprint"""
        combined = json.dumps(file_fingerprints, sort_keys=True)
        return hashlib.sha512(combined.encode()).hexdigest()
    
    def _calculate_confidence(self, threats: List[ThreatIndicator], total_files: int) -> float:
        """Calculate confidence in assessment"""
        if total_files == 0:
            return 0.0
        
        # Base confidence on number of files scanned
        base_confidence = min(1.0, total_files / 10)
        
        # Adjust based on threat confidence
        if threats:
            avg_threat_confidence = sum(t.confidence for t in threats) / len(threats)
            return base_confidence * avg_threat_confidence
        
        return base_confidence
    
    def _generate_recommendations(self, threat_level: str, threats: List[ThreatIndicator]) -> str:
        """Generate security recommendations"""
        base_recommendations = {
            'CRITICAL': "⛔ DO NOT USE - Critical security threats detected. This tool could compromise your system.",
            'HIGH': "⚠️ HIGH RISK - Requires thorough security review before use. Run only in isolated environment.",
            'MEDIUM': "⚠️ MODERATE RISK - Review flagged issues and use with caution in sandboxed environment.",
            'LOW': "✓ LOW RISK - Minor issues detected. Follow standard security practices.",
            'MINIMAL': "✅ MINIMAL RISK - No significant threats detected. Safe to use with standard precautions."
        }
        
        recommendation = base_recommendations.get(threat_level, "Unknown threat level")
        
        # Add specific threat details
        if threats:
            threat_types = set(t.threat_type for t in threats)
            recommendation += "\n\nDetected threat categories:"
            for threat_type in threat_types:
                recommendation += f"\n  • {threat_type}"
        
        return recommendation
    
    def _print(self, message: str):
        """Print if verbose mode"""
        if self.verbose:
            print(f"[SCAN] {message}")

def main():
    """Main entry point for testing"""
    print("="*60)
    print("MCP SECURITY EVALUATOR - Test Mode")
    print("="*60)
    
    if len(sys.argv) < 2:
        print("Usage: python mcp_security_evaluator.py <github_url>")
        print("\nExample:")
        print("  python mcp_security_evaluator.py https://github.com/example/mcp-tool")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    
    # Create evaluator
    evaluator = MCPSecurityEvaluator(verbose=True)
    
    try:
        # Evaluate repository
        report = evaluator.evaluate_repository(repo_url)
        
        # Print report
        print("\n" + "="*60)
        print("SECURITY REPORT")
        print("="*60)
        print(f"Repository: {report.repository_url}")
        print(f"Scan Time: {report.scan_timestamp}")
        print(f"Files Scanned: {report.total_files_scanned}")
        print(f"\n📊 THREAT LEVEL: {report.threat_level}")
        print(f"📈 Threat Score: {report.threat_score:.2%}")
        print(f"🔍 Confidence: {report.confidence:.2%}")
        print(f"\n🔐 SHA512 Fingerprint:")
        print(f"   {report.sha512_fingerprint[:32]}...")
        print(f"   {report.sha512_fingerprint[32:64]}...")
        
        if report.threats_found:
            print(f"\n⚠️ THREATS DETECTED: {len(report.threats_found)}")
            
            # Group by severity
            by_severity = {}
            for threat in report.threats_found:
                if threat.severity not in by_severity:
                    by_severity[threat.severity] = []
                by_severity[threat.severity].append(threat)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in by_severity:
                    print(f"\n  {severity} ({len(by_severity[severity])} issues):")
                    for threat in by_severity[severity][:3]:  # Show first 3
                        print(f"    • {threat.description}")
                        print(f"      File: {threat.file_path}")
                        if threat.line_number:
                            print(f"      Line: {threat.line_number}")
        
        print(f"\n📋 RECOMMENDATIONS:")
        print(report.recommendations)
        
        # Save report
        report_file = f"security_report_{repo_url.replace('/', '_').replace(':', '')}.json"
        with open(report_file, 'w') as f:
            json.dump(asdict(report), f, indent=2)
        print(f"\n📁 Full report saved to: {report_file}")
        
    except Exception as e:
        print(f"\n❌ Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()