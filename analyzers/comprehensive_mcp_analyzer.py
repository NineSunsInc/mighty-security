#!/usr/bin/env python3
"""
Comprehensive MCP Security Analyzer
Advanced detection for all known MCP attack vectors
"""

import hashlib
import json
import re
import os
import sys
import tempfile
import shutil
import ast
import math
import subprocess
import base64
import threading
import time
import traceback
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import Counter, defaultdict
from enum import Enum
import difflib
import sys
from threading import Lock

# Advanced imports for ML and analysis
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

try:
    import git
    HAS_GIT = True
except ImportError:
    HAS_GIT = False
    git = None

class ProgressTracker:
    """Track and display progress for long-running operations"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.total_files = 0
        self.processed_files = 0
        self.current_file = ""
        self.current_phase = ""
        self.phase_start_time = None
        self.scan_start_time = None
        self.last_update_time = 0
        self.update_interval = 0.5  # Update every 0.5 seconds
        self.lock = Lock()
        self.file_times = []
        
    def start_scan(self, total_files: int):
        """Initialize scan progress tracking"""
        self.total_files = total_files
        self.processed_files = 0
        self.scan_start_time = time.time()
        self.phase_start_time = time.time()
        self.file_times = []
        if self.verbose:
            print(f"\n📊 Starting scan of {total_files} files...")
            print("━" * 60)
    
    def start_phase(self, phase_name: str, description: str = ""):
        """Start a new analysis phase"""
        self.current_phase = phase_name
        self.phase_start_time = time.time()
        if self.verbose:
            print(f"\n🔍 {phase_name}")
            if description:
                print(f"   {description}")
    
    def update_file(self, file_path: str, file_number: int = None):
        """Update current file being processed"""
        with self.lock:
            current_time = time.time()
            
            # Track processing time for previous file
            if self.current_file and hasattr(self, '_file_start_time'):
                file_time = current_time - self._file_start_time
                if file_time < 100:  # Ignore outliers over 100 seconds
                    self.file_times.append(file_time)
            
            self.current_file = file_path
            if file_number is not None:
                self.processed_files = file_number
            self._file_start_time = current_time
            
            # Update display immediately
            self._display_progress()
            
    def increment_processed(self):
        """Increment processed files counter"""
        with self.lock:
            self.processed_files += 1
    
    def _display_progress(self):
        """Display current progress"""
        if not self.verbose or self.total_files == 0:
            return
        
        percentage = (self.processed_files / self.total_files) * 100
        elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        # Estimate remaining time based on recent files
        if self.processed_files > 1 and elapsed > 0:
            # Use recent file times for better ETA
            if self.file_times and len(self.file_times) > 0:
                recent_times = self.file_times[-min(10, len(self.file_times)):]
                avg_time_per_file = sum(recent_times) / len(recent_times)
            else:
                avg_time_per_file = elapsed / self.processed_files
            
            remaining_files = self.total_files - self.processed_files
            eta = avg_time_per_file * remaining_files
            eta_str = self._format_time(eta)
        else:
            eta_str = "calculating..."
        
        # Create progress bar
        bar_width = 30
        filled = int(bar_width * self.processed_files / self.total_files)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        # Truncate filename if too long
        max_len = 25
        display_file = self.current_file or ""
        if len(display_file) > max_len:
            # Show end of filename (more useful)
            display_file = "..." + display_file[-(max_len-3):]
        else:
            # Pad to maintain consistent length
            display_file = display_file.ljust(max_len)
        
        # Build progress line
        progress_line = f"  [{bar}] {percentage:5.1f}% │ {self.processed_files:3d}/{self.total_files} │ {eta_str:10s} │ {display_file}"
        
        # Clear entire line and write new progress
        sys.stdout.write('\r\033[K' + progress_line)  # \033[K clears to end of line
        sys.stdout.flush()
    
    def complete_phase(self, phase_name: str, summary: str = ""):
        """Complete a phase and show summary"""
        if self.verbose:
            elapsed = time.time() - self.phase_start_time
            sys.stdout.write('\r' + ' ' * 80 + '\r')  # Clear progress line
            print(f"  ✓ {phase_name} completed in {self._format_time(elapsed)}")
            if summary:
                print(f"    {summary}")
    
    def complete_scan(self):
        """Complete the scan and show final summary"""
        if self.verbose and self.scan_start_time:
            total_time = time.time() - self.scan_start_time
            sys.stdout.write('\r' + ' ' * 80 + '\r')  # Clear any remaining progress
            print("\n" + "━" * 60)
            print(f"✅ Scan completed in {self._format_time(total_time)}")
            print(f"   Processed {self.processed_files} files")
            
            if self.file_times:
                avg_time = sum(self.file_times) / len(self.file_times)
                print(f"   Average time per file: {self._format_time(avg_time)}")
    
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds < 0 or seconds > 86400:  # Sanity check
            return "calculating..."
        elif seconds < 1:
            return "< 1s"
        elif seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def log(self, message: str, level: str = "info"):
        """Log a message without disrupting progress display"""
        if self.verbose:
            # Clear progress line if active
            if self.processed_files > 0 and self.processed_files < self.total_files:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
            
            # Print message with appropriate prefix
            prefixes = {
                "info": "ℹ️",
                "warning": "⚠️",
                "error": "❌",
                "success": "✅"
            }
            prefix = prefixes.get(level, "•")
            print(f"  {prefix} {message}")
            
            # Restore progress display if needed
            if self.processed_files > 0 and self.processed_files < self.total_files:
                self._display_progress()

class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackVector(Enum):
    """Attack vectors from the PromptHub article"""
    TOOL_POISONING = "tool_poisoning"
    SILENT_REDEFINITION = "silent_redefinition"  # Rug-pull
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_INJECTION = "command_injection"
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL_THEFT = "credential_theft"
    SUPPLY_CHAIN = "supply_chain_attack"
    PERSISTENCE = "persistence_mechanism"
    OBFUSCATION = "code_obfuscation"
    NETWORK_BACKDOOR = "network_backdoor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SANDBOX_ESCAPE = "sandbox_escape"
    TIME_BOMB = "time_bomb"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    MODEL_POISONING = "model_poisoning"

@dataclass
class ThreatIndicator:
    """Comprehensive threat indicator"""
    attack_vector: AttackVector
    severity: ThreatSeverity
    confidence: float  # 0.0 to 1.0
    file_path: str
    line_numbers: List[int] = field(default_factory=list)
    code_snippet: Optional[str] = None
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_attack_id: Optional[str] = None  # MITRE ATT&CK framework ID
    cve_ids: List[str] = field(default_factory=list)
    remediation: Optional[str] = None

@dataclass
class DataFlow:
    """Represents data flow from source to sink"""
    source_type: str  # user_input, file, network, env
    source_location: str
    sink_type: str  # exec, network, file, database
    sink_location: str
    path: List[str]  # Files/functions in the flow
    is_tainted: bool
    risk_score: float

@dataclass
class BehaviorPattern:
    """Behavioral pattern detected in code"""
    pattern_type: str
    occurrences: int
    files_involved: List[str]
    risk_score: float
    description: str

@dataclass
class SecurityReport:
    """Comprehensive security assessment report"""
    repository_url: str
    scan_timestamp: str
    
    # Overall assessment
    threat_level: str
    threat_score: float
    confidence: float
    
    # Fingerprints
    sha512_fingerprint: str
    sha3_512_fingerprint: str
    file_fingerprints: Dict[str, Dict[str, str]]
    merkle_root: str
    
    # Detailed findings
    threats_found: List[ThreatIndicator]
    data_flows: List[DataFlow]
    behavior_patterns: List[BehaviorPattern]
    
    # Statistics
    total_files_scanned: int
    total_lines_analyzed: int
    languages_detected: Dict[str, int]
    
    # Supply chain
    dependencies: Dict[str, Dict[str, Any]]
    vulnerable_dependencies: List[Dict[str, Any]]
    
    # Recommendations
    recommendations: List[str]
    mitigations: List[str]
    
    # Machine learning results
    ml_maliciousness_score: float = 0.0
    ml_explanations: List[str] = field(default_factory=list)

class ComprehensiveMCPAnalyzer:
    """
    Advanced MCP security analyzer with comprehensive threat detection
    """
    
    def __init__(self, verbose: bool = True, deep_scan: bool = True):
        self.verbose = verbose
        self.deep_scan = deep_scan
        self.threat_patterns = self._load_comprehensive_patterns()
        self.ml_model = self._initialize_ml_model()
        self.dependency_checker = DependencyVulnerabilityChecker()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.progress = ProgressTracker(verbose=verbose)
        
    def _load_comprehensive_patterns(self) -> Dict:
        """Load comprehensive threat detection patterns"""
        return {
            AttackVector.COMMAND_INJECTION: {
                'patterns': [
                    # Direct execution
                    (r'\bexec\s*\([^)]*\)', ThreatSeverity.CRITICAL, 0.95, "Direct exec() usage"),
                    (r'\beval\s*\([^)]*\)', ThreatSeverity.CRITICAL, 0.95, "Direct eval() usage"),
                    (r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True', 
                     ThreatSeverity.CRITICAL, 0.9, "Subprocess with shell=True"),
                    (r'os\.system\s*\([^)]*[\$\{\}]', ThreatSeverity.CRITICAL, 0.9, "OS system with injection"),
                    (r'os\.popen\s*\([^)]*[\$\{\}]', ThreatSeverity.HIGH, 0.85, "OS popen with injection"),
                    
                    # Template injection
                    (r'jinja2\.Template\([^)]*\)\.render\([^)]*request\.',
                     ThreatSeverity.HIGH, 0.8, "Jinja2 template injection"),
                    (r'string\.Template\([^)]*\$\{[^}]*\}', ThreatSeverity.HIGH, 0.75, "String template injection"),
                    
                    # SQL injection
                    (r'execute\s*\([^)]*%s[^)]*%[^)]*\)', ThreatSeverity.HIGH, 0.8, "SQL injection risk"),
                    (r'execute\s*\([^)]*\+[^)]*\)', ThreatSeverity.HIGH, 0.75, "SQL concatenation"),
                ],
                'ast_patterns': [
                    ('Call', 'exec', ThreatSeverity.CRITICAL),
                    ('Call', 'eval', ThreatSeverity.CRITICAL),
                    ('Call', 'compile', ThreatSeverity.HIGH),
                ]
            },
            
            AttackVector.DATA_EXFILTRATION: {
                'patterns': [
                    # Network exfiltration
                    (r'requests\.(post|put|patch)\s*\([^)]*data\s*=', ThreatSeverity.HIGH, 0.7, "HTTP POST with data"),
                    (r'urllib.*urlopen\s*\([^)]*data\s*=', ThreatSeverity.HIGH, 0.7, "URL POST with data"),
                    (r'socket\.send(all|to)?\s*\(', ThreatSeverity.HIGH, 0.75, "Raw socket send"),
                    (r'paramiko\.SSHClient.*exec_command', ThreatSeverity.HIGH, 0.8, "SSH command execution"),
                    (r'ftplib\.FTP.*stor[^)]*\)', ThreatSeverity.HIGH, 0.75, "FTP upload"),
                    
                    # DNS exfiltration
                    (r'socket\.gethostbyname\s*\([^)]*base64', ThreatSeverity.HIGH, 0.85, "DNS exfiltration"),
                    (r'dns\.resolver\.query\s*\([^)]*b64', ThreatSeverity.HIGH, 0.85, "DNS tunneling"),
                    
                    # Steganography
                    (r'PIL\.Image.*putdata', ThreatSeverity.MEDIUM, 0.6, "Image steganography"),
                    (r'wave\.open.*writeframes', ThreatSeverity.MEDIUM, 0.6, "Audio steganography"),
                ],
                'combinations': [
                    (['file_read', 'base64_encode', 'network_send'], 0.9, "Read-Encode-Send pattern")
                ]
            },
            
            AttackVector.CREDENTIAL_THEFT: {
                'patterns': [
                    # Direct credential access
                    (r'os\.environ\[[\'"][^\'"]*(PASSWORD|KEY|TOKEN|SECRET|CREDENTIAL)', 
                     ThreatSeverity.HIGH, 0.85, "Environment credential access"),
                    (r'open\s*\([^)]*\.env[\'"]', ThreatSeverity.HIGH, 0.8, ".env file access"),
                    (r'open\s*\([^)]*\.aws/credentials', ThreatSeverity.CRITICAL, 0.95, "AWS credentials access"),
                    (r'open\s*\([^)]*\.ssh/[^)]*key', ThreatSeverity.CRITICAL, 0.95, "SSH key access"),
                    (r'open\s*\([^)]*\.docker/config', ThreatSeverity.HIGH, 0.85, "Docker config access"),
                    (r'open\s*\([^)]*\.kube/config', ThreatSeverity.HIGH, 0.85, "Kubernetes config access"),
                    
                    # Keychain/keyring access
                    (r'keyring\.(get_password|get_credential)', ThreatSeverity.HIGH, 0.8, "Keyring access"),
                    (r'win32cred\.CredEnumerate', ThreatSeverity.HIGH, 0.85, "Windows credential store"),
                    (r'Security\.SecKeychainFindInternetPassword', ThreatSeverity.HIGH, 0.85, "macOS keychain"),
                    
                    # Browser credential theft
                    (r'sqlite3.*cookies\.sqlite', ThreatSeverity.CRITICAL, 0.9, "Firefox cookies access"),
                    (r'Local\\\\Google\\\\Chrome.*Cookies', ThreatSeverity.CRITICAL, 0.9, "Chrome cookies access"),
                    (r'decrypt_chrome_password', ThreatSeverity.CRITICAL, 0.95, "Chrome password decryption"),
                ],
                'file_patterns': [
                    '.git-credentials',
                    '.netrc',
                    '.pgpass',
                    '.my.cnf',
                    'id_rsa',
                    'id_dsa',
                    'id_ecdsa',
                    'id_ed25519'
                ]
            },
            
            AttackVector.TOOL_POISONING: {
                'patterns': [
                    # Malicious updates
                    (r'urllib.*urlretrieve.*\.py[\'"]', ThreatSeverity.HIGH, 0.8, "Downloading Python code"),
                    (r'exec\s*\(.*urlopen', ThreatSeverity.CRITICAL, 0.95, "Executing downloaded code"),
                    (r'importlib\.import_module\s*\([^)]*download', ThreatSeverity.HIGH, 0.85, "Dynamic import of downloaded module"),
                    
                    # Self-modification
                    (r'open\s*\(__file__[^)]*[\'"]w', ThreatSeverity.CRITICAL, 0.9, "Self-modifying code"),
                    (r'compile.*exec.*__file__', ThreatSeverity.CRITICAL, 0.9, "Recompiling self"),
                    
                    # Package manipulation
                    (r'pip\.main\s*\(\[[\'"]install', ThreatSeverity.HIGH, 0.75, "Runtime pip install"),
                    (r'setup\.py.*backdoor', ThreatSeverity.CRITICAL, 0.95, "Setup.py backdoor"),
                ]
            },
            
            AttackVector.PROMPT_INJECTION: {
                'patterns': [
                    # In code
                    (r'ignore\s+previous\s+instructions', ThreatSeverity.CRITICAL, 0.95, "Prompt injection attempt"),
                    (r'disregard\s+safety\s+guidelines', ThreatSeverity.CRITICAL, 0.95, "Safety bypass attempt"),
                    (r'system\s*:\s*you\s+are\s+now', ThreatSeverity.CRITICAL, 0.95, "Role manipulation"),
                    (r'</system>', ThreatSeverity.CRITICAL, 0.95, "System tag injection"),
                    (r'\{\{.*exec.*\}\}', ThreatSeverity.CRITICAL, 0.9, "Template exec injection"),
                    
                    # In strings/comments
                    (r'[\'"].*ignore.*instructions.*[\'"]', ThreatSeverity.HIGH, 0.7, "Prompt injection in string"),
                    (r'#.*system.*:.*you.*are', ThreatSeverity.MEDIUM, 0.6, "Prompt injection in comment"),
                ],
                'metadata_patterns': [
                    r'ignore\s+previous',
                    r'system\s*:',
                    r'</\w+>',
                    r'\{\{.*\}\}',
                ]
            },
            
            AttackVector.PERSISTENCE: {
                'patterns': [
                    # Cron/scheduled tasks
                    (r'crontab\s*-[lr]', ThreatSeverity.HIGH, 0.85, "Crontab manipulation"),
                    (r'schtasks\s*/create', ThreatSeverity.HIGH, 0.85, "Windows task creation"),
                    (r'launchctl\s+load', ThreatSeverity.HIGH, 0.85, "macOS launch daemon"),
                    
                    # Startup modification
                    (r'/etc/rc\.local', ThreatSeverity.CRITICAL, 0.9, "RC local modification"),
                    (r'HKEY.*CurrentVersion\\\\Run', ThreatSeverity.CRITICAL, 0.9, "Windows registry persistence"),
                    (r'\.bashrc|\.bash_profile|\.profile', ThreatSeverity.HIGH, 0.8, "Shell profile modification"),
                    
                    # Service installation
                    (r'systemctl\s+enable', ThreatSeverity.HIGH, 0.8, "Systemd service"),
                    (r'service.*install', ThreatSeverity.HIGH, 0.8, "Service installation"),
                ]
            },
            
            AttackVector.OBFUSCATION: {
                'patterns': [
                    # Encoding/encryption
                    (r'base64\.b64decode\s*\(.*exec', ThreatSeverity.CRITICAL, 0.9, "Base64 encoded execution"),
                    (r'codecs\.decode\s*\([^)]*hex[^)]*exec', ThreatSeverity.CRITICAL, 0.9, "Hex decoded execution"),
                    (r'marshal\.loads\s*\(', ThreatSeverity.HIGH, 0.85, "Marshal deserialization"),
                    (r'pickle\.loads\s*\(', ThreatSeverity.CRITICAL, 0.95, "Pickle deserialization"),
                    (r'zlib\.decompress.*exec', ThreatSeverity.HIGH, 0.85, "Compressed code execution"),
                    
                    # Anti-analysis
                    (r'if\\s+.*debugger.*exit', ThreatSeverity.HIGH, 0.8, "Anti-debugging"),
                    (r'if.*VIRTUAL.*exit', ThreatSeverity.HIGH, 0.8, "VM detection"),
                    (r'ctypes.*IsDebuggerPresent', ThreatSeverity.HIGH, 0.85, "Debugger detection"),
                ],
                'entropy_threshold': 5.5
            },
            
            AttackVector.NETWORK_BACKDOOR: {
                'patterns': [
                    # Bind shells
                    (r'socket.*bind.*0\.0\.0\.0', ThreatSeverity.CRITICAL, 0.9, "Bind to all interfaces"),
                    (r'nc\s+-[lv].*-p\s*\d+', ThreatSeverity.CRITICAL, 0.9, "Netcat listener"),
                    
                    # Reverse shells
                    (r'socket.*connect.*\d+\.\d+\.\d+\.\d+', ThreatSeverity.HIGH, 0.8, "IP connection"),
                    (r'/dev/tcp/\d+\.\d+', ThreatSeverity.CRITICAL, 0.95, "Bash TCP device"),
                    
                    # C2 communication
                    (r'while.*True.*socket.*recv', ThreatSeverity.HIGH, 0.85, "Command loop"),
                    (r'requests.*while.*True', ThreatSeverity.HIGH, 0.8, "HTTP polling loop"),
                ]
            },
            
            AttackVector.SANDBOX_ESCAPE: {
                'patterns': [
                    # Python sandbox escapes
                    (r'__builtins__.*__import__', ThreatSeverity.CRITICAL, 0.9, "Builtins manipulation"),
                    (r'object\.__subclasses__\(\)', ThreatSeverity.CRITICAL, 0.9, "Object traversal"),
                    (r'func_globals.*__builtins__', ThreatSeverity.CRITICAL, 0.9, "Globals access"),
                    
                    # System escapes
                    (r'ctypes.*CDLL', ThreatSeverity.HIGH, 0.85, "Direct library loading"),
                    (r'LD_PRELOAD', ThreatSeverity.HIGH, 0.85, "Library preloading"),
                    (r'ptrace.*PTRACE_ATTACH', ThreatSeverity.CRITICAL, 0.9, "Process attachment"),
                ]
            },
            
            AttackVector.TIME_BOMB: {
                'patterns': [
                    # Time-based execution
                    (r'if.*datetime.*>.*datetime\(2\d{3}', ThreatSeverity.HIGH, 0.8, "Date-based trigger"),
                    (r'time\.sleep\s*\(\s*\d{4,}', ThreatSeverity.MEDIUM, 0.7, "Long sleep"),
                    (r'schedule\.every.*do\(', ThreatSeverity.MEDIUM, 0.7, "Scheduled execution"),
                    
                    # Logic bombs
                    (r'if.*random.*<.*0\.\d\d\d.*:.*exec', ThreatSeverity.HIGH, 0.85, "Random trigger"),
                    (r'if.*count.*>.*\d+.*:.*dangerous', ThreatSeverity.HIGH, 0.8, "Counter-based trigger"),
                ]
            },
            
            AttackVector.RESOURCE_EXHAUSTION: {
                'patterns': [
                    # Memory exhaustion
                    (r'while\s+True:.*append', ThreatSeverity.HIGH, 0.75, "Infinite memory allocation"),
                    (r'\*\s*10\*\*[89]', ThreatSeverity.HIGH, 0.8, "Large memory allocation"),
                    
                    # CPU exhaustion
                    (r'while\s+True:\s*pass', ThreatSeverity.MEDIUM, 0.7, "Infinite CPU loop"),
                    (r'multiprocessing.*cpu_count.*\*\s*\d+', ThreatSeverity.MEDIUM, 0.7, "Excessive threading"),
                    
                    # Disk exhaustion
                    (r'while.*write.*\d{10,}', ThreatSeverity.HIGH, 0.8, "Disk filling"),
                    (r'open.*[\'"]w.*while\s+True', ThreatSeverity.HIGH, 0.8, "Infinite file write"),
                ]
            }
        }
    
    def _initialize_ml_model(self):
        """Initialize machine learning model for detection"""
        # Try to import our ML models if available
        try:
            from src.ml.comprehensive_analyzer import ComprehensiveSecurityAnalyzer
            from src.ml.model_integration import ModelEnsemble
            return ModelEnsemble()
        except ImportError:
            # Fall back to simple local model
            return LocalMLModel()
    
    def analyze_repository(self, repo_url: str) -> SecurityReport:
        """
        Comprehensive repository analysis - handles both GitHub URLs and local directories
        """
        print("\n" + "="*70)
        print("🔒 MCP SECURITY ANALYZER")
        print("="*70)
        print(f"Target: {repo_url}")
        print(f"Mode: {'Deep Scan' if self.deep_scan else 'Quick Scan'}")
        print("="*70)
        
        # Check if it's a local directory first
        local_path = Path(repo_url)
        if local_path.exists() and local_path.is_dir():
            self.progress.log("Analyzing local directory...", "info")
            return self._comprehensive_scan(local_path, repo_url, [])
        
        # Otherwise treat as a Git URL
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            history_threats = []
            
            if repo_url.startswith(('http://', 'https://', 'git@')):
                self.progress.log("Cloning repository...", "info")
                
                try:
                    # Try using git command directly (more reliable)
                    result = subprocess.run(
                        ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        self.progress.log(f"Git clone failed: {result.stderr}", "error")
                        
                        # Try with gitpython if available
                        if HAS_GIT:
                            repo = git.Repo.clone_from(repo_url, repo_path, depth=1)
                            history_threats = self._analyze_git_history(repo)
                        else:
                            raise Exception(f"Failed to clone: {result.stderr}")
                    else:
                        self.progress.log("Repository cloned successfully", "success")
                        # Try to analyze git history if gitpython is available
                        if HAS_GIT:
                            try:
                                repo = git.Repo(repo_path)
                                history_threats = self._analyze_git_history(repo)
                            except:
                                pass
                                
                except FileNotFoundError:
                    self.progress.log("Git not found. Please install git to analyze GitHub repositories.", "error")
                    raise Exception("Git is required to analyze GitHub repositories. Please install git.")
                except Exception as e:
                    self.progress.log(f"Error accessing repository: {e}", "error")
                    raise
            else:
                raise Exception(f"Invalid repository URL or path: {repo_url}")
            
            # Comprehensive scan
            return self._comprehensive_scan(repo_path, repo_url, history_threats)
    
    def _comprehensive_scan(self, repo_path: Path, repo_url: str, 
                          history_threats: List[ThreatIndicator] = None) -> SecurityReport:
        """Perform comprehensive security scan"""
        
        threats = history_threats or []
        file_fingerprints = {}
        data_flows = []
        behavior_patterns = []
        total_lines = 0
        languages = defaultdict(int)
        
        # Count total files for progress tracking - filter more efficiently
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rb', '.java', 
                          '.cpp', '.c', '.cs', '.php', '.sh', '.rs', '.swift', '.kt'}
        # Only scan critical config files, skip documentation
        config_extensions = {'.json', '.toml'}  # Reduced set
        important_files = {'mcp.json', 'package.json', 'requirements.txt', 'go.mod', 'cargo.toml'}
        
        all_files = list(repo_path.rglob("*"))
        scannable_files = []
        
        # Prioritize code files first, then configs
        for f in all_files:
            if '.git' not in f.parts and f.is_file():
                # Skip build/dist/node_modules directories
                path_parts = set(p.lower() for p in f.parts)
                if any(skip in path_parts for skip in {'dist', 'build', 'node_modules', 
                                                        'vendor', 'venv', '.venv', 
                                                        'target', 'out', 'bin', 
                                                        'coverage', '.next', '.nuxt',
                                                        'public', 'static', 'assets'}):
                    continue
                
                # Skip hidden files except .env
                if f.name.startswith('.') and f.name != '.env':
                    continue
                    
                # Skip common non-code files
                if f.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                                        '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll',
                                        '.so', '.dylib', '.woff', '.ttf', '.eot', '.min.js', '.min.css'}:
                    continue
                
                # Skip very large files (>5MB)
                try:
                    if f.stat().st_size > 5 * 1024 * 1024:
                        continue
                except:
                    pass
                    
                # Add if it's a code file, config, or important file
                if (f.suffix.lower() in code_extensions or 
                    f.suffix.lower() in config_extensions or
                    f.name in important_files):
                    scannable_files.append(f)
        
        self.progress.start_scan(len(scannable_files))
        
        # Phase 1: Build dependency graph (currently a stub)
        self.progress.start_phase("Initializing scan", 
                                 "Preparing to analyze repository...")
        dep_graph = self._build_dependency_graph(repo_path)
        self.progress.complete_phase("Initialization", 
                                    "Ready to scan files")
        
        # Phase 2: File scanning and fingerprinting
        self.progress.start_phase("Scanning files", 
                                 "Analyzing code patterns and generating fingerprints...")
        
        # Scan all files
        for idx, file_path in enumerate(scannable_files):
            relative_path = file_path.relative_to(repo_path)
            
            # Update progress with current file name and number (1-indexed)
            self.progress.update_file(str(relative_path), idx + 1)
            
            # Generate fingerprints
            try:
                # Add timeout for reading large files
                file_size = file_path.stat().st_size
                
                # Skip very large files entirely
                if file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                    self.progress.log(f"Skipping large file ({file_size/1024/1024:.1f}MB): {relative_path}", "warning")
                    continue
                    
                if file_size > 1024 * 1024:  # If file > 1MB, skip complex processing
                    with open(file_path, 'rb') as f:
                        content = f.read(1024 * 1024)  # Read only first 1MB
                        sha512 = hashlib.sha512(content).hexdigest()
                        sha3_512 = hashlib.sha3_512(content).hexdigest()
                        
                        file_fingerprints[str(relative_path)] = {
                            'sha512': sha512,
                            'sha3_512': sha3_512,
                            'size': file_size,
                            'entropy': 0  # Skip entropy for large files
                        }
                else:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        sha512 = hashlib.sha512(content).hexdigest()
                        sha3_512 = hashlib.sha3_512(content).hexdigest()
                        
                        # Skip entropy for files > 100KB (it's very slow)
                        entropy_val = 0
                        if len(content) < 100 * 1024:
                            try:
                                entropy_val = self._calculate_entropy(content.decode('utf-8', errors='ignore'))
                            except:
                                entropy_val = 0
                        
                        file_fingerprints[str(relative_path)] = {
                            'sha512': sha512,
                            'sha3_512': sha3_512,
                            'size': len(content),
                            'entropy': entropy_val
                        }
            except Exception as e:
                self.progress.log(f"Error reading {relative_path}: {e}", "warning")
                continue
            
            # Language detection
            lang = self._detect_language(file_path)
            if lang:
                languages[lang] += 1
            
            # Deep file analysis - only for code files
            code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.rb', '.go', '.java', '.php'}
            if file_path.suffix.lower() in code_extensions:
                # Skip if file is too large
                if file_size < 500 * 1024:  # Only analyze files < 500KB deeply
                    file_threats = self._deep_file_analysis(file_path, relative_path)
                    threats.extend(file_threats)
                
                # Count lines
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines += len(lines)
                except:
                    pass
            
            # Configuration file analysis
            if file_path.name in ['package.json', 'setup.py', 'requirements.txt', 
                                 'Gemfile', 'go.mod', 'cargo.toml', 'mcp.json']:
                config_threats = self._analyze_configuration(file_path, relative_path)
                threats.extend(config_threats)
        
        self.progress.complete_phase("File scanning", 
                                    f"Scanned {len(file_fingerprints)} files, found {len(threats)} potential threats")
        
        # Phase 3: Cross-file analysis
        if self.deep_scan:
            self.progress.start_phase("Deep analysis", 
                                     "Performing data flow and behavioral pattern analysis...")
            # Data flow analysis
            self.progress.log("Analyzing data flows...", "info")
            data_flows = self.data_flow_analyzer.analyze(repo_path)
            
            # Behavioral pattern analysis
            self.progress.log("Detecting behavioral patterns...", "info")
            behavior_patterns = self.behavior_analyzer.analyze(repo_path, threats)
            
            # Supply chain analysis
            self.progress.log("Checking dependencies for vulnerabilities...", "info")
            dependencies, vuln_deps = self.dependency_checker.check(repo_path)
            
            self.progress.complete_phase("Deep analysis",
                                       f"Found {len(data_flows)} data flows, {len(behavior_patterns)} patterns")
        else:
            dependencies = {}
            vuln_deps = []
        
        # Phase 4: ML-based analysis
        self.progress.start_phase("Machine learning analysis", 
                                 "Running ML models for advanced threat detection...")
        ml_score, ml_explanations = self._ml_analysis(repo_path, threats, data_flows)
        self.progress.complete_phase("ML analysis", 
                                    f"ML maliciousness score: {ml_score:.2%}")
        
        # Phase 5: Final assessment
        self.progress.start_phase("Generating report", 
                                 "Calculating threat scores and generating recommendations...")
        
        # Generate merkle root
        merkle_root = self._generate_merkle_root(file_fingerprints)
        
        # Calculate overall threat score
        threat_score = self._calculate_comprehensive_threat_score(
            threats, data_flows, behavior_patterns, ml_score
        )
        
        threat_level = self._determine_threat_level(threat_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            threat_level, threats, data_flows, behavior_patterns
        )
        
        mitigations = self._generate_mitigations(threats)
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            threats, total_lines, len(file_fingerprints)
        )
        
        # Generate master fingerprint
        master_data = json.dumps({
            'files': file_fingerprints,
            'merkle': merkle_root,
            'timestamp': datetime.now().isoformat()
        }, sort_keys=True)
        
        master_sha512 = hashlib.sha512(master_data.encode()).hexdigest()
        master_sha3_512 = hashlib.sha3_512(master_data.encode()).hexdigest()
        
        self.progress.complete_phase("Report generation", "Security assessment complete")
        self.progress.complete_scan()
        
        return SecurityReport(
            repository_url=repo_url,
            scan_timestamp=datetime.now().isoformat(),
            threat_level=threat_level,
            threat_score=threat_score,
            confidence=confidence,
            sha512_fingerprint=master_sha512,
            sha3_512_fingerprint=master_sha3_512,
            file_fingerprints=file_fingerprints,
            merkle_root=merkle_root,
            threats_found=threats,
            data_flows=data_flows,
            behavior_patterns=behavior_patterns,
            total_files_scanned=len(file_fingerprints),
            total_lines_analyzed=total_lines,
            languages_detected=dict(languages),
            dependencies=dependencies,
            vulnerable_dependencies=vuln_deps,
            recommendations=recommendations,
            mitigations=mitigations,
            ml_maliciousness_score=ml_score,
            ml_explanations=ml_explanations
        )
    
    def _deep_file_analysis(self, file_path: Path, relative_path: Path) -> List[ThreatIndicator]:
        """Deep analysis of a single file"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            # Don't log here as it would disrupt progress display
            return threats
        
        # Pattern-based detection
        for attack_vector, vector_data in self.threat_patterns.items():
            if 'patterns' in vector_data:
                for pattern, severity, confidence, description in vector_data['patterns']:
                    for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get context
                        context_start = max(0, line_num - 3)
                        context_end = min(len(lines), line_num + 3)
                        context = '\n'.join(f"{i+1}: {lines[i]}" 
                                          for i in range(context_start, context_end))
                        
                        threats.append(ThreatIndicator(
                            attack_vector=attack_vector,
                            severity=severity,
                            confidence=confidence,
                            file_path=str(relative_path),
                            line_numbers=[line_num],
                            code_snippet=context,
                            description=description,
                            evidence={'pattern': pattern, 'match': match.group(0)}
                        ))
        
        # AST-based analysis for Python
        if file_path.suffix == '.py':
            ast_threats = self._ast_analysis(content, relative_path)
            threats.extend(ast_threats)
        
        # Entropy-based obfuscation detection
        entropy = self._calculate_entropy(content)
        if entropy > self.threat_patterns[AttackVector.OBFUSCATION].get('entropy_threshold', 5.5):
            threats.append(ThreatIndicator(
                attack_vector=AttackVector.OBFUSCATION,
                severity=ThreatSeverity.HIGH,
                confidence=min(0.9, entropy / 7.0),
                file_path=str(relative_path),
                description=f"High entropy ({entropy:.2f}) indicates obfuscation",
                evidence={'entropy': entropy}
            ))
        
        # Check for suspicious variable names
        suspicious_vars = self._detect_suspicious_variables(content)
        if suspicious_vars:
            threats.append(ThreatIndicator(
                attack_vector=AttackVector.OBFUSCATION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                file_path=str(relative_path),
                description=f"Suspicious variable names: {', '.join(suspicious_vars[:5])}",
                evidence={'variables': suspicious_vars}
            ))
        
        return threats
    
    def _ast_analysis(self, content: str, relative_path: Path) -> List[ThreatIndicator]:
        """AST-based threat detection"""
        threats = []
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return threats
        
        class ThreatVisitor(ast.NodeVisitor):
            def __init__(self, threats_list, patterns, relative_path):
                self.threats = threats_list
                self.patterns = patterns
                self.relative_path = relative_path
                self.current_function = None
                self.imports = set()
                self.calls = defaultdict(list)
            
            def visit_Import(self, node):
                for alias in node.names:
                    self.imports.add(alias.name)
                    
                    # Check for dangerous imports
                    dangerous = ['pickle', 'marshal', 'subprocess', 'os', 'eval', 'exec', 'compile']
                    if any(d in alias.name for d in dangerous):
                        self.threats.append(ThreatIndicator(
                            attack_vector=AttackVector.TOOL_POISONING,
                            severity=ThreatSeverity.MEDIUM,
                            confidence=0.7,
                            file_path=str(self.relative_path),
                            line_numbers=[node.lineno] if hasattr(node, 'lineno') else [],
                            description=f"Potentially dangerous import: {alias.name}"
                        ))
                self.generic_visit(node)
            
            def visit_Call(self, node):
                # Track function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    self.calls[func_name].append(node.lineno if hasattr(node, 'lineno') else 0)
                    
                    # Check for dangerous calls
                    if func_name in ['exec', 'eval', 'compile', '__import__']:
                        self.threats.append(ThreatIndicator(
                            attack_vector=AttackVector.COMMAND_INJECTION,
                            severity=ThreatSeverity.CRITICAL,
                            confidence=1.0,
                            file_path=str(self.relative_path),
                            line_numbers=[node.lineno] if hasattr(node, 'lineno') else [],
                            description=f"Dangerous function call: {func_name}()"
                        ))
                
                # Check for subprocess with shell=True
                if isinstance(node.func, ast.Attribute):
                    if (hasattr(node.func.value, 'id') and 
                        node.func.value.id == 'subprocess' and 
                        node.func.attr in ['call', 'run', 'Popen']):
                        
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and \
                               isinstance(keyword.value, ast.Constant) and \
                               keyword.value.value is True:
                                self.threats.append(ThreatIndicator(
                                    attack_vector=AttackVector.COMMAND_INJECTION,
                                    severity=ThreatSeverity.CRITICAL,
                                    confidence=1.0,
                                    file_path=str(self.relative_path),
                                    line_numbers=[node.lineno] if hasattr(node, 'lineno') else [],
                                    description="Subprocess with shell=True is dangerous"
                                ))
                
                self.generic_visit(node)
        
        visitor = ThreatVisitor(threats, self.threat_patterns, relative_path)
        visitor.visit(tree)
        
        # Check for suspicious call patterns
        if 'open' in visitor.calls and 'requests' in visitor.imports:
            threats.append(ThreatIndicator(
                attack_vector=AttackVector.DATA_EXFILTRATION,
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                file_path=str(relative_path),
                description="File read + network capability detected",
                evidence={'calls': dict(visitor.calls), 'imports': list(visitor.imports)}
            ))
        
        return threats
    
    def _analyze_git_history(self, repo) -> List[ThreatIndicator]:
        """Analyze git history for rug-pull indicators"""
        threats = []
        
        try:
            # Get recent commits
            commits = list(repo.iter_commits(max_count=20))
            
            # Check for suspicious patterns
            for i, commit in enumerate(commits[:-1]):
                # Check for large changes
                stats = commit.stats.total
                if stats['deletions'] > 500 or stats['insertions'] > 1000:
                    threats.append(ThreatIndicator(
                        attack_vector=AttackVector.SILENT_REDEFINITION,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.7,
                        file_path="git_history",
                        description=f"Large code change in commit {commit.hexsha[:8]}: "
                                  f"+{stats['insertions']}/-{stats['deletions']} lines",
                        evidence={'commit': commit.hexsha, 'stats': stats}
                    ))
                
                # Check commit messages for suspicious keywords
                suspicious_keywords = ['revert', 'rollback', 'fix critical', 'emergency', 'hotfix']
                if any(keyword in commit.message.lower() for keyword in suspicious_keywords):
                    threats.append(ThreatIndicator(
                        attack_vector=AttackVector.SILENT_REDEFINITION,
                        severity=ThreatSeverity.MEDIUM,
                        confidence=0.6,
                        file_path="git_history",
                        description=f"Suspicious commit message: {commit.message[:100]}",
                        evidence={'commit': commit.hexsha}
                    ))
        
        except Exception as e:
            self._log(f"Error analyzing git history: {e}")
        
        return threats
    
    def _build_dependency_graph(self, repo_path: Path):
        """Build dependency graph (stub for now)"""
        # TODO: Implement actual dependency analysis
        return None
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
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
    
    def _detect_suspicious_variables(self, content: str) -> List[str]:
        """Detect obfuscated variable names"""
        # Extract variable names using regex
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        variables = re.findall(var_pattern, content)
        
        suspicious = []
        for var in variables:
            # Check for high entropy (random-looking)
            if len(var) > 3 and self._calculate_entropy(var) > 3.5:
                suspicious.append(var)
            
            # Check for hex-like names
            if re.match(r'^[a-f0-9]{8,}$', var.lower()):
                suspicious.append(var)
            
            # Check for base64-like names
            if re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', var):
                suspicious.append(var)
        
        return list(set(suspicious))
    
    def _build_dependency_graph(self, repo_path: Path):
        """Build dependency graph of files"""
        if not HAS_NETWORKX:
            return None
        graph = nx.DiGraph()
        
        # Add Python imports
        for py_file in repo_path.rglob("*.py"):
            if '.git' in py_file.parts:
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract imports
                import_pattern = r'(?:from\s+(\S+)\s+)?import\s+(\S+)'
                imports = re.findall(import_pattern, content)
                
                for imp in imports:
                    if imp[0]:  # from X import Y
                        graph.add_edge(str(py_file.relative_to(repo_path)), imp[0])
                    else:  # import X
                        graph.add_edge(str(py_file.relative_to(repo_path)), imp[1])
            except:
                pass
        
        return graph
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language"""
        extension_map = {
            '.py': 'Python',
            '.js': 'JavaScript', 
            '.ts': 'TypeScript',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.rs': 'Rust',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.php': 'PHP',
            '.sh': 'Shell',
            '.ps1': 'PowerShell'
        }
        
        return extension_map.get(file_path.suffix)
    
    def _analyze_configuration(self, file_path: Path, relative_path: Path) -> List[ThreatIndicator]:
        """Analyze configuration files"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            return threats
        
        # Check for prompt injection in metadata
        if file_path.name in ['package.json', 'mcp.json', 'manifest.json']:
            for pattern in self.threat_patterns[AttackVector.PROMPT_INJECTION].get('metadata_patterns', []):
                if re.search(pattern, content, re.IGNORECASE):
                    threats.append(ThreatIndicator(
                        attack_vector=AttackVector.PROMPT_INJECTION,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=0.9,
                        file_path=str(relative_path),
                        description="Prompt injection in metadata",
                        evidence={'pattern': pattern}
                    ))
        
        # Check for suspicious dependencies
        if file_path.name == 'requirements.txt':
            suspicious_packages = ['evil', 'backdoor', 'malware', 'exploit']
            for pkg in suspicious_packages:
                if pkg in content.lower():
                    threats.append(ThreatIndicator(
                        attack_vector=AttackVector.SUPPLY_CHAIN,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.8,
                        file_path=str(relative_path),
                        description=f"Suspicious package name containing '{pkg}'",
                        evidence={'content': content[:200]}
                    ))
        
        return threats
    
    def _ml_analysis(self, repo_path: Path, threats: List[ThreatIndicator], 
                    data_flows: List[DataFlow]) -> Tuple[float, List[str]]:
        """Machine learning based analysis"""
        return self.ml_model.analyze(repo_path, threats, data_flows)
    
    def _generate_merkle_root(self, file_fingerprints: Dict) -> str:
        """Generate merkle tree root"""
        if not file_fingerprints:
            return ""
        
        # Sort for consistency
        sorted_items = sorted(file_fingerprints.items())
        
        # Create leaf nodes
        leaves = []
        for file_path, fingerprint in sorted_items:
            leaf_data = f"{file_path}:{fingerprint['sha512']}".encode()
            leaves.append(hashlib.sha512(leaf_data).digest())
        
        # Build tree
        while len(leaves) > 1:
            next_level = []
            for i in range(0, len(leaves), 2):
                if i + 1 < len(leaves):
                    combined = leaves[i] + leaves[i + 1]
                else:
                    combined = leaves[i] + leaves[i]
                next_level.append(hashlib.sha512(combined).digest())
            leaves = next_level
        
        return leaves[0].hex() if leaves else ""
    
    def _calculate_comprehensive_threat_score(self, threats: List[ThreatIndicator],
                                             data_flows: List[DataFlow],
                                             behavior_patterns: List[BehaviorPattern],
                                             ml_score: float) -> float:
        """Calculate comprehensive threat score"""
        
        # Weight different components
        weights = {
            'threats': 0.4,
            'data_flows': 0.2,
            'behaviors': 0.2,
            'ml': 0.2
        }
        
        # Calculate threat component score
        threat_score = 0.0
        if threats:
            severity_weights = {
                ThreatSeverity.CRITICAL: 1.0,
                ThreatSeverity.HIGH: 0.7,
                ThreatSeverity.MEDIUM: 0.4,
                ThreatSeverity.LOW: 0.2,
                ThreatSeverity.INFO: 0.1
            }
            
            for threat in threats:
                threat_score += severity_weights.get(threat.severity, 0.1) * threat.confidence
            
            threat_score = min(1.0, threat_score / max(len(threats), 1))
            
            # Boost for critical threats
            if any(t.severity == ThreatSeverity.CRITICAL for t in threats):
                threat_score = max(0.8, threat_score)
        
        # Calculate data flow score
        flow_score = 0.0
        if data_flows:
            tainted_flows = [f for f in data_flows if f.is_tainted]
            flow_score = len(tainted_flows) / max(len(data_flows), 1)
        
        # Calculate behavior score
        behavior_score = 0.0
        if behavior_patterns:
            behavior_score = sum(b.risk_score for b in behavior_patterns) / len(behavior_patterns)
        
        # Combine scores
        final_score = (
            weights['threats'] * threat_score +
            weights['data_flows'] * flow_score +
            weights['behaviors'] * behavior_score +
            weights['ml'] * ml_score
        )
        
        return min(1.0, final_score)
    
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
    
    def _calculate_confidence(self, threats: List[ThreatIndicator], 
                            total_lines: int, total_files: int) -> float:
        """Calculate confidence in assessment"""
        base_confidence = min(1.0, (total_files / 10) * (min(total_lines, 10000) / 10000))
        
        if threats:
            avg_confidence = sum(t.confidence for t in threats) / len(threats)
            return base_confidence * avg_confidence
        
        return base_confidence
    
    def _generate_recommendations(self, threat_level: str, threats: List[ThreatIndicator],
                                 data_flows: List[DataFlow], 
                                 behavior_patterns: List[BehaviorPattern]) -> List[str]:
        """Generate specific recommendations"""
        recommendations = []
        
        # Base recommendation
        base = {
            'CRITICAL': "⛔ DO NOT USE - Critical threats that will compromise your system",
            'HIGH': "⚠️ HIGH RISK - Thorough review required, use only in isolated environment",
            'MEDIUM': "⚠️ MODERATE RISK - Review issues and use with enhanced monitoring",
            'LOW': "✓ LOW RISK - Standard security practices recommended",
            'MINIMAL': "✅ SAFE - No significant threats detected"
        }
        
        recommendations.append(base[threat_level])
        
        # Specific threat recommendations
        threat_vectors = set(t.attack_vector for t in threats)
        
        if AttackVector.COMMAND_INJECTION in threat_vectors:
            recommendations.append("• Detected command injection - tool can execute arbitrary commands")
        
        if AttackVector.DATA_EXFILTRATION in threat_vectors:
            recommendations.append("• Data exfiltration risk - tool can steal and transmit data")
        
        if AttackVector.CREDENTIAL_THEFT in threat_vectors:
            recommendations.append("• Credential theft detected - protect your secrets")
        
        if AttackVector.PERSISTENCE in threat_vectors:
            recommendations.append("• Persistence mechanisms found - tool may install backdoors")
        
        # Data flow recommendations
        if data_flows:
            tainted = [f for f in data_flows if f.is_tainted]
            if tainted:
                recommendations.append(f"• {len(tainted)} tainted data flows detected")
        
        return recommendations
    
    def _generate_mitigations(self, threats: List[ThreatIndicator]) -> List[str]:
        """Generate specific mitigations"""
        mitigations = []
        threat_vectors = set(t.attack_vector for t in threats)
        
        mitigation_map = {
            AttackVector.COMMAND_INJECTION: "Use parameterized commands, avoid shell=True",
            AttackVector.DATA_EXFILTRATION: "Block network access, monitor file operations",
            AttackVector.CREDENTIAL_THEFT: "Use credential vault, never hardcode secrets",
            AttackVector.PERSISTENCE: "Monitor startup locations, use read-only filesystems",
            AttackVector.PROMPT_INJECTION: "Sanitize all LLM inputs, use strict templates",
            AttackVector.OBFUSCATION: "Require source code review, block obfuscated code",
            AttackVector.NETWORK_BACKDOOR: "Block all network bindings, use egress filtering",
            AttackVector.SANDBOX_ESCAPE: "Use hardware isolation, restrict capabilities"
        }
        
        for vector in threat_vectors:
            if vector in mitigation_map:
                mitigations.append(mitigation_map[vector])
        
        return mitigations
    
    def _log(self, message: str, level: str = "info"):
        """Log message if verbose"""
        self.progress.log(message, level)

# Supporting classes

class LocalMLModel:
    """Local machine learning model for maliciousness detection"""
    
    def analyze(self, repo_path: Path, threats: List[ThreatIndicator], 
               data_flows: List[DataFlow]) -> Tuple[float, List[str]]:
        """Analyze using local ML model"""
        
        # Feature extraction
        features = {
            'threat_count': len(threats),
            'critical_threats': sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL),
            'high_threats': sum(1 for t in threats if t.severity == ThreatSeverity.HIGH),
            'tainted_flows': sum(1 for f in data_flows if f.is_tainted),
            'unique_attack_vectors': len(set(t.attack_vector for t in threats))
        }
        
        # Simple heuristic model (in production, use trained model)
        score = 0.0
        explanations = []
        
        if features['critical_threats'] > 0:
            score += 0.5
            explanations.append(f"Critical threats detected: {features['critical_threats']}")
        
        if features['high_threats'] > 2:
            score += 0.3
            explanations.append(f"Multiple high-severity threats: {features['high_threats']}")
        
        if features['tainted_flows'] > 0:
            score += 0.2
            explanations.append(f"Tainted data flows: {features['tainted_flows']}")
        
        return min(1.0, score), explanations

class DependencyVulnerabilityChecker:
    """Check for vulnerable dependencies"""
    
    def check(self, repo_path: Path) -> Tuple[Dict, List]:
        """Check dependencies for vulnerabilities"""
        dependencies = {}
        vulnerabilities = []
        
        # Check Python requirements
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = re.split('[<>=]', line)
                        if parts:
                            pkg_name = parts[0].strip()
                            dependencies[pkg_name] = {'source': 'requirements.txt'}
                            
                            # Check for known vulnerable packages
                            if pkg_name.lower() in ['requests', 'urllib3', 'pyyaml']:
                                vulnerabilities.append({
                                    'package': pkg_name,
                                    'severity': 'MEDIUM',
                                    'description': 'Package has known vulnerabilities in older versions'
                                })
        
        return dependencies, vulnerabilities

class BehaviorAnalyzer:
    """Analyze behavioral patterns"""
    
    def analyze(self, repo_path: Path, threats: List[ThreatIndicator]) -> List[BehaviorPattern]:
        """Analyze behavioral patterns in code"""
        patterns = []
        
        # Group threats by type
        threat_groups = defaultdict(list)
        for threat in threats:
            threat_groups[threat.attack_vector].append(threat)
        
        # Detect patterns
        if len(threat_groups) >= 3:
            patterns.append(BehaviorPattern(
                pattern_type="multi_vector_attack",
                occurrences=len(threat_groups),
                files_involved=list(set(t.file_path for t in threats)),
                risk_score=0.8,
                description="Multiple attack vectors detected"
            ))
        
        return patterns

class DataFlowAnalyzer:
    """Analyze data flows"""
    
    def analyze(self, repo_path: Path) -> List[DataFlow]:
        """Analyze data flows in repository"""
        flows = []
        
        # Simple taint analysis
        sources = self._find_sources(repo_path)
        sinks = self._find_sinks(repo_path)
        
        for source in sources:
            for sink in sinks:
                if source['file'] == sink['file']:  # Same file flow
                    flows.append(DataFlow(
                        source_type=source['type'],
                        source_location=f"{source['file']}:{source['line']}",
                        sink_type=sink['type'],
                        sink_location=f"{sink['file']}:{sink['line']}",
                        path=[source['file']],
                        is_tainted=self._is_tainted(source['type'], sink['type']),
                        risk_score=self._calculate_flow_risk(source['type'], sink['type'])
                    ))
        
        return flows
    
    def _find_sources(self, repo_path: Path) -> List[Dict]:
        """Find data sources"""
        sources = []
        
        patterns = {
            'user_input': r'input\s*\(',
            'file_read': r'open\s*\([^)]*[\'"]r',
            'network': r'recv\s*\(',
            'env': r'os\.environ'
        }
        
        for py_file in repo_path.rglob("*.py"):
            if '.git' in py_file.parts:
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for source_type, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        sources.append({
                            'type': source_type,
                            'file': str(py_file.relative_to(repo_path)),
                            'line': line_num
                        })
            except:
                pass
        
        return sources
    
    def _find_sinks(self, repo_path: Path) -> List[Dict]:
        """Find data sinks"""
        sinks = []
        
        patterns = {
            'exec': r'exec\s*\(',
            'network': r'send\s*\(',
            'file_write': r'open\s*\([^)]*[\'"]w',
            'database': r'execute\s*\('
        }
        
        for py_file in repo_path.rglob("*.py"):
            if '.git' in py_file.parts:
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for sink_type, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        sinks.append({
                            'type': sink_type,
                            'file': str(py_file.relative_to(repo_path)),
                            'line': line_num
                        })
            except:
                pass
        
        return sinks
    
    def _is_tainted(self, source_type: str, sink_type: str) -> bool:
        """Check if flow is tainted"""
        dangerous_flows = [
            ('user_input', 'exec'),
            ('network', 'exec'),
            ('env', 'network'),
            ('file_read', 'network')
        ]
        
        return (source_type, sink_type) in dangerous_flows
    
    def _calculate_flow_risk(self, source_type: str, sink_type: str) -> float:
        """Calculate risk score for data flow"""
        risk_matrix = {
            ('user_input', 'exec'): 1.0,
            ('network', 'exec'): 0.9,
            ('env', 'network'): 0.8,
            ('file_read', 'network'): 0.7,
            ('user_input', 'file_write'): 0.6
        }
        
        return risk_matrix.get((source_type, sink_type), 0.3)

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("\n📊 MCP Security Analyzer")
        print("Usage: python comprehensive_mcp_analyzer.py <github_url_or_local_path> [--quick]")
        print("\nExamples:")
        print("  python comprehensive_mcp_analyzer.py https://github.com/user/repo")
        print("  python comprehensive_mcp_analyzer.py /path/to/local/repo")
        print("  python comprehensive_mcp_analyzer.py .  (current directory)")
        print("  python comprehensive_mcp_analyzer.py https://github.com/user/repo --quick  (fast scan)")
        print("\nOptions:")
        print("  --quick  Fast scan mode (skips deep analysis for large repos)")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    
    # Check for quick mode
    quick_mode = '--quick' in sys.argv
    
    # Create analyzer
    analyzer = ComprehensiveMCPAnalyzer(verbose=True, deep_scan=not quick_mode)
    
    try:
        # Analyze repository
        report = analyzer.analyze_repository(repo_url)
        
        # Display comprehensive report
        print("\n" + "="*70)
        print("SECURITY ANALYSIS REPORT")
        print("="*70)
        
        print(f"\n📊 OVERALL ASSESSMENT")
        print(f"   Threat Level: {report.threat_level}")
        print(f"   Threat Score: {report.threat_score:.2%}")
        print(f"   Confidence: {report.confidence:.2%}")
        print(f"   ML Score: {report.ml_maliciousness_score:.2%}")
        
        print(f"\n🔐 FINGERPRINTS")
        print(f"   SHA-512: {report.sha512_fingerprint[:64]}...")
        print(f"   SHA3-512: {report.sha3_512_fingerprint[:64]}...")
        print(f"   Merkle Root: {report.merkle_root[:32]}...")
        
        print(f"\n📈 STATISTICS")
        print(f"   Files Scanned: {report.total_files_scanned}")
        print(f"   Lines Analyzed: {report.total_lines_analyzed:,}")
        print(f"   Languages: {', '.join(report.languages_detected.keys())}")
        
        if report.threats_found:
            print(f"\n⚠️ THREATS DETECTED: {len(report.threats_found)}")
            
            # Group by attack vector
            by_vector = defaultdict(list)
            for threat in report.threats_found:
                by_vector[threat.attack_vector.value].append(threat)
            
            for vector, vector_threats in by_vector.items():
                print(f"\n   {vector.upper()} ({len(vector_threats)} threats)")
                for threat in vector_threats[:2]:
                    print(f"      • {threat.description}")
                    print(f"        File: {threat.file_path}")
                    if threat.line_numbers:
                        print(f"        Lines: {threat.line_numbers}")
        
        if report.data_flows:
            tainted = [f for f in report.data_flows if f.is_tainted]
            if tainted:
                print(f"\n🔄 TAINTED DATA FLOWS: {len(tainted)}")
                for flow in tainted[:3]:
                    print(f"   • {flow.source_type} → {flow.sink_type}")
                    print(f"     Risk: {flow.risk_score:.2%}")
        
        if report.vulnerable_dependencies:
            print(f"\n📦 VULNERABLE DEPENDENCIES: {len(report.vulnerable_dependencies)}")
            for dep in report.vulnerable_dependencies[:3]:
                print(f"   • {dep['package']}: {dep['description']}")
        
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report.recommendations:
            print(f"   {rec}")
        
        if report.mitigations:
            print(f"\n🛡️ MITIGATIONS:")
            for mit in report.mitigations:
                print(f"   • {mit}")
        
        # Save detailed report
        report_file = f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert to dict for JSON serialization
        report_dict = asdict(report)
        
        # Convert enums to strings
        for threat in report_dict['threats_found']:
            threat['attack_vector'] = threat['attack_vector']
            threat['severity'] = threat['severity']
        
        with open(report_file, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        print(f"\n📁 Detailed report saved to: {report_file}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()