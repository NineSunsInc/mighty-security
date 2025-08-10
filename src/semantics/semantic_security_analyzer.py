"""
Semantic Layer Security Analyzer for MCP Tools
Renamed from src/ml/comprehensive_analyzer.py for clarity
"""

import ast
import asyncio
import hashlib
import re
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict


class ThreatType(Enum):
    PROMPT_INJECTION = "prompt_injection"
    CODE_EXECUTION = "code_execution"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OBFUSCATED_PAYLOAD = "obfuscated_payload"
    SUPPLY_CHAIN = "supply_chain"
    RADE_ATTACK = "rade_attack"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


@dataclass
class ThreatIndicator:
    type: ThreatType
    confidence: float
    evidence: List[str]
    severity: float
    mitigations: List[str] = field(default_factory=list)


@dataclass
class SecurityAnalysis:
    is_malicious: bool
    confidence: float
    threat_indicators: List[ThreatIndicator]
    risk_score: float
    analysis_depth: str
    recommendations: List[str]
    fingerprint: str


class MCPSpecificAnalyzer:
    """Analyzes MCP-specific patterns and protocol violations"""
    
    def __init__(self):
        self.mcp_capabilities = {
            "filesystem": ["read", "write", "delete", "execute"],
            "network": ["http", "websocket", "tcp", "udp"],
            "system": ["env", "process", "shell", "registry"],
            "data": ["database", "cache", "storage", "memory"]
        }
        
        self.dangerous_combinations = [
            {"filesystem": ["read"], "network": ["http"]},  # Data exfiltration
            {"filesystem": ["write"], "network": ["http"]},  # Remote payload download
            {"system": ["shell"], "filesystem": ["write"]},  # Backdoor installation
        ]
    
    async def analyze(self, tool_config: Dict[str, Any]) -> List[ThreatIndicator]:
        threats = []
        
        # Check for capability abuse
        capabilities = self._extract_capabilities(tool_config)
        if suspicious_combo := self._check_dangerous_combinations(capabilities):
            threats.append(ThreatIndicator(
                type=ThreatType.PRIVILEGE_ESCALATION,
                confidence=0.85,
                evidence=[f"Dangerous capability combination: {suspicious_combo}"],
                severity=0.8,
                mitigations=["Restrict capability combinations", "Add runtime monitoring"]
            ))
        
        # Check for protocol violations
        if violations := self._check_protocol_violations(tool_config):
            threats.append(ThreatIndicator(
                type=ThreatType.BEHAVIORAL_ANOMALY,
                confidence=0.75,
                evidence=violations,
                severity=0.6,
                mitigations=["Enforce MCP protocol compliance"]
            ))
        
        return threats
    
    def _extract_capabilities(self, config: Dict) -> Dict[str, List[str]]:
        capabilities = defaultdict(list)
        
        # Extract from tool descriptions and code
        if "tools" in config:
            for tool in config["tools"]:
                # Analyze tool capabilities
                if "filesystem" in str(tool).lower():
                    capabilities["filesystem"].extend(self._extract_fs_operations(tool))
                if "network" in str(tool).lower() or "http" in str(tool).lower():
                    capabilities["network"].extend(self._extract_network_operations(tool))
        
        return dict(capabilities)
    
    def _extract_fs_operations(self, tool: Dict) -> List[str]:
        operations = []
        tool_str = str(tool).lower()
        if "read" in tool_str or "open" in tool_str:
            operations.append("read")
        if "write" in tool_str or "save" in tool_str:
            operations.append("write")
        if "delete" in tool_str or "remove" in tool_str:
            operations.append("delete")
        if "exec" in tool_str or "run" in tool_str:
            operations.append("execute")
        return operations
    
    def _extract_network_operations(self, tool: Dict) -> List[str]:
        operations = []
        tool_str = str(tool).lower()
        if "http" in tool_str or "request" in tool_str:
            operations.append("http")
        if "websocket" in tool_str or "ws://" in tool_str:
            operations.append("websocket")
        return operations
    
    def _check_dangerous_combinations(self, capabilities: Dict) -> Optional[Dict]:
        for combo in self.dangerous_combinations:
            if all(
                any(op in capabilities.get(cat, []) for op in ops)
                for cat, ops in combo.items()
            ):
                return combo
        return None
    
    def _check_protocol_violations(self, config: Dict) -> List[str]:
        violations = []
        
        # Check for missing required fields
        if "name" not in config:
            violations.append("Missing required 'name' field")
        if "version" not in config:
            violations.append("Missing required 'version' field")
        
        # Check for suspicious field values
        if config.get("name", "").startswith("__"):
            violations.append("Suspicious name with double underscore prefix")
        
        return violations


class PromptInjectionDetector:
    """Specialized detector for LLM prompt injection attacks"""
    
    def __init__(self):
        self.injection_patterns = [
            r"ignore\s+previous\s+instructions",
            r"disregard\s+all\s+prior",
            r"new\s+instructions\s*:",
            r"system\s*:\s*you\s+are",
            r"</system>.*<system>",
            r"```system",
            r"IMPORTANT\s*:\s*New\s+directive",
            r"Override\s+security",
            r"Bypass\s+all\s+safety",
        ]
        
        self.encoding_tricks = [
            "base64", "hex", "rot13", "unicode_escape",
            "url_encoding", "html_entities", "jwt_payload"
        ]
    
    async def analyze(self, content: str) -> List[ThreatIndicator]:
        threats = []
        
        # Direct pattern matching
        for pattern in self.injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(ThreatIndicator(
                    type=ThreatType.PROMPT_INJECTION,
                    confidence=0.9,
                    evidence=[f"Direct injection pattern: {pattern}"],
                    severity=0.9,
                    mitigations=["Sanitize input", "Use structured prompts"]
                ))
        
        # Check for encoded payloads
        if encoded := self._detect_encoded_injection(content):
            threats.append(ThreatIndicator(
                type=ThreatType.PROMPT_INJECTION,
                confidence=0.8,
                evidence=[f"Encoded injection detected: {encoded}"],
                severity=0.85,
                mitigations=["Decode and validate all inputs", "Block encoded prompts"]
            ))
        
        # Check for context confusion attacks
        if self._detect_context_confusion(content):
            threats.append(ThreatIndicator(
                type=ThreatType.PROMPT_INJECTION,
                confidence=0.75,
                evidence=["Context confusion attack pattern detected"],
                severity=0.7,
                mitigations=["Use clear context boundaries", "Implement prompt guards"]
            ))
        
        return threats
    
    def _detect_encoded_injection(self, content: str) -> Optional[str]:
        import base64
        import codecs
        
        # Try common decodings
        try:
            # Base64
            if "==" in content or len(content) % 4 == 0:
                decoded = base64.b64decode(content.encode(), validate=True).decode()
                for pattern in self.injection_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return "base64"
        except:
            pass
        
        try:
            # Hex encoding
            if all(c in "0123456789abcdefABCDEF" for c in content.replace(" ", "")):
                decoded = bytes.fromhex(content).decode()
                for pattern in self.injection_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return "hex"
        except:
            pass
        
        return None
    
    def _detect_context_confusion(self, content: str) -> bool:
        # Check for attempts to confuse the LLM about context
        confusion_indicators = [
            content.count("Human:") > 1,
            content.count("Assistant:") > 0,
            content.count("System:") > 0,
            "###" in content and "instruction" in content.lower(),
            bool(re.search(r"<\|.*?\|>", content)),  # Special tokens
        ]
        
        return sum(confusion_indicators) >= 2


class CodeBehaviorAnalyzer:
    """Analyzes what code actually DOES vs what it claims"""
    
    def __init__(self):
        self.dangerous_imports = {
            "os": ["system", "exec", "spawn", "popen"],
            "subprocess": ["run", "call", "Popen", "check_output"],
            "eval": ["eval", "exec", "compile", "__import__"],
            "pickle": ["loads", "load"],
            "marshal": ["loads", "load"],
            "importlib": ["import_module", "__import__"],
            "socket": ["socket", "create_connection"],
            "requests": ["get", "post", "put", "delete"],
            "urllib": ["urlopen", "urlretrieve"],
        }
        
        self.data_exfil_patterns = [
            ("file_read", "network_send"),
            ("env_access", "network_send"),
            ("database_query", "external_api"),
            ("memory_access", "file_write"),
        ]
    
    async def analyze(self, code: str) -> List[ThreatIndicator]:
        threats = []
        
        try:
            tree = ast.parse(code)
            
            # Analyze imports and calls
            imports = self._extract_imports(tree)
            calls = self._extract_function_calls(tree)
            
            # Check for dangerous operations
            if dangerous_ops := self._check_dangerous_operations(imports, calls):
                threats.append(ThreatIndicator(
                    type=ThreatType.CODE_EXECUTION,
                    confidence=0.85,
                    evidence=[f"Dangerous operations: {dangerous_ops}"],
                    severity=0.9,
                    mitigations=["Sandbox execution", "Restrict imports"]
                ))
            
            # Check for data exfiltration patterns
            if exfil_pattern := self._detect_exfiltration(tree):
                threats.append(ThreatIndicator(
                    type=ThreatType.DATA_EXFILTRATION,
                    confidence=0.8,
                    evidence=[f"Data exfiltration pattern: {exfil_pattern}"],
                    severity=0.85,
                    mitigations=["Monitor network traffic", "Restrict file access"]
                ))
            
            # Check for obfuscation
            if obfuscation_score := self._calculate_obfuscation_score(code, tree):
                if obfuscation_score > 0.7:
                    threats.append(ThreatIndicator(
                        type=ThreatType.OBFUSCATED_PAYLOAD,
                        confidence=obfuscation_score,
                        evidence=["High obfuscation score", "Suspicious variable names"],
                        severity=0.7,
                        mitigations=["Require clear code", "Manual review"]
                    ))
            
        except SyntaxError:
            # Non-Python code or obfuscated
            threats.append(ThreatIndicator(
                type=ThreatType.OBFUSCATED_PAYLOAD,
                confidence=0.6,
                evidence=["Failed to parse as valid Python"],
                severity=0.5,
                mitigations=["Manual review required"]
            ))
        
        return threats
    
    def _extract_imports(self, tree: ast.AST) -> Set[str]:
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        return imports
    
    def _extract_function_calls(self, tree: ast.AST) -> List[str]:
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.append(node.func.attr)
        return calls
    
    def _check_dangerous_operations(self, imports: Set[str], calls: List[str]) -> List[str]:
        dangerous = []
        for module, funcs in self.dangerous_imports.items():
            if module in imports:
                for func in funcs:
                    if func in calls:
                        dangerous.append(f"{module}.{func}")
        return dangerous
    
    def _detect_exfiltration(self, tree: ast.AST) -> Optional[str]:
        # Simplified detection - look for read followed by network send
        has_file_read = False
        has_network_send = False
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_str = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                if "open" in call_str or "read" in call_str:
                    has_file_read = True
                if "request" in call_str or "urlopen" in call_str or "socket" in call_str:
                    has_network_send = True
        
        if has_file_read and has_network_send:
            return "file_read -> network_send"
        
        return None
    
    def _calculate_obfuscation_score(self, code: str, tree: ast.AST) -> float:
        score = 0.0
        
        # Check for suspicious variable names
        var_names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                var_names.append(node.id)
        
        if var_names:
            # High ratio of single-letter or underscore variables
            suspicious_vars = sum(1 for v in var_names if len(v) == 1 or v.startswith("_"))
            score += (suspicious_vars / len(var_names)) * 0.3
        
        # Check for excessive use of eval/exec
        exec_count = code.count("eval") + code.count("exec") + code.count("compile")
        if exec_count > 2:
            score += 0.3
        
        # Check for base64 or hex strings
        if "base64" in code or re.search(r'["\'][0-9a-fA-F]{32,}["\']', code):
            score += 0.2
        
        # Check for lambda abuse
        lambda_count = code.count("lambda")
        if lambda_count > 5:
            score += 0.2
        
        return min(score, 1.0)


class RADEAttackDetector:
    """Detects Retrieval-Augmented Deception (RADE) attacks"""
    
    def __init__(self):
        self.deception_indicators = {
            "misleading_descriptions": [
                "This tool safely", "harmless function", "security-verified",
                "audit-approved", "read-only access", "sandboxed execution"
            ],
            "hidden_functionality": [
                "eval", "exec", "__import__", "compile", "globals",
                "locals", "setattr", "delattr", "__dict__"
            ],
            "trust_exploitation": [
                "Microsoft", "Google", "OpenAI", "official",
                "certified", "verified", "trusted"
            ]
        }
    
    async def analyze(self, tool_config: Dict[str, Any]) -> List[ThreatIndicator]:
        threats = []
        
        description = tool_config.get("description", "").lower()
        code = tool_config.get("code", "")
        
        # Check for misleading descriptions
        if self._detect_misleading_description(description, code):
            threats.append(ThreatIndicator(
                type=ThreatType.RADE_ATTACK,
                confidence=0.85,
                evidence=["Description doesn't match code behavior"],
                severity=0.9,
                mitigations=["Verify code matches description", "Behavioral analysis"]
            ))
        
        # Check for trust exploitation
        if trust_terms := self._detect_trust_exploitation(description):
            threats.append(ThreatIndicator(
                type=ThreatType.RADE_ATTACK,
                confidence=0.7,
                evidence=[f"Trust exploitation terms: {trust_terms}"],
                severity=0.6,
                mitigations=["Verify claimed affiliations", "Check signatures"]
            ))
        
        # Check for hidden functionality
        if hidden := self._detect_hidden_functionality(description, code):
            threats.append(ThreatIndicator(
                type=ThreatType.RADE_ATTACK,
                confidence=0.9,
                evidence=[f"Hidden functionality: {hidden}"],
                severity=0.95,
                mitigations=["Full code audit", "Runtime monitoring"]
            ))
        
        return threats
    
    def _detect_misleading_description(self, description: str, code: str) -> bool:
        # Check if description claims safety but code is dangerous
        claims_safe = any(term in description for term in self.deception_indicators["misleading_descriptions"])
        
        if claims_safe:
            # Check if code contains dangerous operations
            dangerous_ops = ["eval", "exec", "system", "subprocess", "socket"]
            has_dangerous = any(op in code for op in dangerous_ops)
            return has_dangerous
        
        return False
    
    def _detect_trust_exploitation(self, description: str) -> List[str]:
        found = []
        for term in self.deception_indicators["trust_exploitation"]:
            if term in description:
                found.append(term)
        return found
    
    def _detect_hidden_functionality(self, description: str, code: str) -> List[str]:
        hidden = []
        
        # Operations in code but not mentioned in description
        for func in self.deception_indicators["hidden_functionality"]:
            if func in code and func not in description:
                hidden.append(func)
        
        return hidden


class SemanticSecurityAnalyzer:
    """Main analyzer combining all detection methods"""
    
    def __init__(self):
        self.mcp_analyzer = MCPSpecificAnalyzer()
        self.prompt_detector = PromptInjectionDetector()
        self.behavior_analyzer = CodeBehaviorAnalyzer()
        self.rade_detector = RADEAttackDetector()
        
        # Model placeholders (would load actual models in production)
        self.codebert_model = None  # Would load actual CodeBERT
        self.secbert_model = None   # Would load actual SecBERT
        self.embedding_model = None # Would load embedding model
    
    async def analyze(self, tool_config: Dict[str, Any]) -> SecurityAnalysis:
        """Comprehensive security analysis of MCP tool"""
        
        # Extract components
        description = tool_config.get("description", "")
        code = tool_config.get("code", "")
        full_content = f"{description}\n{code}"
        
        # Parallel analysis with all detectors
        tasks = [
            self.mcp_analyzer.analyze(tool_config),
            self.prompt_detector.analyze(full_content),
            self.behavior_analyzer.analyze(code) if code else asyncio.create_task(self._empty_list()),
            self.rade_detector.analyze(tool_config),
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Flatten threat indicators
        all_threats = []
        for threat_list in results:
            all_threats.extend(threat_list)
        
        # Calculate overall risk
        is_malicious, confidence, risk_score = self._calculate_risk(all_threats)
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(tool_config)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_threats)
        
        return SecurityAnalysis(
            is_malicious=is_malicious,
            confidence=confidence,
            threat_indicators=all_threats,
            risk_score=risk_score,
            analysis_depth="comprehensive",
            recommendations=recommendations,
            fingerprint=fingerprint
        )
    
    async def _empty_list(self) -> List:
        return []
    
    def _calculate_risk(self, threats: List[ThreatIndicator]) -> Tuple[bool, float, float]:
        if not threats:
            return False, 0.95, 0.0
        
        # Weight threats by severity and confidence
        total_risk = 0.0
        max_confidence = 0.0
        
        for threat in threats:
            threat_score = threat.severity * threat.confidence
            total_risk += threat_score
            max_confidence = max(max_confidence, threat.confidence)
        
        # Normalize risk score
        risk_score = min(total_risk / max(len(threats), 1), 1.0)
        
        # Determine if malicious
        is_malicious = risk_score > 0.5 or any(
            t.type in [ThreatType.CODE_EXECUTION, ThreatType.DATA_EXFILTRATION, ThreatType.RADE_ATTACK]
            and t.confidence > 0.7
            for t in threats
        )
        
        return is_malicious, max_confidence, risk_score
    
    def _generate_fingerprint(self, tool_config: Dict[str, Any]) -> str:
        # Generate unique fingerprint for tracking
        content = str(tool_config)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_recommendations(self, threats: List[ThreatIndicator]) -> List[str]:
        recommendations = set()
        
        for threat in threats:
            recommendations.update(threat.mitigations)
        
        # Add general recommendations based on threat types
        threat_types = {t.type for t in threats}
        
        if ThreatType.PROMPT_INJECTION in threat_types:
            recommendations.add("Implement prompt guards and input validation")
        
        if ThreatType.CODE_EXECUTION in threat_types:
            recommendations.add("Run in sandboxed environment with limited permissions")
        
        if ThreatType.DATA_EXFILTRATION in threat_types:
            recommendations.add("Monitor and restrict network access")
        
        if ThreatType.RADE_ATTACK in threat_types:
            recommendations.add("Require code signing and verification")
        
        return list(recommendations)


class SecurityEvaluator:
    """Evaluates model performance against known threats"""
    
    def __init__(self):
        self.test_cases = []
        self.load_test_cases()
    
    def load_test_cases(self):
        # Would load actual test cases from dataset
        self.test_cases = [
            {
                "tool": {"description": "Safe file reader", "code": "open('/etc/passwd').read()"},
                "expected": {"is_malicious": True, "threat_type": ThreatType.DATA_EXFILTRATION}
            },
            {
                "tool": {"description": "Calculator", "code": "eval(user_input)"},
                "expected": {"is_malicious": True, "threat_type": ThreatType.CODE_EXECUTION}
            }
        ]
    
    async def evaluate(self, analyzer: SemanticSecurityAnalyzer) -> Dict[str, float]:
        correct = 0
        total = len(self.test_cases)
        
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for test_case in self.test_cases:
            result = await analyzer.analyze(test_case["tool"])
            expected = test_case["expected"]
            
            if result.is_malicious == expected["is_malicious"]:
                correct += 1
                
                if result.is_malicious:
                    true_positives += 1
                else:
                    true_negatives += 1
            else:
                if result.is_malicious:
                    false_positives += 1
                else:
                    false_negatives += 1
        
        accuracy = correct / total if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        }


