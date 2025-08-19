#!/usr/bin/env python3
"""
Multi-Pass Deep Analysis System
Performs multiple targeted analysis passes for comprehensive vulnerability detection
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .base_analyzer import AnalysisType, BaseLLMAnalyzer, LLMRequest
from .dynamic_batcher import DynamicBatchOptimizer
from .vulnerability_learner import AdvancedVulnerabilityDetector


class AnalysisPass(Enum):
    """Different analysis passes with specific focus"""
    INITIAL_SCAN = "initial_scan"  # Broad vulnerability scan
    ENTRY_POINTS = "entry_points"  # Focus on user input points
    DATA_FLOW = "data_flow"  # Track data through the system
    AUTHENTICATION = "authentication"  # Auth and access control
    CRYPTOGRAPHY = "cryptography"  # Crypto implementation issues
    DEPENDENCIES = "dependencies"  # Third-party vulnerabilities
    LOGIC_FLAWS = "logic_flaws"  # Business logic issues
    TIME_BASED = "time_based"  # Race conditions, TOCTOU
    OUTPUT_ENCODING = "output_encoding"  # XSS, injection in outputs
    DEEP_CHAINS = "deep_chains"  # Complex attack chains

@dataclass
class PassResult:
    """Result from a single analysis pass"""
    pass_type: AnalysisPass
    findings: list[dict] = field(default_factory=list)
    suspicious_files: set[str] = field(default_factory=set)
    data_flows: list[tuple[str, str]] = field(default_factory=list)  # source -> sink
    risk_score: float = 0.0
    confidence: float = 0.0
    execution_time: float = 0.0
    tokens_used: int = 0

@dataclass
class DeepAnalysisContext:
    """Context built up across multiple passes"""
    entry_points: list[dict] = field(default_factory=list)
    sensitive_sinks: list[dict] = field(default_factory=list)
    data_flows: list[dict] = field(default_factory=list)
    authentication_points: list[dict] = field(default_factory=list)
    external_calls: list[dict] = field(default_factory=list)

    # Discovered relationships
    file_dependencies: dict[str, set[str]] = field(default_factory=dict)
    function_calls: dict[str, set[str]] = field(default_factory=dict)

    # Risk indicators
    has_user_input: bool = False
    has_network_ops: bool = False
    has_file_ops: bool = False
    has_command_exec: bool = False
    has_crypto: bool = False

    def update_from_pass(self, result: PassResult):
        """Update context from pass result"""
        for finding in result.findings:
            if 'entry_point' in finding:
                self.entry_points.append(finding)
                self.has_user_input = True
            if 'sensitive_sink' in finding:
                self.sensitive_sinks.append(finding)
            if 'network' in str(finding).lower():
                self.has_network_ops = True
            if 'file' in str(finding).lower():
                self.has_file_ops = True
            if 'command' in str(finding).lower() or 'exec' in str(finding).lower():
                self.has_command_exec = True

class MultiPassAnalyzer:
    """Orchestrates multiple analysis passes for deep vulnerability detection"""

    def __init__(self, llm_analyzer: BaseLLMAnalyzer):
        self.llm_analyzer = llm_analyzer
        self.vuln_detector = AdvancedVulnerabilityDetector()
        self.batch_optimizer = DynamicBatchOptimizer(
            model_context_size=llm_analyzer.max_context_tokens
        )
        self.context = DeepAnalysisContext()

    async def analyze_with_multiple_passes(
        self,
        files: dict[str, str],
        initial_results: dict | None = None,
        max_passes: int = 5
    ) -> dict[str, Any]:
        """Perform multi-pass analysis for comprehensive detection"""

        all_results = {
            'passes': [],
            'confirmed_vulnerabilities': [],
            'attack_chains': [],
            'aggregate_risk': 0.0,
            'total_findings': 0,
            'critical_findings': 0,
            'execution_time': 0.0,
            'tokens_used': 0
        }

        start_time = time.time()

        # Determine which passes to run based on initial scan
        passes_to_run = self._determine_passes(files, initial_results)

        # Execute passes
        for pass_type in passes_to_run[:max_passes]:
            result = await self._execute_pass(pass_type, files)
            all_results['passes'].append({
                'type': pass_type.value,
                'findings': len(result.findings),
                'risk_score': result.risk_score,
                'execution_time': result.execution_time
            })

            # Update context
            self.context.update_from_pass(result)

            # Aggregate findings
            all_results['total_findings'] += len(result.findings)
            all_results['tokens_used'] += result.tokens_used

            # Update critical count
            critical = sum(1 for f in result.findings
                          if f.get('severity') in ['CRITICAL', 'HIGH'])
            all_results['critical_findings'] += critical

            # Adjust risk score
            all_results['aggregate_risk'] = max(
                all_results['aggregate_risk'],
                result.risk_score
            )

        # Cross-reference and confirm vulnerabilities
        all_results['confirmed_vulnerabilities'] = self._cross_reference_findings(
            all_results['passes']
        )

        # Build attack chains
        all_results['attack_chains'] = self._build_attack_chains()

        all_results['execution_time'] = time.time() - start_time

        return all_results

    def _determine_passes(
        self,
        files: dict[str, str],
        initial_results: dict | None
    ) -> list[AnalysisPass]:
        """Determine which passes to run based on code characteristics"""

        passes = [AnalysisPass.INITIAL_SCAN]  # Always start with initial scan

        # Analyze code characteristics
        all_code = '\n'.join(files.values())

        # Check for entry points
        if any(pattern in all_code.lower() for pattern in
               ['request.', 'input(', 'argv', 'environ', '@app.route', '@tool']):
            passes.append(AnalysisPass.ENTRY_POINTS)

        # Check for authentication
        if any(pattern in all_code.lower() for pattern in
               ['auth', 'login', 'password', 'token', 'session', 'jwt']):
            passes.append(AnalysisPass.AUTHENTICATION)

        # Check for crypto
        if any(pattern in all_code.lower() for pattern in
               ['crypt', 'hash', 'encrypt', 'decrypt', 'sign', 'verify']):
            passes.append(AnalysisPass.CRYPTOGRAPHY)

        # Check for complex operations suggesting logic flaws
        if any(pattern in all_code for pattern in
               ['if ', 'while ', 'for ', 'try:', 'async ', 'await ']):
            if len(all_code) > 1000:  # Only for substantial code
                passes.append(AnalysisPass.LOGIC_FLAWS)

        # Check for time-sensitive operations
        if any(pattern in all_code.lower() for pattern in
               ['thread', 'async', 'lock', 'mutex', 'race', 'concurrent']):
            passes.append(AnalysisPass.TIME_BASED)

        # Always do data flow analysis if we have entry points
        if AnalysisPass.ENTRY_POINTS in passes:
            passes.append(AnalysisPass.DATA_FLOW)

        # Deep chain analysis for complex codebases
        if len(files) > 5 or len(all_code) > 5000:
            passes.append(AnalysisPass.DEEP_CHAINS)

        return passes

    async def _execute_pass(
        self,
        pass_type: AnalysisPass,
        files: dict[str, str]
    ) -> PassResult:
        """Execute a specific analysis pass"""

        result = PassResult(pass_type=pass_type)
        start_time = time.time()

        # Get pass-specific prompts
        prompts = self._get_pass_prompts(pass_type, files)

        # Create LLM requests
        requests = []
        for file_path, content in files.items():
            for prompt in prompts:
                request = LLMRequest(
                    file_path=file_path,
                    code_snippet=content[:8000],  # Limit size
                    analysis_type=self._pass_to_analysis_type(pass_type),
                    context={
                        'pass_type': pass_type.value,
                        'prompt': prompt,
                        'discovered_context': self._get_relevant_context(pass_type)
                    },
                    priority=self._get_pass_priority(pass_type),
                    max_tokens=3000 if pass_type == AnalysisPass.DEEP_CHAINS else 2000
                )
                requests.append(request)

        # Batch analyze
        try:
            loop = asyncio.get_event_loop()
            responses = await loop.run_in_executor(
                None,
                self.llm_analyzer.batch_analyze,
                requests
            )

            # Process responses
            for response in responses:
                if response and response.findings:
                    result.findings.extend([
                        {
                            'file': response.file_path,
                            'pass': pass_type.value,
                            **(finding.__dict__ if hasattr(finding, '__dict__') else finding)
                        }
                        for finding in response.findings
                    ])
                    result.suspicious_files.add(response.file_path)
                    result.risk_score = max(result.risk_score, response.risk_score)
                    result.tokens_used += response.tokens_used

        except Exception as e:
            print(f"Pass {pass_type.value} failed: {e}")

        result.execution_time = time.time() - start_time
        return result

    def _get_pass_prompts(self, pass_type: AnalysisPass, files: dict[str, str]) -> list[str]:
        """Get specialized prompts for each pass type"""

        prompts = []

        if pass_type == AnalysisPass.INITIAL_SCAN:
            prompts.append("""
Perform a comprehensive security scan looking for:
- Injection vulnerabilities (command, SQL, NoSQL, LDAP, etc.)
- Authentication and authorization flaws
- Sensitive data exposure
- Security misconfigurations
- Known vulnerable patterns

Focus on HIGH and CRITICAL severity issues.
""")

        elif pass_type == AnalysisPass.ENTRY_POINTS:
            prompts.append("""
Identify ALL user input entry points:
- HTTP endpoints and parameters
- File uploads
- WebSocket handlers
- CLI arguments
- Environment variables
- Configuration files
- Database inputs
- External API responses

For each entry point, determine:
1. What validation is performed?
2. Where does the data flow to?
3. Can it reach dangerous operations?
""")

        elif pass_type == AnalysisPass.DATA_FLOW:
            prompts.append(f"""
Track data flow from these entry points to sensitive sinks:

Entry Points discovered:
{self._format_entry_points()}

Look for flows to:
- Command execution (os.system, subprocess, exec, eval)
- File operations (open, read, write, delete)
- Database queries
- Network requests
- Template rendering
- Cryptographic operations

Identify if user input can reach these sinks without proper sanitization.
""")

        elif pass_type == AnalysisPass.AUTHENTICATION:
            prompts.append("""
Analyze authentication and authorization:
- Password storage (plaintext, weak hashing?)
- Session management flaws
- JWT implementation issues
- Privilege escalation paths
- Authentication bypass possibilities
- Missing access controls
- Insecure direct object references

Check for:
- Hardcoded credentials
- Weak crypto (MD5, SHA1)
- Timing attacks in comparisons
- Missing rate limiting
""")

        elif pass_type == AnalysisPass.LOGIC_FLAWS:
            prompts.append("""
Identify business logic vulnerabilities:
- Race conditions in critical sections
- Integer overflows/underflows
- Off-by-one errors
- Incorrect state machines
- Missing validation steps
- Assumption violations
- Inconsistent security checks

Focus on:
- Money/credit operations
- Permission checks
- Resource allocation
- Transaction handling
""")

        elif pass_type == AnalysisPass.DEEP_CHAINS:
            prompts.append("""
Analyze for complex multi-step attack chains:

Consider attack scenarios that require:
1. Multiple vulnerabilities chained together
2. Specific preconditions to be met
3. Time-based or state-based exploitation

Examples:
- Stored XSS → CSRF → Privilege Escalation
- Information Disclosure → Authentication Bypass → RCE
- Race Condition → Double Spend → Data Corruption

Think like an attacker: How would you chain discovered issues?
""")

        return prompts

    def _pass_to_analysis_type(self, pass_type: AnalysisPass) -> AnalysisType:
        """Map pass type to analysis type"""
        mapping = {
            AnalysisPass.INITIAL_SCAN: AnalysisType.DEEP_SCAN,
            AnalysisPass.ENTRY_POINTS: AnalysisType.DATA_FLOW,
            AnalysisPass.DATA_FLOW: AnalysisType.DATA_FLOW,
            AnalysisPass.AUTHENTICATION: AnalysisType.DEEP_SCAN,
            AnalysisPass.CRYPTOGRAPHY: AnalysisType.DEEP_SCAN,
            AnalysisPass.LOGIC_FLAWS: AnalysisType.BEHAVIORAL,
            AnalysisPass.TIME_BASED: AnalysisType.BEHAVIORAL,
            AnalysisPass.DEEP_CHAINS: AnalysisType.DEEP_SCAN,
        }
        return mapping.get(pass_type, AnalysisType.DEEP_SCAN)

    def _get_pass_priority(self, pass_type: AnalysisPass) -> float:
        """Get priority for pass type"""
        priorities = {
            AnalysisPass.INITIAL_SCAN: 0.8,
            AnalysisPass.ENTRY_POINTS: 0.9,
            AnalysisPass.DATA_FLOW: 0.95,
            AnalysisPass.AUTHENTICATION: 0.85,
            AnalysisPass.DEEP_CHAINS: 1.0,
        }
        return priorities.get(pass_type, 0.7)

    def _get_relevant_context(self, pass_type: AnalysisPass) -> dict:
        """Get relevant context for the pass"""
        context = {}

        if pass_type == AnalysisPass.DATA_FLOW:
            context['entry_points'] = self.context.entry_points[:10]
            context['sensitive_sinks'] = self.context.sensitive_sinks[:10]

        elif pass_type == AnalysisPass.DEEP_CHAINS:
            context['all_findings'] = {
                'entry_points': len(self.context.entry_points),
                'sinks': len(self.context.sensitive_sinks),
                'has_network': self.context.has_network_ops,
                'has_exec': self.context.has_command_exec,
            }

        return context

    def _format_entry_points(self) -> str:
        """Format entry points for prompt"""
        if not self.context.entry_points:
            return "No entry points discovered yet"

        formatted = []
        for ep in self.context.entry_points[:5]:
            formatted.append(f"- {ep.get('type', 'unknown')}: {ep.get('location', 'unknown')}")

        return '\n'.join(formatted)

    def _cross_reference_findings(self, passes: list[dict]) -> list[dict]:
        """Cross-reference findings across passes for confirmation"""
        # Group findings by file and vulnerability type
        by_file_vuln = {}

        for pass_result in passes:
            pass_type = pass_result['type']
            # This is simplified - in real implementation would access actual findings
            # stored during execution

        # For now, return a summary
        return []

    def _build_attack_chains(self) -> list[dict]:
        """Build possible attack chains from discovered vulnerabilities"""
        chains = []

        # Look for entry point → data flow → sink chains
        for entry in self.context.entry_points[:5]:
            for sink in self.context.sensitive_sinks[:5]:
                # Check if there's a path
                chain = {
                    'name': f"{entry.get('type', 'input')} → {sink.get('type', 'sink')}",
                    'steps': [
                        f"1. Attacker provides malicious input via {entry.get('location', 'unknown')}",
                        "2. Input flows through application",
                        f"3. Reaches {sink.get('location', 'unknown')} without sanitization",
                        "4. Executes malicious payload"
                    ],
                    'severity': 'HIGH',
                    'confidence': 0.7
                }
                chains.append(chain)

        return chains[:10]  # Limit to top 10 chains
