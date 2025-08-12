#!/usr/bin/env python3
"""
Base LLM Analyzer Interface
Modular design for pluggable LLM providers
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import json
import re

class AnalysisType(Enum):
    """Types of LLM analysis"""
    DEEP_SCAN = "deep_scan"
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_FLOW = "data_flow"
    OBFUSCATION = "obfuscation"
    BEHAVIORAL = "behavioral"
    SUPPLY_CHAIN = "supply_chain"

@dataclass
class LLMRequest:
    """Request for LLM analysis"""
    file_path: str
    code_snippet: str
    analysis_type: AnalysisType
    context: Dict[str, Any] = field(default_factory=dict)
    priority: float = 0.5  # 0-1, higher = more important
    max_tokens: int = 2000
    
    def estimate_tokens(self) -> int:
        """Estimate token count (rough: 1 token ≈ 4 chars)"""
        return len(self.code_snippet) // 4 + 500  # +500 for prompt overhead

@dataclass
class LLMFinding:
    """Individual finding from LLM analysis"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    attack_vector: str
    description: str
    line_numbers: List[int] = field(default_factory=list)
    confidence: float = 0.0
    exploitation_scenario: str = ""
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LLMResponse:
    """Response from LLM analysis"""
    file_path: str
    analysis_type: AnalysisType
    findings: List[LLMFinding]
    risk_score: float  # 0-1
    summary: str
    tokens_used: int = 0
    analysis_time: float = 0.0
    
class BaseLLMAnalyzer(ABC):
    """Base class for LLM security analyzers"""
    
    def __init__(self, max_context_tokens: int = 8192):
        self.max_context_tokens = max_context_tokens
        self.total_tokens_used = 0
        
    @abstractmethod
    def analyze(self, request: LLMRequest) -> LLMResponse:
        """Analyze a single code snippet"""
        pass
    
    @abstractmethod
    def batch_analyze(self, requests: List[LLMRequest]) -> List[LLMResponse]:
        """Batch analysis for efficiency"""
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        pass
    
    def can_fit_request(self, request: LLMRequest) -> bool:
        """Check if request fits in context window"""
        return request.estimate_tokens() <= self.max_context_tokens

    # -------------------------
    # Shared utilities
    # -------------------------
    def _parse_json_response(self, response_text: str) -> Optional[Dict]:
        """Parse JSON from an LLM response with robust error handling.

        Supports fenced code blocks and attempts to repair common JSON issues
        (dangling commas, missing commas between objects/strings).
        """
        if not response_text:
            return None

        try:
            # Highest priority: sentinel markers
            if 'JSON_START' in response_text and 'JSON_END' in response_text:
                start = response_text.find('JSON_START') + len('JSON_START')
                end = response_text.find('JSON_END', start)
                json_str = response_text[start:end].strip() if end > start else ''
            # Prefer fenced JSON if present
            elif '```json' in response_text:
                json_start = response_text.find('```json') + 7
                json_end = response_text.find('```', json_start)
                json_str = response_text[json_start:json_end].strip()
            elif '```' in response_text:
                # Handle unlabeled code fences
                fence_start = response_text.find('```') + 3
                fence_end = response_text.find('```', fence_start)
                json_str = response_text[fence_start:fence_end].strip()
            elif '{' in response_text or '[' in response_text:
                # Find first JSON-like start and last end
                start_brace = response_text.find('{')
                start_bracket = response_text.find('[')

                if start_brace == -1:
                    json_start = start_bracket
                elif start_bracket == -1:
                    json_start = start_brace
                else:
                    json_start = min(start_brace, start_bracket)

                if json_start == -1:
                    return None

                if response_text[json_start] == '{':
                    json_end = response_text.rfind('}') + 1
                else:
                    json_end = response_text.rfind(']') + 1

                json_str = response_text[json_start:json_end]
            else:
                return None

            # Normalize unicode quotes
            json_str = json_str.replace('\u201c', '"').replace('\u201d', '"').replace('\u2019', "'")

            # Clean up common JSON issues before parsing
            # Remove trailing commas before closing brackets/braces
            json_str = re.sub(r',\s*([}\]])', r'\1', json_str)

            # Fix missing commas between string values
            json_str = re.sub(r'"\s*\n\s*"', '",\n"', json_str)

            # Fix missing commas between objects
            json_str = re.sub(r'}\s*\n\s*{', '},\n{', json_str)

            return json.loads(json_str)

        except json.JSONDecodeError:
            # One more attempt: extract largest balanced JSON object
            obj = self._extract_largest_json_object(response_text)
            if obj:
                try:
                    return json.loads(obj)
                except Exception:
                    return None
            return None
        except Exception:
            return None

    def _normalize_llm_response_dict(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and normalize a parsed LLM response into the expected schema.

        Ensures keys exist with correct types and coerces values where reasonable.
        """
        if not isinstance(data, dict):
            return None

        normalized: Dict[str, Any] = {}

        # Summary
        normalized['summary'] = str(data.get('summary', ''))

        # Risk score
        try:
            normalized['risk_score'] = float(data.get('risk_score', 0.0) or 0.0)
        except Exception:
            normalized['risk_score'] = 0.0

        # Findings
        findings_in = data.get('findings', [])
        if not isinstance(findings_in, list):
            findings_in = []

        allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        normalized_findings: List[Dict[str, Any]] = []
        for raw in findings_in:
            if not isinstance(raw, dict):
                continue
            severity_val = str(raw.get('severity', 'MEDIUM')).upper()
            severity = severity_val if severity_val in allowed_severities else 'MEDIUM'
            try:
                confidence = float(raw.get('confidence', 0.5) or 0.5)
            except Exception:
                confidence = 0.5
            line_numbers = raw.get('line_numbers', []) or []
            if not isinstance(line_numbers, list):
                line_numbers = []

            normalized_findings.append({
                'severity': severity,
                'attack_vector': raw.get('attack_vector', 'unknown') or 'unknown',
                'description': raw.get('description', '') or '',
                'line_numbers': line_numbers,
                'confidence': confidence,
                'exploitation_scenario': raw.get('exploitation_scenario', '') or '',
                'remediation': raw.get('remediation', '') or '',
                'evidence': raw.get('evidence', {}) or {},
            })

        normalized['findings'] = normalized_findings
        return normalized

    def _extract_largest_json_object(self, text: str) -> Optional[str]:
        """Extract the largest balanced {...} block as a fallback."""
        start = -1
        depth = 0
        best = None
        for i, ch in enumerate(text):
            if ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        candidate = text[start:i+1]
                        # quick sanity check
                        if 'findings' in candidate and 'risk_score' in candidate:
                            best = candidate
        return best

    def _sanitize_text_policy(self, text: str) -> str:
        """Remove suggestions to install/add external dependencies.

        We strip lines that recommend package installation or dependency changes
        (pip/npm/yarn/pnpm/poetry/conda/brew/apt/apk/go/cargo/gem/composer).
        """
        if not text:
            return text

        forbidden_install_patterns = [
            r'\bpip3?\s+install\b',
            r'\bnpm\s+install\b',
            r'\byarn\s+add\b',
            r'\bpnpm\s+add\b',
            r'\bpoetry\s+add\b',
            r'\bconda\s+install\b',
            r'\bbrew\s+install\b',
            r'\bapt(-get)?\s+install\b',
            r'\bapk\s+add\b',
            r'\bgo\s+get\b',
            r'\bcargo\s+add\b',
            r'\bgem\s+install\b',
            r'\bcomposer\s+require\b',
        ]

        lines = text.splitlines()
        cleaned_lines: List[str] = []
        for line in lines:
            if any(re.search(p, line, flags=re.IGNORECASE) for p in forbidden_install_patterns):
                continue
            cleaned_lines.append(line)
        cleaned = "\n".join(cleaned_lines)

        # Soft-reminder: if we removed anything, reinforce policy once
        if len(cleaned_lines) < len(lines):
            policy_note = (
                "Note: External dependency installation is not permitted in remediation. "
                "Provide code/config changes within the repository only."
            )
            if policy_note not in cleaned:
                cleaned = f"{cleaned}\n{policy_note}"

        return cleaned

    def _enforce_policy_on_findings(self, findings: List[LLMFinding]) -> List[LLMFinding]:
        """Apply remediation policy to all findings in-place and return them."""
        for finding in findings:
            finding.description = self._sanitize_text_policy(finding.description)
            finding.exploitation_scenario = self._sanitize_text_policy(finding.exploitation_scenario)
            finding.remediation = self._sanitize_text_policy(finding.remediation)
        return findings

    def sanitize_response(self, response: LLMResponse) -> LLMResponse:
        """Sanitize an LLMResponse to remove prohibited recommendations."""
        response.summary = self._sanitize_text_policy(response.summary)
        response.findings = self._enforce_policy_on_findings(response.findings)
        return response