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