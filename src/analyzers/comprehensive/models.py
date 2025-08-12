from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackVector(Enum):
    TOOL_POISONING = "tool_poisoning"
    SILENT_REDEFINITION = "silent_redefinition"
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
    attack_vector: AttackVector
    severity: ThreatSeverity
    confidence: float
    file_path: str
    line_numbers: List[int] = field(default_factory=list)
    code_snippet: Optional[str] = None
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_attack_id: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    remediation: Optional[str] = None


@dataclass
class DataFlow:
    source_type: str
    source_location: str
    sink_type: str
    sink_location: str
    path: List[str]
    is_tainted: bool
    risk_score: float


@dataclass
class BehaviorPattern:
    pattern_type: str
    occurrences: int
    files_involved: List[str]
    risk_score: float
    description: str


@dataclass
class SecurityReport:
    repository_url: str
    scan_timestamp: str
    threat_level: str
    threat_score: float
    confidence: float
    sha512_fingerprint: str
    sha3_512_fingerprint: str
    file_fingerprints: Dict[str, Dict[str, str]]
    merkle_root: str
    threats_found: List[ThreatIndicator]
    data_flows: List[DataFlow]
    behavior_patterns: List[BehaviorPattern]
    total_files_scanned: int
    total_lines_analyzed: int
    languages_detected: Dict[str, int]
    dependencies: Dict[str, Dict[str, Any]]
    vulnerable_dependencies: List[Dict[str, Any]]
    recommendations: List[str]
    mitigations: List[str]
    ml_maliciousness_score: float = 0.0
    ml_explanations: List[str] = field(default_factory=list)
    llm_analysis: Dict[str, Any] = field(default_factory=dict)
    advanced_ml_analysis: Dict[str, Any] = field(default_factory=dict)
    combined_ai_assessment: Dict[str, Any] = field(default_factory=dict)


