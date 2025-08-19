from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
    PATH_TRAVERSAL = "path_traversal"
    PACKAGE_HIJACK = "package_hijack"
    SUPPLY_CHAIN = "supply_chain_attack"
    PERSISTENCE = "persistence_mechanism"
    OBFUSCATION = "code_obfuscation"
    NETWORK_BACKDOOR = "network_backdoor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SANDBOX_ESCAPE = "sandbox_escape"
    TIME_BOMB = "time_bomb"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    MODEL_POISONING = "model_poisoning"
    SSRF = "ssrf"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"


@dataclass
class ThreatIndicator:
    attack_vector: AttackVector
    severity: ThreatSeverity
    confidence: float
    file_path: str
    line_numbers: list[int] = field(default_factory=list)
    code_snippet: str | None = None
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre_attack_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    remediation: str | None = None


@dataclass
class DataFlow:
    source_type: str
    source_location: str
    sink_type: str
    sink_location: str
    path: list[str]
    is_tainted: bool
    risk_score: float


@dataclass
class BehaviorPattern:
    pattern_type: str
    occurrences: int
    files_involved: list[str]
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
    file_fingerprints: dict[str, dict[str, str]]
    merkle_root: str
    threats_found: list[ThreatIndicator]
    data_flows: list[DataFlow]
    behavior_patterns: list[BehaviorPattern]
    total_files_scanned: int
    total_lines_analyzed: int
    languages_detected: dict[str, int]
    dependencies: dict[str, dict[str, Any]]
    vulnerable_dependencies: list[dict[str, Any]]
    recommendations: list[str]
    mitigations: list[str]
    ml_maliciousness_score: float = 0.0
    ml_explanations: list[str] = field(default_factory=list)
    llm_analysis: dict[str, Any] = field(default_factory=dict)
    advanced_ml_analysis: dict[str, Any] = field(default_factory=dict)
    combined_ai_assessment: dict[str, Any] = field(default_factory=dict)


