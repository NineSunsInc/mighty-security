"""Composable components for the Comprehensive MCP Analyzer."""

from .behavior import BehaviorAnalyzer
from .data_flow import DataFlowAnalyzer
from .dependencies import DependencyVulnerabilityChecker
from .ml import LocalMLModel
from .models import (
    AttackVector,
    BehaviorPattern,
    DataFlow,
    SecurityReport,
    ThreatIndicator,
    ThreatSeverity,
)
from .patterns import get_threat_patterns
from .progress import ProgressTracker

__all__ = [
    "ThreatSeverity",
    "AttackVector",
    "ThreatIndicator",
    "DataFlow",
    "BehaviorPattern",
    "SecurityReport",
    "ProgressTracker",
    "LocalMLModel",
    "DependencyVulnerabilityChecker",
    "BehaviorAnalyzer",
    "DataFlowAnalyzer",
    "get_threat_patterns",
]

def load_components():
    """Return a centralized bundle of analyzer components and patterns.

    This provides a single import surface when another module wants to
    construct the analyzer or access its building blocks.
    """
    return {
        "models": {
            "ThreatSeverity": ThreatSeverity,
            "AttackVector": AttackVector,
            "ThreatIndicator": ThreatIndicator,
            "DataFlow": DataFlow,
            "BehaviorPattern": BehaviorPattern,
            "SecurityReport": SecurityReport,
        },
        "ProgressTracker": ProgressTracker,
        "LocalMLModel": LocalMLModel,
        "DependencyVulnerabilityChecker": DependencyVulnerabilityChecker,
        "BehaviorAnalyzer": BehaviorAnalyzer,
        "DataFlowAnalyzer": DataFlowAnalyzer,
        "threat_patterns": get_threat_patterns(),
    }


