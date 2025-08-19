from collections import defaultdict

from .models import BehaviorPattern, ThreatIndicator


class BehaviorAnalyzer:
    """Analyze behavioral patterns in code based on detected threats."""

    def analyze(self, repo_path, threats: list[ThreatIndicator]) -> list[BehaviorPattern]:
        patterns: list[BehaviorPattern] = []
        threat_groups = defaultdict(list)
        for threat in threats:
            threat_groups[threat.attack_vector].append(threat)
        if len(threat_groups) >= 3:
            patterns.append(
                BehaviorPattern(
                    pattern_type="multi_vector_attack",
                    occurrences=len(threat_groups),
                    files_involved=list(set(t.file_path for t in threats)),
                    risk_score=0.8,
                    description="Multiple attack vectors detected",
                )
            )
        return patterns


