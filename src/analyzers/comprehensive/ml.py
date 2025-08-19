from pathlib import Path

from .models import DataFlow, ThreatIndicator, ThreatSeverity


class LocalMLModel:
    """Local machine learning model for maliciousness detection (heuristic)."""

    def analyze(
        self, repo_path: Path, threats: list[ThreatIndicator], data_flows: list[DataFlow]
    ) -> tuple[float, list[str]]:
        features = {
            "threat_count": len(threats),
            "critical_threats": sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL),
            "high_threats": sum(1 for t in threats if t.severity == ThreatSeverity.HIGH),
            "tainted_flows": sum(1 for f in data_flows if f.is_tainted),
            "unique_attack_vectors": len(set(t.attack_vector for t in threats)),
        }

        score = 0.0
        explanations: list[str] = []

        if features["critical_threats"] > 0:
            score += 0.5
            explanations.append(
                f"Critical threats detected: {features['critical_threats']}"
            )

        if features["high_threats"] > 2:
            score += 0.3
            explanations.append(
                f"Multiple high-severity threats: {features['high_threats']}"
            )

        if features["tainted_flows"] > 0:
            score += 0.2
            explanations.append(f"Tainted data flows: {features['tainted_flows']}")

        return min(1.0, score), explanations


