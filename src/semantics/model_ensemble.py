"""
Security Model Ensemble (renamed from src/ml/model_integration.py)
Provides analyze(repo_path, threats, data_flows) compatible API
"""



class ModelEnsemble:
    """Ensemble wrapper that exposes analyze(repo_path, threats, data_flows)."""

    def __init__(self):
        # Lazy-load heavy deps from old module if available
        try:
            from src.ml.model_integration import ModelEnsemble as Legacy
            self._legacy = Legacy()
        except Exception:
            self._legacy = None

    def analyze(self, repo_path, threats, data_flows) -> tuple[float, list[str]]:
        """Return (ml_score, explanations) compatible with analyzer."""
        # Prefer legacy ensemble if available for richer signals
        if self._legacy and hasattr(self._legacy, "analyze_comprehensive"):
            try:
                # Minimal tool_config for legacy path
                # We aggregate threat descriptions as context
                threat_text = "\n".join(getattr(t, 'description', '') for t in threats)
                tool_config = {"description": threat_text, "code": ""}

                import asyncio
                result = asyncio.get_event_loop().run_until_complete(
                    self._legacy.analyze_comprehensive(tool_config)
                )
                score = float(result.get("threat_score", 0.5))
                return score, ["legacy_ensemble"]
            except Exception:
                pass

        # Fallback heuristic if no legacy ensemble
        critical = sum(1 for t in threats if getattr(t, 'severity', None) and t.severity.value == 'CRITICAL')
        high = sum(1 for t in threats if getattr(t, 'severity', None) and t.severity.value == 'HIGH')
        tainted = sum(1 for f in data_flows if getattr(f, 'is_tainted', False))

        score = 0.0
        if critical:
            score += 0.5
        if high > 1:
            score += 0.2
        if tainted:
            score += 0.2

        return min(1.0, score), ["heuristic_ensemble"]


