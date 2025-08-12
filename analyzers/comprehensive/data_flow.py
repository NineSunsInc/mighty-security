import re
from pathlib import Path
from typing import Dict, List

from .models import DataFlow


class DataFlowAnalyzer:
    """Analyze simple data flows within a repository (single-file heuristic)."""

    def analyze(self, repo_path: Path) -> List[DataFlow]:
        flows: List[DataFlow] = []
        sources = self._find_sources(repo_path)
        sinks = self._find_sinks(repo_path)
        for source in sources:
            for sink in sinks:
                if source["file"] == sink["file"]:
                    flows.append(
                        DataFlow(
                            source_type=source["type"],
                            source_location=f"{source['file']}:{source['line']}",
                            sink_type=sink["type"],
                            sink_location=f"{sink['file']}:{sink['line']}",
                            path=[source["file"]],
                            is_tainted=self._is_tainted(source["type"], sink["type"]),
                            risk_score=self._calculate_flow_risk(
                                source["type"], sink["type"]
                            ),
                        )
                    )
        return flows

    def _find_sources(self, repo_path: Path) -> List[Dict]:
        sources: List[Dict] = []
        patterns = {
            "user_input": r"input\s*\(",
            "file_read": r"open\s*\([^)]*[\'\"]r",
            "network": r"recv\s*\(",
            "env": r"os\.environ",
        }
        for py_file in repo_path.rglob("*.py"):
            if ".git" in py_file.parts:
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                for source_type, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        line_num = content[: match.start()].count("\n") + 1
                        sources.append(
                            {
                                "type": source_type,
                                "file": str(py_file.relative_to(repo_path)),
                                "line": line_num,
                            }
                        )
            except Exception:
                pass
        return sources

    def _find_sinks(self, repo_path: Path) -> List[Dict]:
        sinks: List[Dict] = []
        patterns = {
            "exec": r"exec\s*\(",
            "network": r"send\s*\(",
            "file_write": r"open\s*\([^)]*[\'\"]w",
            "database": r"execute\s*\(",
        }
        for py_file in repo_path.rglob("*.py"):
            if ".git" in py_file.parts:
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                for sink_type, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        line_num = content[: match.start()].count("\n") + 1
                        sinks.append(
                            {
                                "type": sink_type,
                                "file": str(py_file.relative_to(repo_path)),
                                "line": line_num,
                            }
                        )
            except Exception:
                pass
        return sinks

    def _is_tainted(self, source_type: str, sink_type: str) -> bool:
        dangerous_flows = [
            ("user_input", "exec"),
            ("network", "exec"),
            ("env", "network"),
            ("file_read", "network"),
        ]
        return (source_type, sink_type) in dangerous_flows

    def _calculate_flow_risk(self, source_type: str, sink_type: str) -> float:
        risk_matrix = {
            ("user_input", "exec"): 1.0,
            ("network", "exec"): 0.9,
            ("env", "network"): 0.8,
            ("file_read", "network"): 0.7,
            ("user_input", "file_write"): 0.6,
        }
        return risk_matrix.get((source_type, sink_type), 0.3)


