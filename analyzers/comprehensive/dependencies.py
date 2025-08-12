import re
from pathlib import Path
from typing import Dict, List, Tuple


class DependencyVulnerabilityChecker:
    """Check for vulnerable dependencies (simple heuristic)."""

    def check(self, repo_path: Path) -> Tuple[Dict, List]:
        dependencies: Dict[str, Dict] = {}
        vulnerabilities: List[Dict] = []

        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            with open(req_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = re.split("[<>=]", line)
                        if parts:
                            pkg_name = parts[0].strip()
                            dependencies[pkg_name] = {"source": "requirements.txt"}
                            if pkg_name.lower() in ["requests", "urllib3", "pyyaml"]:
                                vulnerabilities.append(
                                    {
                                        "package": pkg_name,
                                        "severity": "MEDIUM",
                                        "description": "Package has known vulnerabilities in older versions",
                                    }
                                )

        return dependencies, vulnerabilities


