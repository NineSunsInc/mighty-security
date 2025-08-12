import re
from pathlib import Path
from typing import Dict, List, Tuple, Any
import json
import urllib.request
import urllib.error


class DependencyVulnerabilityChecker:
    """Check for vulnerable dependencies (simple heuristic)."""

    def check(self, repo_path: Path) -> Tuple[Dict, List]:
        dependencies: Dict[str, Dict] = {}
        vulnerabilities: List[Dict] = []

        # Collect pinned dependencies from common manifests
        py_reqs = self._parse_requirements(repo_path / "requirements.txt")
        npm_lock = self._parse_package_lock(repo_path / "package-lock.json")

        # Merge dependency lists for reporting
        for name, version in py_reqs:
            dependencies[f"pypi:{name}"] = {"ecosystem": "PyPI", "name": name, "version": version, "source": "requirements.txt"}
        for name, version in npm_lock:
            dependencies[f"npm:{name}"] = {"ecosystem": "npm", "name": name, "version": version, "source": "package-lock.json"}

        # Build OSV batch queries
        queries: List[Dict[str, Any]] = []
        for name, version in py_reqs:
            if version:
                queries.append({
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version
                })
        for name, version in npm_lock:
            if version:
                queries.append({
                    "package": {"name": name, "ecosystem": "npm"},
                    "version": version
                })

        if queries:
            osv_vulns = self._osv_query_batch(queries)
            for result in osv_vulns:
                pkg = result.get("package", {})
                vulns = result.get("vulns", [])
                for v in vulns:
                    vulnerabilities.append(self._normalize_osv_vuln(pkg, v))

        return dependencies, vulnerabilities

    # ------------------------
    # Parsers
    # ------------------------
    def _parse_requirements(self, path: Path) -> List[Tuple[str, str]]:
        deps: List[Tuple[str, str]] = []
        if not path.exists():
            return deps
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Accept forms: pkg==1.2.3, pkg===1.2.3, pkg>=1.2.3 (take pinned only), pkg==1.2.3 ; markers
                name_ver = re.split(r";|\s", line)[0]
                if "==" in name_ver:
                    name, version = name_ver.split("==", 1)
                    deps.append((name.strip(), version.strip()))
                elif "===" in name_ver:
                    name, version = name_ver.split("===", 1)
                    deps.append((name.strip(), version.strip()))
                else:
                    # Skip unpinned to avoid false matches
                    pass
        return deps

    def _parse_package_lock(self, path: Path) -> List[Tuple[str, str]]:
        deps: List[Tuple[str, str]] = []
        if not path.exists():
            return deps
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return deps
        # npm v7+ lockfile has "packages" with keys as paths; v6 uses "dependencies"
        if "packages" in data:
            for pkg_path, meta in data.get("packages", {}).items():
                name = meta.get("name")
                version = meta.get("version")
                if name and version:
                    deps.append((name, version))
        elif "dependencies" in data:
            def walk(dep_map: Dict[str, Any]):
                for name, meta in dep_map.items():
                    version = meta.get("version")
                    if name and version:
                        deps.append((name, version))
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
            walk(data["dependencies"])
        return deps

    # ------------------------
    # OSV client
    # ------------------------
    def _osv_query_batch(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Query OSV batch API. Returns list of {package, vulns} results.
        Uses only stdlib to avoid extra dependencies.
        """
        url = "https://api.osv.dev/v1/querybatch"
        body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                # Attach package metadata back to each result for normalization
                # The API returns results in the same order as queries
                for i, r in enumerate(results):
                    r["package"] = queries[i].get("package", {})
                return results
        except urllib.error.URLError:
            return []
        except Exception:
            return []

    def _normalize_osv_vuln(self, pkg: Dict[str, Any], v: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize OSV vulnerability to our internal structure."""
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        vuln_id = v.get("id")
        aliases = v.get("aliases", [])
        summary = v.get("summary") or v.get("details", "")[:200]
        severity = None
        for sev in v.get("severity", []):
            if sev.get("type", "").startswith("CVSS") and sev.get("score"):
                severity = sev["score"]
                break

        # Map to MCP-relevant if details mention certain classes
        details = (v.get("details") or "") + " " + (summary or "")
        mcp_relevant = bool(re.search(r"command\s+injection|ssrf|server[- ]side\s+request|path\s+traversal|deserializ|arbitrary\s+file|open\s+redirect|remote\s+code\s+execution", details, re.IGNORECASE))

        return {
            "package": f"{ecosystem}:{name}",
            "id": vuln_id,
            "aliases": aliases,
            "summary": summary,
            "severity": severity,
            "mcp_relevant": mcp_relevant,
            "references": v.get("references", []),
        }


