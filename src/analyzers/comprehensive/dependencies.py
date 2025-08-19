import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class DependencyVulnerabilityChecker:
    """Check for vulnerable dependencies (simple heuristic)."""

    def check(self, repo_path: Path) -> tuple[dict, list]:
        dependencies: dict[str, dict] = {}
        vulnerabilities: list[dict] = []

        # Collect pinned dependencies from common manifests
        py_reqs = self._parse_requirements(repo_path / "requirements.txt")
        npm_lock = self._parse_package_lock(repo_path / "package-lock.json")

        # Merge dependency lists for reporting
        for name, version in py_reqs:
            dependencies[f"pypi:{name}"] = {"ecosystem": "PyPI", "name": name, "version": version, "source": "requirements.txt"}
        for name, version in npm_lock:
            dependencies[f"npm:{name}"] = {"ecosystem": "npm", "name": name, "version": version, "source": "package-lock.json"}

        # Build OSV batch queries
        queries: list[dict[str, Any]] = []
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
    def _parse_requirements(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        if not path.exists():
            return deps
        with open(path, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Accept forms: pkg==1.2.3, pkg===1.2.3, pkg>=1.2.3, pkg<2.0, pkg<=, pkg>
                name_ver = re.split(r";|\s", line)[0]
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?|===)\s*([^#]+)$", name_ver)
                if m:
                    name, op, ver = m.group(1), m.group(2), m.group(3).strip()
                    ver = ver.split('#')[0].strip()
                    deps.append((name.strip(), ver if op in {"==", "==="} else f"{op}{ver}"))
                else:
                    m2 = re.match(r"^([A-Za-z0-9_.\-]+)$", name_ver)
                    if m2:
                        deps.append((m2.group(1), ""))
        return deps

    def _parse_package_lock(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
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
            def walk(dep_map: dict[str, Any]):
                for name, meta in dep_map.items():
                    version = meta.get("version")
                    if name and version:
                        deps.append((name, version))
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
            walk(data["dependencies"])
        return deps

    def parse_package_json(self, path: Path) -> list[tuple[str, str, bool]]:
        """Parse package.json dependencies and devDependencies.
        Returns list of (name, version, is_dev).
        """
        out: list[tuple[str, str, bool]] = []
        if not path.exists():
            return out
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return out
        for name, ver in (data.get("dependencies") or {}).items():
            out.append((name, ver, False))
        for name, ver in (data.get("devDependencies") or {}).items():
            out.append((name, ver, True))
        return out

    # ------------------------
    # OSV client
    # ------------------------
    def _osv_query_batch(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    def _normalize_osv_vuln(self, pkg: dict[str, Any], v: dict[str, Any]) -> dict[str, Any]:
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


