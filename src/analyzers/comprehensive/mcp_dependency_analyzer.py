"""
MCP Dependency Analyzer - Tracks MCP tool interactions and security risks
Focuses on: MCP tool relationships, risky patterns, handler security
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MCPToolInfo:
    """Information about an MCP tool/handler"""
    file_path: str
    tool_name: str | None
    imports_tools: list[str]  # Other tools it imports
    risky_operations: dict[str, bool]
    security_score: int  # 0-100, lower is riskier


@dataclass
class MCPDependencyGraph:
    """MCP-specific dependency information"""
    tools: dict[str, MCPToolInfo]
    tool_relationships: list[tuple]  # (tool_a, imports, tool_b)
    risky_imports: list[dict]
    security_concerns: list[dict]
    mcp_manifest: dict | None


class MCPDependencyAnalyzer:
    """
    Analyzes MCP-specific dependencies and relationships
    Focuses on security implications of tool interactions
    """

    # Dangerous operations for MCP tools
    RISKY_OPERATIONS = {
        'exec': 'Code injection risk',
        'eval': 'Code injection risk',
        'compile': 'Dynamic code risk',
        '__import__': 'Dynamic import risk',
        'subprocess': 'Command execution risk',
        'os.system': 'Command execution risk',
        'pickle.loads': 'Deserialization risk',
        'marshal.loads': 'Deserialization risk',
        'requests.get': 'External communication',
        'urllib.request': 'External communication',
        'open': 'File system access',
        'Path': 'File system access'
    }

    # MCP-specific patterns
    MCP_PATTERNS = {
        'tool_decorator': r'@tool\s*\(',
        'tool_class': r'class\s+\w*Tool\w*',
        'handler_func': r'def\s+handle\w*\s*\(',
        'mcp_import': r'from\s+mcp\s+import',
        'tool_import': r'from\s+\.?\w*tools?\w*\s+import'
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.tools = {}
        self.tool_relationships = []
        self.risky_imports = []
        self.security_concerns = []

    def analyze(self, repo_path: Path) -> MCPDependencyGraph:
        """
        Analyze MCP dependencies in repository
        
        Args:
            repo_path: Path to repository
            
        Returns:
            MCPDependencyGraph with analysis results
        """
        # Find all Python files that might be MCP tools
        tool_files = self._find_mcp_tools(repo_path)

        # Analyze each tool
        for tool_file in tool_files:
            self._analyze_tool_file(tool_file, repo_path)

        # Build tool relationships
        self._build_tool_relationships()

        # Check MCP manifest
        mcp_manifest = self._analyze_mcp_manifest(repo_path)

        # Calculate security scores
        self._calculate_security_scores()

        return MCPDependencyGraph(
            tools=self.tools,
            tool_relationships=self.tool_relationships,
            risky_imports=self.risky_imports,
            security_concerns=self.security_concerns,
            mcp_manifest=mcp_manifest
        )

    def _find_mcp_tools(self, repo_path: Path) -> list[Path]:
        """Find potential MCP tool files"""
        tool_files = []

        # Look for files that might be MCP tools
        patterns = ['*tool*.py', '*handler*.py', '*mcp*.py', '*server*.py']

        for pattern in patterns:
            for file_path in repo_path.rglob(pattern):
                if self._is_valid_file(file_path):
                    tool_files.append(file_path)

        # Also check for Python files with MCP patterns
        for py_file in repo_path.rglob('*.py'):
            if py_file not in tool_files and self._is_valid_file(py_file):
                try:
                    with open(py_file, encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)  # Check first 1KB

                        # Check for MCP patterns
                        for pattern_name, pattern in self.MCP_PATTERNS.items():
                            if re.search(pattern, content):
                                tool_files.append(py_file)
                                break
                except Exception:
                    continue

        return list(set(tool_files))  # Remove duplicates

    def _is_valid_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed"""
        excluded = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'test', 'tests'}
        return not any(part in excluded for part in file_path.parts)

    def _analyze_tool_file(self, file_path: Path, repo_path: Path) -> None:
        """Analyze a single MCP tool file"""
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                content = f.read()

            relative_path = str(file_path.relative_to(repo_path))

            # Extract tool name
            tool_name = self._extract_tool_name(content, file_path)

            # Check for risky operations
            risky_ops = self._check_risky_operations(content)

            # Find imports of other tools
            tool_imports = self._find_tool_imports(content, relative_path)

            # Create tool info
            tool_info = MCPToolInfo(
                file_path=relative_path,
                tool_name=tool_name,
                imports_tools=tool_imports,
                risky_operations=risky_ops,
                security_score=100  # Will be calculated later
            )

            self.tools[relative_path] = tool_info

            # Check for specific security concerns
            self._check_security_concerns(content, relative_path)

        except Exception as e:
            if self.verbose:
                logger.warning(f"Error analyzing {file_path}: {e}")

    def _extract_tool_name(self, content: str, file_path: Path) -> str | None:
        """Extract tool name from content or filename"""
        # Try to find @tool decorator with name
        tool_match = re.search(r'@tool\s*\(["\'](\w+)["\']', content)
        if tool_match:
            return tool_match.group(1)

        # Try class name
        class_match = re.search(r'class\s+(\w*Tool\w*)', content)
        if class_match:
            return class_match.group(1)

        # Fallback to filename
        return file_path.stem

    def _check_risky_operations(self, content: str) -> dict[str, bool]:
        """Check for risky operations in code"""
        risky_ops = {}

        for op, risk in self.RISKY_OPERATIONS.items():
            # Simple check - could be improved with AST parsing
            if op in content:
                risky_ops[op] = True

                # Add to risky imports list
                self.risky_imports.append({
                    'operation': op,
                    'risk': risk
                })

        return risky_ops

    def _find_tool_imports(self, content: str, current_file: str) -> list[str]:
        """Find imports of other tools"""
        tool_imports = []

        # Find import statements
        import_pattern = r'(?:from\s+([a-zA-Z0-9_.]+)\s+)?import\s+([a-zA-Z0-9_.,\s]+)'
        imports = re.findall(import_pattern, content)

        for imp in imports:
            module = imp[0] if imp[0] else imp[1]

            # Check if it's likely importing another tool
            if any(keyword in module.lower() for keyword in ['tool', 'handler', 'mcp']):
                tool_imports.append(module)

        return tool_imports

    def _check_security_concerns(self, content: str, file_path: str) -> None:
        """Check for specific security concerns"""
        # Check for exec/eval
        if 'exec(' in content or 'eval(' in content:
            self.security_concerns.append({
                'file': file_path,
                'issue': 'Uses exec/eval - high code injection risk',
                'severity': 'CRITICAL',
                'category': 'code_injection'
            })

        # Check for subprocess with shell=True
        if 'subprocess' in content and 'shell=True' in content:
            self.security_concerns.append({
                'file': file_path,
                'issue': 'Uses subprocess with shell=True - command injection risk',
                'severity': 'CRITICAL',
                'category': 'command_injection'
            })

        # Check for hardcoded secrets
        secret_patterns = [
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]

        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.security_concerns.append({
                    'file': file_path,
                    'issue': 'Possible hardcoded secrets',
                    'severity': 'HIGH',
                    'category': 'credential_exposure'
                })
                break

        # Check for unsafe deserialization
        if 'pickle.loads' in content or 'marshal.loads' in content:
            self.security_concerns.append({
                'file': file_path,
                'issue': 'Uses unsafe deserialization',
                'severity': 'HIGH',
                'category': 'unsafe_deserialization'
            })

    def _build_tool_relationships(self) -> None:
        """Build relationships between tools"""
        for file_path, tool_info in self.tools.items():
            for imported in tool_info.imports_tools:
                # Try to find the imported tool in our tools
                for other_path, other_tool in self.tools.items():
                    if other_path != file_path:
                        if imported in other_path or (other_tool.tool_name and imported in other_tool.tool_name):
                            self.tool_relationships.append((file_path, 'imports', other_path))

    def _analyze_mcp_manifest(self, repo_path: Path) -> dict | None:
        """Analyze MCP manifest file"""
        mcp_json = repo_path / "mcp.json"

        if not mcp_json.exists():
            return None

        try:
            import json
            with open(mcp_json) as f:
                manifest = json.load(f)

            # Extract relevant security information
            result = {
                'name': manifest.get('name', 'unknown'),
                'version': manifest.get('version', 'unknown'),
                'tools': [],
                'permissions': manifest.get('permissions', []),
                'security_issues': []
            }

            # Analyze tools
            for tool in manifest.get('tools', []):
                result['tools'].append({
                    'name': tool.get('name'),
                    'description': tool.get('description', '')[:100]  # First 100 chars
                })

            # Check for security issues
            if 'permissions' in manifest:
                perms = manifest['permissions']
                if isinstance(perms, list):
                    if '*' in perms or 'all' in perms:
                        result['security_issues'].append('Overly broad permissions requested')
                    if 'system' in perms or 'admin' in perms:
                        result['security_issues'].append('Elevated permissions requested')

            return result

        except Exception as e:
            if self.verbose:
                logger.warning(f"Error reading mcp.json: {e}")
            return None

    def _calculate_security_scores(self) -> None:
        """Calculate security scores for each tool"""
        for file_path, tool_info in self.tools.items():
            score = 100

            # Deduct for risky operations
            for op in tool_info.risky_operations:
                if 'exec' in op or 'eval' in op:
                    score -= 30
                elif 'subprocess' in op:
                    score -= 20
                elif 'pickle' in op or 'marshal' in op:
                    score -= 15
                else:
                    score -= 5

            # Deduct for security concerns
            for concern in self.security_concerns:
                if concern['file'] == file_path:
                    if concern['severity'] == 'CRITICAL':
                        score -= 25
                    elif concern['severity'] == 'HIGH':
                        score -= 15
                    else:
                        score -= 5

            tool_info.security_score = max(0, score)

    def get_summary(self, graph: MCPDependencyGraph) -> dict:
        """Get summary of analysis results"""
        total_tools = len(graph.tools)
        risky_tools = sum(1 for t in graph.tools.values() if t.security_score < 50)
        critical_concerns = sum(1 for c in graph.security_concerns if c['severity'] == 'CRITICAL')

        return {
            'total_tools': total_tools,
            'risky_tools': risky_tools,
            'tool_relationships': len(graph.tool_relationships),
            'risky_operations': len(graph.risky_imports),
            'critical_concerns': critical_concerns,
            'has_manifest': graph.mcp_manifest is not None
        }
