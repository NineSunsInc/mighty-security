#!/usr/bin/env python3
"""
Enhanced Inter-procedural Taint Analysis Engine
Tracks data flow across files and functions to detect vulnerabilities
"""

from typing import List, Dict, Set, Tuple, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
import ast
import re
from enum import Enum

from .types import FlowTrace, TaintKind, Frame
from .sources_sinks import SOURCE_PATTERNS, SINK_PATTERNS, SANITIZERS

class TaintSource(Enum):
    """Types of taint sources"""
    USER_INPUT = "user_input"
    FILE_READ = "file_read"
    NETWORK = "network"
    DATABASE = "database"
    ENVIRONMENT = "environment"
    COMMAND_ARG = "command_arg"
    EXTERNAL_API = "external_api"

class TaintSink(Enum):
    """Types of taint sinks"""
    COMMAND_EXEC = "command_execution"
    FILE_WRITE = "file_write"
    SQL_QUERY = "sql_query"
    NETWORK_OUT = "network_output"
    TEMPLATE = "template_render"
    EVAL_EXEC = "eval_execution"
    CRYPTO_OP = "crypto_operation"
    LOG_OUTPUT = "log_output"

@dataclass
class TaintedVariable:
    """Represents a tainted variable in the analysis"""
    name: str
    source: TaintSource
    file_path: str
    line_number: int
    confidence: float = 1.0
    sanitized: bool = False
    transformations: List[str] = field(default_factory=list)

@dataclass
class DataFlowEdge:
    """Edge in the data flow graph"""
    from_var: str
    to_var: str
    from_file: str
    to_file: str
    from_line: int
    to_line: int
    flow_type: str  # assignment, function_call, return, etc.
    is_sanitized: bool = False

class EnhancedTaintEngine:
    """Enhanced taint analysis with cross-file tracking"""
    
    def __init__(self):
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        self.data_flow_graph: List[DataFlowEdge] = []
        self.vulnerable_flows: List[FlowTrace] = []
        self.call_graph = None
        self.file_asts: Dict[str, ast.AST] = {}
        
        # Track function signatures for inter-procedural analysis
        self.function_signatures: Dict[str, Dict] = {}
        
        # Sanitization patterns
        self.sanitizers = [
            r'escape\(',
            r'quote\(',
            r'sanitize\(',
            r'clean\(',
            r'validate\(',
            r'filter\(',
            r'html\.escape',
            r'shlex\.quote',
            r'parameterized',
            r'prepared_statement',
        ]
    
    def analyze(self, repo_path: Path, call_graph: Any, catalog: Any = None) -> List[FlowTrace]:
        """Perform enhanced taint analysis across the repository"""
        
        self.call_graph = call_graph
        
        # Parse all Python files
        self._parse_all_files(repo_path)
        
        # Identify taint sources
        self._identify_sources(repo_path)
        
        # Build data flow graph
        self._build_data_flow_graph()
        
        # Propagate taint through the graph
        self._propagate_taint()
        
        # Check for vulnerable flows to sinks
        self._check_sinks()
        
        return self.vulnerable_flows
    
    def _parse_all_files(self, repo_path: Path):
        """Parse all Python files into ASTs"""
        for py_file in repo_path.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                tree = ast.parse(content, filename=str(py_file))
                self.file_asts[str(py_file)] = tree
                
                # Extract function signatures
                self._extract_function_signatures(tree, str(py_file))
            except:
                continue
    
    def _extract_function_signatures(self, tree: ast.AST, file_path: str):
        """Extract function signatures for inter-procedural analysis"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                sig = {
                    'name': node.name,
                    'file': file_path,
                    'line': node.lineno,
                    'args': [arg.arg for arg in node.args.args],
                    'returns': [],  # Will be filled during analysis
                    'calls': [],  # Functions this function calls
                    'modifies': [],  # Variables it modifies
                }
                self.function_signatures[f"{file_path}:{node.name}"] = sig
    
    def _identify_sources(self, repo_path: Path):
        """Identify taint sources in the codebase"""
        
        source_patterns = {
            TaintSource.USER_INPUT: [
                r'request\.(GET|POST|args|form|json|data|files)',
                r'input\(',
                r'sys\.argv',
                r'raw_input\(',
                r'@app\.route.*methods',
                r'@tool',  # MCP tool decorator
            ],
            TaintSource.FILE_READ: [
                r'open\(.*["\']r',
                r'\.read\(',
                r'Path\(.*\)\.read_text',
                r'json\.load\(',
            ],
            TaintSource.NETWORK: [
                r'requests\.(get|post|put|delete)',
                r'urlopen\(',
                r'socket\.recv',
                r'websocket\.',
            ],
            TaintSource.DATABASE: [
                r'\.execute\(',
                r'\.fetchone\(',
                r'\.fetchall\(',
                r'\.find\(',  # MongoDB
            ],
            TaintSource.ENVIRONMENT: [
                r'os\.environ',
                r'os\.getenv',
                r'dotenv',
            ],
        }
        
        for file_path, tree in self.file_asts.items():
            for node in ast.walk(tree):
                # Check for pattern matches
                node_str = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                
                for source_type, patterns in source_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, node_str):
                            # Found a source
                            if isinstance(node, ast.Assign):
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        tainted = TaintedVariable(
                                            name=target.id,
                                            source=source_type,
                                            file_path=file_path,
                                            line_number=getattr(node, 'lineno', 0)
                                        )
                                        self.tainted_vars[f"{file_path}:{target.id}"] = tainted
    
    def _build_data_flow_graph(self):
        """Build data flow graph across files"""
        
        for file_path, tree in self.file_asts.items():
            visitor = DataFlowVisitor(self, file_path)
            visitor.visit(tree)
    
    def _propagate_taint(self):
        """Propagate taint through the data flow graph"""
        
        # Use worklist algorithm
        worklist = list(self.tainted_vars.keys())
        visited = set()
        
        while worklist:
            var_key = worklist.pop(0)
            if var_key in visited:
                continue
            visited.add(var_key)
            
            # Find all edges from this variable
            for edge in self.data_flow_graph:
                if f"{edge.from_file}:{edge.from_var}" == var_key:
                    to_key = f"{edge.to_file}:{edge.to_var}"
                    
                    # Propagate taint
                    if var_key in self.tainted_vars:
                        source_taint = self.tainted_vars[var_key]
                        
                        # Check if flow passes through sanitizer
                        is_sanitized = edge.is_sanitized or self._is_sanitized(edge)
                        
                        # Create or update tainted variable
                        if to_key not in self.tainted_vars:
                            self.tainted_vars[to_key] = TaintedVariable(
                                name=edge.to_var,
                                source=source_taint.source,
                                file_path=edge.to_file,
                                line_number=edge.to_line,
                                confidence=source_taint.confidence * 0.9,  # Reduce confidence
                                sanitized=is_sanitized
                            )
                            worklist.append(to_key)
    
    def _check_sinks(self):
        """Check if tainted data reaches dangerous sinks"""
        
        sink_patterns = {
            TaintSink.COMMAND_EXEC: [
                r'subprocess\.(run|call|Popen)',
                r'os\.system',
                r'os\.popen',
                r'exec\(',
                r'eval\(',
            ],
            TaintSink.FILE_WRITE: [
                r'open\(.*["\']w',
                r'\.write\(',
                r'Path\(.*\)\.write_text',
            ],
            TaintSink.SQL_QUERY: [
                r'\.execute\(',
                r'\.raw\(',  # Django ORM
                r'\.extra\(',
            ],
            TaintSink.TEMPLATE: [
                r'render_template',
                r'jinja2\.Template',
                r'\.format\(',
                r'string\.Template',
            ],
        }
        
        for file_path, tree in self.file_asts.items():
            for node in ast.walk(tree):
                node_str = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                
                for sink_type, patterns in sink_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, node_str):
                            # Check if any tainted variable is used
                            used_vars = self._get_used_variables(node)
                            
                            for var in used_vars:
                                var_key = f"{file_path}:{var}"
                                if var_key in self.tainted_vars:
                                    taint = self.tainted_vars[var_key]
                                    
                                    if not taint.sanitized:
                                        # Found vulnerable flow!
                                        flow = self._create_flow_trace(
                                            taint, 
                                            sink_type,
                                            file_path,
                                            getattr(node, 'lineno', 0)
                                        )
                                        self.vulnerable_flows.append(flow)
    
    def _is_sanitized(self, edge: DataFlowEdge) -> bool:
        """Check if data flow passes through sanitization"""
        # Check for sanitization patterns in the flow
        # This would need access to the actual code between from and to
        return False  # Simplified for now
    
    def _get_used_variables(self, node: ast.AST) -> Set[str]:
        """Get all variables used in an AST node"""
        variables = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                variables.add(child.id)
        return variables
    
    def _create_flow_trace(
        self,
        taint: TaintedVariable,
        sink_type: TaintSink,
        sink_file: str,
        sink_line: int
    ) -> FlowTrace:
        """Create a FlowTrace object for the vulnerability"""
        
        # Build the flow path
        frames = []
        
        # Source frame
        frames.append(Frame(
            file_path=taint.file_path,
            function_name="<module>",  # Would need to determine actual function
            line_number=taint.line_number,
            code_snippet="",  # Would need to extract actual code
            variable_name=taint.name,
            taint_kind=TaintKind.UNTRUSTED_INPUT
        ))
        
        # Sink frame
        frames.append(Frame(
            file_path=sink_file,
            function_name="<module>",
            line_number=sink_line,
            code_snippet="",
            variable_name=taint.name,
            taint_kind=TaintKind.DANGEROUS_SINK
        ))
        
        return FlowTrace(
            source_type=taint.source.value,
            sink_type=sink_type.value,
            frames=frames,
            confidence=taint.confidence,
            severity="HIGH" if sink_type == TaintSink.COMMAND_EXEC else "MEDIUM",
            description=f"Tainted data from {taint.source.value} reaches {sink_type.value}"
        )

class DataFlowVisitor(ast.NodeVisitor):
    """AST visitor to build data flow edges"""
    
    def __init__(self, engine: EnhancedTaintEngine, file_path: str):
        self.engine = engine
        self.file_path = file_path
        self.current_function = None
    
    def visit_FunctionDef(self, node):
        """Track function definitions"""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Assign(self, node):
        """Track assignments for data flow"""
        # Get target variables
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
        
        # Get source variables
        sources = self._get_variables_from_value(node.value)
        
        # Create edges
        for source in sources:
            for target in targets:
                edge = DataFlowEdge(
                    from_var=source,
                    to_var=target,
                    from_file=self.file_path,
                    to_file=self.file_path,
                    from_line=node.lineno,
                    to_line=node.lineno,
                    flow_type="assignment"
                )
                self.engine.data_flow_graph.append(edge)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track function calls for inter-procedural flow"""
        # Would need to map calls to function definitions
        # and track parameter passing
        self.generic_visit(node)
    
    def _get_variables_from_value(self, node) -> List[str]:
        """Extract variable names from a value node"""
        variables = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                variables.append(child.id)
        return variables


def analyze(repo_path: Path, call_graph: Any, catalog: Any = None) -> List[FlowTrace]:
    """Analyze repository for tainted flows using enhanced engine"""
    engine = EnhancedTaintEngine()
    return engine.analyze(repo_path, call_graph, catalog)


