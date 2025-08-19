#!/usr/bin/env python3
"""
MINIMAL WORKING TAINT ANALYSIS
This is the absolute minimum needed to make taint analysis functional.
No fancy features - just source -> propagation -> sink detection.
"""

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TaintedVar:
    """Simple tainted variable tracking"""
    name: str
    source_line: int
    source_type: str


@dataclass
class Vulnerability:
    """Simple vulnerability finding"""
    source_var: str
    source_line: int
    sink_line: int
    sink_type: str
    confidence: float


class MinimalTaintEngine:
    """
    Minimal taint engine that actually works.
    No field sensitivity, no context sensitivity, no fancy features.
    Just tracks: input() -> variable -> dangerous_function()
    """

    def __init__(self):
        self.tainted_vars: dict[str, TaintedVar] = {}
        self.vulnerabilities: list[Vulnerability] = []

        # Simple patterns
        self.sources = {
            'input': 'user_input',
            'raw_input': 'user_input',
            'sys.argv': 'command_arg',
            'request.args': 'web_input',
            'request.form': 'web_input',
            'request.GET': 'web_input',
            'request.POST': 'web_input',
        }

        self.sinks = {
            'eval': 'code_execution',
            'exec': 'code_execution',
            'os.system': 'command_execution',
            'os.popen': 'command_execution',
            'subprocess.run': 'command_execution',
            'subprocess.call': 'command_execution',
            'subprocess.Popen': 'command_execution',
            '__import__': 'dynamic_import',
            'open': 'file_operation',
        }

    def analyze_file(self, filepath: Path) -> list[Vulnerability]:
        """Analyze a single Python file for taint vulnerabilities"""
        self.tainted_vars.clear()
        self.vulnerabilities.clear()

        try:
            with open(filepath) as f:
                code = f.read()
            tree = ast.parse(code, filename=str(filepath))
        except:
            return []

        # Step 1: Find all taint sources
        self._find_sources(tree)

        # Step 2: Propagate taint through assignments
        self._propagate_taint(tree)

        # Step 3: Check if tainted data reaches sinks
        self._check_sinks(tree)

        return self.vulnerabilities

    def _find_sources(self, tree: ast.AST):
        """Find all taint sources in the AST"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if assignment is from a taint source
                if isinstance(node.value, ast.Call):
                    call_name = self._get_call_name(node.value)

                    if call_name in self.sources:
                        # Mark variable as tainted
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.tainted_vars[target.id] = TaintedVar(
                                    name=target.id,
                                    source_line=node.lineno,
                                    source_type=self.sources[call_name]
                                )

    def _propagate_taint(self, tree: ast.AST):
        """Propagate taint through simple assignments"""
        # Multiple passes to handle chains like: a = input(); b = a; c = b
        for _ in range(3):  # Max 3 levels of propagation
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    # Check if assignment is from a tainted variable
                    if isinstance(node.value, ast.Name):
                        if node.value.id in self.tainted_vars:
                            # Propagate taint
                            source_taint = self.tainted_vars[node.value.id]
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.tainted_vars[target.id] = TaintedVar(
                                        name=target.id,
                                        source_line=source_taint.source_line,
                                        source_type=source_taint.source_type
                                    )

    def _check_sinks(self, tree: ast.AST):
        """Check if tainted variables reach dangerous sinks"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)

                if call_name in self.sinks:
                    # Check if any argument is tainted
                    for arg in node.args:
                        tainted_var = self._get_tainted_var(arg)
                        if tainted_var:
                            self.vulnerabilities.append(Vulnerability(
                                source_var=tainted_var.name,
                                source_line=tainted_var.source_line,
                                sink_line=node.lineno,
                                sink_type=self.sinks[call_name],
                                confidence=0.9
                            ))

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''

    def _get_tainted_var(self, node: ast.AST) -> TaintedVar:
        """Check if a node references a tainted variable"""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)
        # Could handle more complex expressions here
        return None


def analyze(filepath: Path) -> list[dict]:
    """Simple interface matching existing code"""
    engine = MinimalTaintEngine()
    vulns = engine.analyze_file(filepath)

    # Convert to dict format
    return [
        {
            'type': 'taint_flow',
            'source': f"line {v.source_line}: {v.source_var}",
            'sink': f"line {v.sink_line}: {v.sink_type}",
            'confidence': v.confidence,
            'severity': 'HIGH' if 'execution' in v.sink_type else 'MEDIUM'
        }
        for v in vulns
    ]


if __name__ == '__main__':
    # Test it
    import tempfile

    test_code = """
import os
import subprocess

# Test 1: Direct flow
user_input = input("Enter command: ")
os.system(user_input)  # VULNERABLE

# Test 2: Simple propagation
data = input("Enter data: ")
command = data
subprocess.run(command, shell=True)  # VULNERABLE

# Test 3: Safe usage
safe_var = "ls -la"
os.system(safe_var)  # SAFE - not from user input
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)

    engine = MinimalTaintEngine()
    vulnerabilities = engine.analyze_file(test_file)

    print(f"Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln.source_var} (line {vuln.source_line}) -> {vuln.sink_type} (line {vuln.sink_line})")

    # Clean up
    test_file.unlink()
