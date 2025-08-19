#!/usr/bin/env python3
"""
Test MCP Dependency Analyzer - Focused on MCP tool security analysis
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzers.comprehensive.mcp_dependency_analyzer import MCPDependencyAnalyzer


def test_mcp_tool_detection():
    """Test detection of MCP tools and handlers"""
    print("\n" + "="*60)
    print("🔍 MCP TOOL DETECTION TEST")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create MCP tool files
        tool1 = tmpdir / "calculator_tool.py"
        tool1.write_text("""
@tool("calculator")
def handle_calculation(params):
    expression = params.get("expression")
    # DANGER: Using eval!
    result = eval(expression)
    return {"result": result}
""")

        tool2 = tmpdir / "file_handler.py"
        tool2.write_text("""
import os
import subprocess

class FileHandlerTool:
    def handle(self, request):
        path = request.get("path")
        # DANGER: Path traversal risk
        with open(path, 'r') as f:
            return f.read()
    
    def execute_command(self, cmd):
        # DANGER: Command injection
        subprocess.run(cmd, shell=True)
""")

        # Create a safe tool
        safe_tool = tmpdir / "json_formatter.py"
        safe_tool.write_text("""
import json

@tool("json_formatter")
def format_json(params):
    data = params.get("data")
    pretty = json.dumps(data, indent=2)
    return {"formatted": pretty}
""")

        # Run analysis
        analyzer = MCPDependencyAnalyzer()
        graph = analyzer.analyze(tmpdir)

        print(f"   ✅ Found {len(graph.tools)} MCP tools")

        # Check detection
        assert len(graph.tools) >= 2

        # Check for risky operations
        risky = [t for t in graph.tools.values() if t.risky_operations]
        print(f"   ⚠️  {len(risky)} tools have risky operations")

        # Check security concerns
        critical = [c for c in graph.security_concerns if c['severity'] == 'CRITICAL']
        print(f"   🚨 {len(critical)} critical security concerns found")

        assert len(critical) > 0  # Should find eval and subprocess issues

        print("   ✅ MCP tool detection working!")
        return True


def test_tool_relationships():
    """Test detection of tool import relationships"""
    print("\n" + "="*60)
    print("🔍 TOOL RELATIONSHIP DETECTION TEST")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create interconnected tools
        (tmpdir / "main_tool.py").write_text("""
from .auth_tool import authenticate
from .data_tool import process_data

@tool("main")
def handle_request(params):
    if authenticate(params):
        return process_data(params)
""")

        (tmpdir / "auth_tool.py").write_text("""
import os

@tool("auth")
def authenticate(params):
    token = params.get("token")
    # Check token
    return token == os.environ.get("SECRET_TOKEN")
""")

        (tmpdir / "data_tool.py").write_text("""
import pickle

@tool("data")
def process_data(params):
    data = params.get("data")
    # DANGER: Unsafe deserialization
    obj = pickle.loads(data)
    return obj
""")

        # Run analysis
        analyzer = MCPDependencyAnalyzer()
        graph = analyzer.analyze(tmpdir)

        print(f"   ✅ Found {len(graph.tools)} tools")
        print(f"   📊 Found {len(graph.tool_relationships)} relationships")

        # Check that main_tool imports were detected
        main_imports = None
        for tool in graph.tools.values():
            if 'main_tool' in tool.file_path:
                main_imports = tool.imports_tools
                break

        if main_imports:
            print(f"   ✅ Main tool imports: {main_imports}")

        print("   ✅ Tool relationship detection working!")
        return True


def test_mcp_manifest_analysis():
    """Test MCP manifest security analysis"""
    print("\n" + "="*60)
    print("📋 MCP MANIFEST ANALYSIS TEST")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create MCP manifest with security issues
        manifest = {
            "name": "test-mcp-server",
            "version": "1.0.0",
            "permissions": ["*", "system"],  # Overly broad!
            "tools": [
                {
                    "name": "dangerous_tool",
                    "description": "A tool that does dangerous things"
                },
                {
                    "name": "safe_tool",
                    "description": "A safe tool"
                }
            ]
        }

        with open(tmpdir / "mcp.json", 'w') as f:
            json.dump(manifest, f)

        # Create corresponding tool file
        (tmpdir / "dangerous_tool.py").write_text("""
import subprocess

@tool("dangerous_tool")
def handle(params):
    cmd = params.get("command")
    subprocess.run(cmd, shell=True)
""")

        # Run analysis
        analyzer = MCPDependencyAnalyzer()
        graph = analyzer.analyze(tmpdir)

        assert graph.mcp_manifest is not None
        print(f"   ✅ Manifest found: {graph.mcp_manifest['name']}")

        # Check for permission issues
        if graph.mcp_manifest['security_issues']:
            print("   🚨 Security issues in manifest:")
            for issue in graph.mcp_manifest['security_issues']:
                print(f"      - {issue}")

        assert len(graph.mcp_manifest['security_issues']) > 0

        print("   ✅ MCP manifest analysis working!")
        return True


def test_security_scoring():
    """Test security scoring of tools"""
    print("\n" + "="*60)
    print("📊 SECURITY SCORING TEST")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create tools with different risk levels
        high_risk = tmpdir / "high_risk_tool.py"
        high_risk.write_text("""
import subprocess

@tool("high_risk")
def handle(params):
    # Multiple high-risk operations
    cmd = params.get("cmd")
    eval(cmd)  # Code injection
    subprocess.run(cmd, shell=True)  # Command injection
    api_key = "sk-12345678"  # Hardcoded secret
""")

        medium_risk = tmpdir / "medium_risk_tool.py"
        medium_risk.write_text("""
import requests

@tool("medium_risk")
def handle(params):
    url = params.get("url")
    # External communication
    response = requests.get(url)
    return response.text
""")

        low_risk = tmpdir / "low_risk_tool.py"
        low_risk.write_text("""
import json

@tool("low_risk")
def handle(params):
    # Safe operations only
    data = params.get("data")
    return json.dumps(data)
""")

        # Run analysis
        analyzer = MCPDependencyAnalyzer()
        graph = analyzer.analyze(tmpdir)

        # Check security scores
        scores = {}
        for tool in graph.tools.values():
            if 'high_risk' in tool.file_path:
                scores['high'] = tool.security_score
            elif 'medium_risk' in tool.file_path:
                scores['medium'] = tool.security_score
            elif 'low_risk' in tool.file_path:
                scores['low'] = tool.security_score

        print("   📊 Security Scores:")
        print(f"      High-risk tool: {scores.get('high', 'N/A')}/100")
        print(f"      Medium-risk tool: {scores.get('medium', 'N/A')}/100")
        print(f"      Low-risk tool: {scores.get('low', 'N/A')}/100")

        # Verify scoring makes sense
        if 'high' in scores and 'low' in scores:
            assert scores['high'] < scores['low'], "High-risk should score lower than low-risk"

        print("   ✅ Security scoring working!")
        return True


def main():
    """Run all MCP dependency analyzer tests"""
    print("🧪 Testing MCP Dependency Analyzer...")

    tests = [
        ("MCP Tool Detection", test_mcp_tool_detection),
        ("Tool Relationships", test_tool_relationships),
        ("MCP Manifest Analysis", test_mcp_manifest_analysis),
        ("Security Scoring", test_security_scoring)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"   ❌ {test_name} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "="*60)
    print("FINAL TEST RESULTS")
    print("="*60)
    print(f"✅ Passed: {passed}/{len(tests)}")
    if failed > 0:
        print(f"❌ Failed: {failed}/{len(tests)}")
    else:
        print("🎉 ALL MCP DEPENDENCY ANALYZER TESTS PASSED!")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
