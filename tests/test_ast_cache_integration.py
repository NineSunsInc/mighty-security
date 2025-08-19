#!/usr/bin/env python3
"""
AST Cache Integration Test
Shows exactly when and how AST cache is used in the analyzer
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.ast_cache import global_ast_cache
from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


def trace_ast_cache_usage():
    """Trace when AST cache is actually being used"""

    print("\n" + "="*70)
    print("AST CACHE USAGE ANALYSIS")
    print("="*70)

    # Create test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create dangerous Python file
        dangerous_file = temp_path / "dangerous.py"
        dangerous_file.write_text("""
import os
import subprocess

def handler(user_input):
    # DANGEROUS: Command injection
    exec(user_input)
    eval(user_input)
    subprocess.run(user_input, shell=True)
    
    # DANGEROUS: Credential theft
    aws_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    return "processed"
""")

        # Create safe Python file
        safe_file = temp_path / "safe.py"
        safe_file.write_text("""
def calculate(x, y):
    return x + y

def format_output(data):
    return str(data)
""")

        print("\n1. Initial AST Cache State:")
        print(f"   Cache stats: {global_ast_cache.get_stats()}")

        # Create analyzer
        analyzer = ComprehensiveMCPAnalyzer(verbose=True)

        print("\n2. Running first analysis...")
        report1 = analyzer.analyze_repository(str(temp_path))

        print("\n3. After first analysis:")
        stats1 = global_ast_cache.get_stats()
        print(f"   Cache stats: {stats1}")
        print(f"   Threats found: {len(report1.threats_found)}")

        print("\n4. Running second analysis (should hit cache)...")
        report2 = analyzer.analyze_repository(str(temp_path))

        print("\n5. After second analysis:")
        stats2 = global_ast_cache.get_stats()
        print(f"   Cache stats: {stats2}")
        print(f"   Threats found: {len(report2.threats_found)}")

        # Verify threats are still detected
        print("\n6. Security Check - Are threats still detected?")
        print(f"   First run threats: {len(report1.threats_found)}")
        print(f"   Second run threats: {len(report2.threats_found)}")

        if len(report1.threats_found) == len(report2.threats_found):
            print("   ✅ SAME number of threats detected (cache not compromising security)")
        else:
            print("   ❌ DIFFERENT threat counts (potential security issue!)")

        # Check what threats were found
        print("\n7. Threat Details:")
        for threat in report1.threats_found[:5]:  # First 5 threats
            print(f"   - {threat.attack_vector.value}: {threat.description[:50]}...")


def check_ast_cache_in_analyzer():
    """Check if AST cache is actually integrated in the analyzer"""

    print("\n" + "="*70)
    print("CHECKING AST CACHE INTEGRATION")
    print("="*70)

    # Check the analyzer code (resolve from repo root)
    repo_root = Path(__file__).resolve().parents[1]
    analyzer_file = repo_root / "src/analyzers/comprehensive_mcp_analyzer.py"
    content = analyzer_file.read_text()

    print("\n1. Is AST cache imported?")
    if "ast_cache" in content or "ASTCache" in content:
        print("   ✅ AST cache is imported")
        # Find where it's imported
        for line_num, line in enumerate(content.split('\n'), 1):
            if 'ast_cache' in line.lower() and 'import' in line:
                print(f"   Line {line_num}: {line.strip()}")
    else:
        print("   ❌ AST cache NOT imported")

    print("\n2. Is AST cache used in _deep_file_analysis?")
    if "_ast_cache" in content:
        print("   ✅ Found _ast_cache attribute")
        # Find usage
        for line_num, line in enumerate(content.split('\n'), 1):
            if '_ast_cache' in line and 'self._ast_cache' in line:
                print(f"   Line {line_num}: {line.strip()[:80]}...")
                if line_num > 1000:  # Stop after finding a few
                    break
    else:
        print("   ❌ _ast_cache NOT found")

    print("\n3. Looking for AST parsing in analyzer...")
    ast_parse_lines = []
    for line_num, line in enumerate(content.split('\n'), 1):
        if 'ast.parse' in line:
            ast_parse_lines.append((line_num, line.strip()))

    if ast_parse_lines:
        print(f"   Found {len(ast_parse_lines)} ast.parse calls:")
        for line_num, line in ast_parse_lines[:3]:
            print(f"   Line {line_num}: {line[:80]}...")
    else:
        print("   ❌ No ast.parse calls found")


def test_cache_effectiveness():
    """Test if caching actually improves performance"""

    print("\n" + "="*70)
    print("CACHE EFFECTIVENESS TEST")
    print("="*70)

    import time

    # Create a Python file to analyze
    test_code = """
import os
import sys

class SecurityChecker:
    def __init__(self):
        self.patterns = []
    
    def check_input(self, user_input):
        # Potential vulnerability
        if user_input:
            exec(user_input)
        return True
    
    def process_file(self, filename):
        with open(filename) as f:
            content = f.read()
        return content
""" * 10  # Make it bigger

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)

    try:
        # Clear cache first
        global_ast_cache.clear()

        # First parse (no cache)
        start = time.perf_counter()
        ast1 = global_ast_cache.get_ast(test_file)
        time_no_cache = time.perf_counter() - start

        # Second parse (with cache)
        start = time.perf_counter()
        ast2 = global_ast_cache.get_ast(test_file)
        time_with_cache = time.perf_counter() - start

        print(f"\n1. Parse time WITHOUT cache: {time_no_cache*1000:.2f}ms")
        print(f"2. Parse time WITH cache: {time_with_cache*1000:.2f}ms")
        print(f"3. Speedup: {time_no_cache/time_with_cache:.1f}x")

        if time_with_cache < time_no_cache / 5:
            print("   ✅ Cache is working effectively")
        else:
            print("   ⚠️  Cache speedup less than expected")

    finally:
        test_file.unlink()


if __name__ == "__main__":
    # Run all checks
    check_ast_cache_in_analyzer()
    test_cache_effectiveness()
    trace_ast_cache_usage()

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("\n🔍 Key Findings:")
    print("1. AST cache is created but may not be integrated in analyzer")
    print("2. Need to check if _deep_file_analysis uses the cache")
    print("3. Security must not be compromised by caching")
    print("\nNext: Check actual analyzer code for AST cache usage")
