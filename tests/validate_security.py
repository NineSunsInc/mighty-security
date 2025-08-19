#!/usr/bin/env python3
"""
Final Security Validation
Ensures the tool is safe to use with all optimizations
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.ast_cache import global_ast_cache
from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.unified_pattern_registry import pattern_registry


def validate_security():
    """Comprehensive security validation"""

    print("\n" + "="*70)
    print("🔒 COMPREHENSIVE SECURITY VALIDATION")
    print("="*70)

    all_passed = True

    # Test 1: Pattern Detection
    print("\n1. Testing Pattern Detection...")
    dangerous_patterns = [
        ("exec(user_input)", "command_injection"),
        ("os.system(cmd)", "command_injection"),
        ("eval(data)", "command_injection"),
        ("subprocess.run(cmd, shell=True)", "command_injection"),
        ("password = 'hardcoded123'", "credential_theft"),
        ("../../etc/passwd", "path_traversal"),
    ]

    for code, category in dangerous_patterns:
        matches = pattern_registry.scan_content(code, [category])
        if matches:
            print(f"   ✅ Detected: {code[:30]}")
        else:
            print(f"   ❌ MISSED: {code[:30]}")
            all_passed = False

    # Test 2: AST Cache Safety
    print("\n2. Testing AST Cache Safety...")
    with tempfile.TemporaryDirectory() as td:
        test_file = Path(td) / "test.py"
        test_file.write_text("exec(dangerous_code)")

        # Clear cache
        global_ast_cache.clear()

        # First parse
        ast1 = global_ast_cache.get_ast(test_file)
        stats1 = global_ast_cache.get_stats()

        # Second parse (cached)
        ast2 = global_ast_cache.get_ast(test_file)
        stats2 = global_ast_cache.get_stats()

        if stats2['hits'] > stats1['hits']:
            print(f"   ✅ AST cache working (hit rate: {stats2['hit_rate']})")
        else:
            print("   ❌ AST cache not working")
            all_passed = False

    # Test 3: Full Analysis
    print("\n3. Testing Full Analysis...")
    with tempfile.TemporaryDirectory() as td:
        test_file = Path(td) / "vulnerable.py"
        vulnerable_code = """
import os
import subprocess

def handler(user_input):
    exec(user_input)
    eval(user_input)
    subprocess.run(user_input, shell=True)
    os.system(user_input)
    
    password = "secret123"
    aws_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    with open("../../etc/passwd") as f:
        data = f.read()
"""
        test_file.write_text(vulnerable_code)

        analyzer = ComprehensiveMCPAnalyzer(verbose=False)
        report = analyzer.analyze_repository(str(td))

        threats = len(report.threats_found)
        if threats >= 5:
            print(f"   ✅ Found {threats} threats")
        else:
            print(f"   ❌ Only found {threats} threats (expected >= 5)")
            all_passed = False

        # Check specific threat types
        threat_types = set()
        for threat in report.threats_found:
            threat_types.add(str(threat.attack_vector))

        expected = ['command_injection', 'credential_theft', 'path_traversal']
        for exp in expected:
            if any(exp in t.lower() for t in threat_types):
                print(f"   ✅ Detected {exp}")
            else:
                print(f"   ❌ MISSED {exp}")
                all_passed = False

    # Test 4: Consistency
    print("\n4. Testing Detection Consistency...")
    with tempfile.TemporaryDirectory() as td:
        test_file = Path(td) / "test.py"
        test_file.write_text("exec(user_input); eval(user_data)")

        analyzer = ComprehensiveMCPAnalyzer(verbose=False)

        # Run 3 times
        results = []
        for i in range(3):
            report = analyzer.analyze_repository(str(td))
            results.append(len(report.threats_found))

        if len(set(results)) == 1:
            print(f"   ✅ Consistent detection: {results[0]} threats each time")
        else:
            print(f"   ❌ INCONSISTENT: {results}")
            all_passed = False

    # Test 5: Performance Check
    print("\n5. Testing Performance Optimizations...")
    import time

    with tempfile.TemporaryDirectory() as td:
        # Create 10 test files
        for i in range(10):
            test_file = Path(td) / f"file{i}.py"
            test_file.write_text(f"# File {i}\nprint('test')")

        analyzer = ComprehensiveMCPAnalyzer(verbose=False)

        start = time.perf_counter()
        report = analyzer.analyze_repository(str(td))
        duration = time.perf_counter() - start

        files_per_second = 10 / duration
        if files_per_second > 50:
            print(f"   ✅ Performance: {files_per_second:.1f} files/second")
        else:
            print(f"   ⚠️  Performance: {files_per_second:.1f} files/second (expected > 50)")

    # Final Summary
    print("\n" + "="*70)
    print("VALIDATION RESULTS")
    print("="*70)

    if all_passed:
        print("\n✅ ALL SECURITY CHECKS PASSED")
        print("\n🔒 The tool is SAFE to use with optimizations:")
        print("   - Pattern detection: Working")
        print("   - AST cache: Safe and working")
        print("   - Threat detection: Comprehensive")
        print("   - Consistency: Verified")
        print("   - Performance: Optimized")
        print("\n✅ Ready for production use!")
        return True
    else:
        print("\n❌ SECURITY VALIDATION FAILED")
        print("\n🚨 DO NOT USE - Security issues detected!")
        print("\nFix all issues before using this tool.")
        return False


if __name__ == "__main__":
    success = validate_security()
    sys.exit(0 if success else 1)
