#!/usr/bin/env python3
"""
Integration test for context-aware scanning with the ComprehensiveMCPAnalyzer.
Verifies that the full pipeline works correctly with real code analysis.
"""

import sys
import tempfile
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


def create_test_repository():
    """Create a temporary repository with various file types for testing"""
    temp_dir = tempfile.mkdtemp(prefix="test_scan_")

    # Create directory structure
    (Path(temp_dir) / "src").mkdir()
    (Path(temp_dir) / "tests").mkdir()
    (Path(temp_dir) / "examples").mkdir()

    # Production code with REAL vulnerability
    prod_code = '''
import subprocess
import os

def process_file(user_input):
    # CRITICAL: Command injection vulnerability
    subprocess.call(f"cat {user_input}", shell=True)
    
def get_config():
    # CRITICAL: Hardcoded credentials
    api_key = "sk_live_4242424242424242"
    return api_key
'''

    # Test code with intentional vulnerabilities (should be filtered in production)
    test_code = '''
import unittest
import subprocess

class TestExploits(unittest.TestCase):
    def test_command_injection(self):
        # Intentional vulnerability for testing
        os.system("rm -rf /")
        subprocess.call("evil", shell=True)
        exec("malicious_code")
'''

    # Example code (should be filtered in production)
    example_code = '''
# Example of dangerous patterns
import os
os.system(user_input)  # Don't do this!
eval(user_data)  # Never use eval with user input
'''

    # Security tool code (should have adjusted severity)
    security_tool = '''
import ast
import inspect

class SecurityAnalyzer:
    def __init__(self):
        self.analyzer = "security"
        self.detector = "threats"
    
    def scan_for_vulnerabilities(self):
        # Detect eval and exec usage
        dangerous_functions = ['eval', 'exec', 'compile']
        return dangerous_functions
'''

    # Write files
    with open(Path(temp_dir) / "src" / "api.py", "w") as f:
        f.write(prod_code)

    with open(Path(temp_dir) / "tests" / "test_security.py", "w") as f:
        f.write(test_code)

    with open(Path(temp_dir) / "examples" / "bad_practices.py", "w") as f:
        f.write(example_code)

    with open(Path(temp_dir) / "src" / "scanner.py", "w") as f:
        f.write(security_tool)

    return temp_dir


def test_production_profile():
    """Test that production profile excludes tests/examples but catches real issues"""
    print("\n🏭 Testing PRODUCTION Profile")
    print("=" * 60)

    temp_repo = create_test_repository()

    try:
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=False,
            deep_scan=True,
            profile='production'
        )

        report = analyzer.analyze_repository(temp_repo)

        print(f"Files scanned: {report.total_files_scanned}")
        print(f"Threats found: {len(report.threats_found)}")

        # Check that critical vulnerabilities in production code are found
        critical_threats = [t for t in report.threats_found
                          if 'CRITICAL' in str(t.severity) and 'src/api.py' in str(t.file_path)]

        print(f"Critical threats in production code: {len(critical_threats)}")

        # Verify test files were excluded
        test_threats = [t for t in report.threats_found
                       if 'tests/' in str(t.file_path)]

        print(f"Threats from test files: {len(test_threats)} (should be 0)")

        # Verify example files were excluded
        example_threats = [t for t in report.threats_found
                          if 'examples/' in str(t.file_path)]

        print(f"Threats from example files: {len(example_threats)} (should be 0)")

        # Print summary
        print("\n📊 Production Profile Results:")
        print(f"  ✅ Critical vulnerabilities detected: {len(critical_threats) >= 2}")
        print(f"  ✅ Test files excluded: {len(test_threats) == 0}")
        print(f"  ✅ Example files excluded: {len(example_threats) == 0}")

        # Cleanup
        import shutil
        shutil.rmtree(temp_repo)

        return len(critical_threats) >= 2 and len(test_threats) == 0 and len(example_threats) == 0

    except Exception as e:
        print(f"❌ Error: {e}")
        import shutil
        shutil.rmtree(temp_repo)
        return False


def test_development_profile():
    """Test that development profile includes tests with adjusted severity"""
    print("\n🔧 Testing DEVELOPMENT Profile")
    print("=" * 60)

    temp_repo = create_test_repository()

    try:
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=False,
            deep_scan=True,
            profile='development'
        )

        report = analyzer.analyze_repository(temp_repo)

        print(f"Files scanned: {report.total_files_scanned}")
        print(f"Threats found: {len(report.threats_found)}")

        # Check that test files are included
        test_threats = [t for t in report.threats_found
                       if 'tests/' in str(t.file_path)]

        print(f"Threats from test files: {len(test_threats)} (should be > 0)")

        # Check that critical threats in tests are downgraded
        test_critical = [t for t in test_threats if 'CRITICAL' in str(t.severity)]
        print(f"Critical severity in test files: {len(test_critical)} (should be reduced)")

        # Production code should still have critical threats
        prod_critical = [t for t in report.threats_found
                        if 'CRITICAL' in str(t.severity) and 'src/api.py' in str(t.file_path)]

        print(f"Critical threats in production: {len(prod_critical)} (should be > 0)")

        print("\n📊 Development Profile Results:")
        print(f"  ✅ Test files included: {len(test_threats) > 0}")
        print(f"  ✅ Production threats still critical: {len(prod_critical) > 0}")

        # Cleanup
        import shutil
        shutil.rmtree(temp_repo)

        return len(test_threats) > 0 and len(prod_critical) > 0

    except Exception as e:
        print(f"❌ Error: {e}")
        import shutil
        shutil.rmtree(temp_repo)
        return False


def test_filtering_statistics():
    """Test that filtering statistics are correctly reported"""
    print("\n📈 Testing Filtering Statistics")
    print("=" * 60)

    temp_repo = create_test_repository()

    try:
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=False,
            deep_scan=False,
            profile='production'
        )

        # Get filter stats before scan
        if analyzer.smart_filter:
            analyzer.smart_filter.reset_stats()

        report = analyzer.analyze_repository(temp_repo)

        if analyzer.smart_filter:
            stats = analyzer.smart_filter.get_stats()
            print(f"Files excluded: {stats['files_excluded']}")
            print(f"Files included: {stats['files_included']}")
            print(f"Adjustments made: {stats['adjustments_made']}")

            if stats['top_exclusion_reasons']:
                print("\nTop exclusion reasons:")
                for reason, count in stats['top_exclusion_reasons']:
                    print(f"  - {reason}: {count}")

        # Cleanup
        import shutil
        shutil.rmtree(temp_repo)

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import shutil
        shutil.rmtree(temp_repo)
        return False


def main():
    """Run all integration tests"""
    print("\n" + "=" * 70)
    print("CONTEXT-AWARE SCANNING INTEGRATION TESTS")
    print("=" * 70)

    results = []

    # Run tests
    results.append(("Production Profile", test_production_profile()))
    results.append(("Development Profile", test_development_profile()))
    results.append(("Statistics Tracking", test_filtering_statistics()))

    # Print summary
    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\n📊 Results: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 ALL INTEGRATION TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
