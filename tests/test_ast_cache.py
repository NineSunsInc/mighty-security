#!/usr/bin/env python3
"""
Test Suite for AST Cache
Tests caching, performance, and correctness
"""

import ast
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.ast_cache import ASTCache, GlobalASTCache


class TestASTCache(unittest.TestCase):
    """Test AST cache functionality"""

    def setUp(self):
        """Set up test cache"""
        self.cache = ASTCache(max_size=5)
        self.test_code = """
def example_function(x, y):
    result = x + y
    return result

class ExampleClass:
    def __init__(self):
        self.value = 42
"""

    def test_cache_basic_functionality(self):
        """Test basic cache operations"""
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(self.test_code)
            temp_path = Path(f.name)

        try:
            # First call - cache miss
            ast1 = self.cache.get_ast(temp_path)
            self.assertIsNotNone(ast1, "Should parse AST")
            self.assertEqual(self.cache._misses, 1)
            self.assertEqual(self.cache._hits, 0)

            # Second call - cache hit
            ast2 = self.cache.get_ast(temp_path)
            self.assertIsNotNone(ast2, "Should return cached AST")
            self.assertEqual(self.cache._misses, 1)
            self.assertEqual(self.cache._hits, 1)

            # Should be same object
            self.assertIs(ast1, ast2, "Should return same cached object")

        finally:
            temp_path.unlink()

    def test_cache_performance(self):
        """Test that caching improves performance"""
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Large code to make parsing slower
            large_code = self.test_code * 100
            f.write(large_code)
            temp_path = Path(f.name)

        try:
            # First parse (cache miss)
            start = time.perf_counter()
            ast1 = self.cache.get_ast(temp_path)
            time_miss = time.perf_counter() - start

            # Second parse (cache hit)
            start = time.perf_counter()
            ast2 = self.cache.get_ast(temp_path)
            time_hit = time.perf_counter() - start

            # Cache hit should be at least 10x faster
            self.assertLess(time_hit, time_miss / 10,
                          f"Cache hit ({time_hit:.4f}s) not fast enough vs miss ({time_miss:.4f}s)")

        finally:
            temp_path.unlink()

    def test_cache_eviction(self):
        """Test LRU eviction when cache is full"""
        # Create multiple temp files
        temp_files = []
        for i in range(7):  # More than cache size (5)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(f"# File {i}\nprint({i})")
                temp_files.append(Path(f.name))

        try:
            # Fill cache beyond capacity
            for i, temp_path in enumerate(temp_files):
                self.cache.get_ast(temp_path)

            # Cache should have max_size entries
            self.assertEqual(len(self.cache._cache), 5,
                           "Cache should not exceed max_size")

            # First files should be evicted (LRU)
            cache_keys = list(self.cache._cache.keys())
            for i in range(2):  # First 2 should be evicted
                self.assertNotIn(str(temp_files[i]),
                               ' '.join(cache_keys),
                               f"File {i} should be evicted")

        finally:
            for temp_path in temp_files:
                temp_path.unlink()

    def test_content_based_hashing(self):
        """Test that cache uses content hash, not file path"""
        # Create two files with same content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f1:
            f1.write(self.test_code)
            temp_path1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f2:
            f2.write(self.test_code)
            temp_path2 = Path(f2.name)

        try:
            # Parse first file
            ast1 = self.cache.get_ast(temp_path1)
            self.assertEqual(self.cache._misses, 1)

            # Parse second file with same content
            # Should still be a miss because paths differ
            ast2 = self.cache.get_ast(temp_path2)
            self.assertEqual(self.cache._misses, 2)

            # But if we parse first file again, should hit
            ast3 = self.cache.get_ast(temp_path1)
            self.assertEqual(self.cache._hits, 1)

        finally:
            temp_path1.unlink()
            temp_path2.unlink()

    def test_syntax_error_handling(self):
        """Test handling of files with syntax errors"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def broken_function(\n    pass")  # Syntax error
            temp_path = Path(f.name)

        try:
            # Should return None for syntax errors
            result = self.cache.get_ast(temp_path)
            self.assertIsNone(result, "Should return None for syntax errors")
            self.assertEqual(self.cache._parse_errors, 1)

            # Should not cache syntax errors
            self.assertEqual(len(self.cache._cache), 0)

        finally:
            temp_path.unlink()

    def test_cache_stats(self):
        """Test cache statistics tracking"""
        # Initial stats
        stats = self.cache.get_stats()
        self.assertEqual(stats['hits'], 0)
        self.assertEqual(stats['misses'], 0)
        self.assertEqual(stats['cache_size'], 0)

        # Create and parse file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(self.test_code)
            temp_path = Path(f.name)

        try:
            # Parse multiple times
            self.cache.get_ast(temp_path)  # Miss
            self.cache.get_ast(temp_path)  # Hit
            self.cache.get_ast(temp_path)  # Hit

            stats = self.cache.get_stats()
            self.assertEqual(stats['hits'], 2)
            self.assertEqual(stats['misses'], 1)
            self.assertEqual(stats['cache_size'], 1)
            self.assertEqual(stats['hit_rate'], '66.7%')

        finally:
            temp_path.unlink()

    def test_ast_pattern_analysis(self):
        """Test AST pattern analysis functionality"""
        test_code = """
import os
import subprocess

def dangerous_function(user_input):
    exec(user_input)
    eval(user_input)
    subprocess.run(user_input, shell=True)

class SafeClass:
    def safe_method(self):
        try:
            return "safe"
        except Exception:
            pass
"""

        # Parse code
        tree = ast.parse(test_code)

        # Analyze patterns
        patterns = self.cache.analyze_ast_patterns(tree)

        self.assertEqual(patterns['exec_calls'], 1)
        self.assertEqual(patterns['eval_calls'], 1)
        self.assertEqual(patterns['subprocess_calls'], 1)
        self.assertEqual(patterns['imports'], 2)
        self.assertEqual(patterns['functions'], 2)  # dangerous_function and safe_method
        self.assertEqual(patterns['classes'], 1)
        self.assertEqual(patterns['try_except'], 1)

    def test_preload_directory(self):
        """Test directory preloading"""
        # Create temp directory with Python files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            for i in range(3):
                file_path = temp_path / f"test_{i}.py"
                file_path.write_text(f"# File {i}\nprint({i})")

            # Preload directory
            self.cache.preload_directory(temp_path)

            # Check cache is populated
            self.assertEqual(len(self.cache._cache), 3)
            self.assertEqual(self.cache._misses, 3)

            # Now parsing should hit cache
            test_file = temp_path / "test_0.py"
            self.cache.get_ast(test_file)
            self.assertEqual(self.cache._hits, 1)

    def test_global_cache_singleton(self):
        """Test global cache singleton pattern"""
        cache1 = GlobalASTCache()
        cache2 = GlobalASTCache()

        # Should be same instance
        self.assertIs(cache1, cache2, "Global cache should be singleton")

        # Should have larger max_size
        self.assertEqual(cache1._max_size, 200)

    def test_cache_clear(self):
        """Test cache clearing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(self.test_code)
            temp_path = Path(f.name)

        try:
            # Populate cache
            self.cache.get_ast(temp_path)
            self.assertEqual(len(self.cache._cache), 1)

            # Clear cache
            self.cache.clear()
            self.assertEqual(len(self.cache._cache), 0)

            # Should miss after clear
            self.cache.get_ast(temp_path)
            self.assertEqual(self.cache._misses, 2)  # Original + after clear

        finally:
            temp_path.unlink()


def run_tests():
    """Run all AST cache tests"""
    print("\n" + "="*60)
    print("AST CACHE TEST SUITE")
    print("="*60)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test class
    suite.addTests(loader.loadTestsFromTestCase(TestASTCache))

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
