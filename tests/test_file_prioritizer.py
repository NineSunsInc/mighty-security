#!/usr/bin/env python3
"""
Test Suite for Smart File Prioritizer
Tests file prioritization logic and risk scoring
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.file_prioritizer import SmartFilePrioritizer, FilePriority


class TestFilePrioritizer(unittest.TestCase):
    """Test file prioritization functionality"""
    
    def test_entry_point_prioritization(self):
        """Test that entry points get highest priority"""
        files = [
            Path('utils.py'),
            Path('main.py'),
            Path('helper.py'),
            Path('__main__.py'),
            Path('app.py'),
            Path('server.py'),
        ]
        
        prioritized = SmartFilePrioritizer.prioritize_files(files)
        
        # Entry points should be first
        top_files = [f.name for f in prioritized[:4]]
        self.assertIn('main.py', top_files)
        self.assertIn('__main__.py', top_files)
        self.assertIn('app.py', top_files)
        self.assertIn('server.py', top_files)
    
    def test_security_file_prioritization(self):
        """Test that security-related files get high priority"""
        files = [
            Path('readme.md'),
            Path('auth_handler.py'),
            Path('secret_manager.py'),
            Path('password_reset.py'),
            Path('token_validator.py'),
            Path('test.py'),
        ]
        
        prioritized = SmartFilePrioritizer.prioritize_files(files)
        
        # Security files should be prioritized
        top_files = [f.name for f in prioritized[:4]]
        self.assertIn('secret_manager.py', top_files)
        self.assertIn('auth_handler.py', top_files)
        self.assertIn('password_reset.py', top_files)
        self.assertIn('token_validator.py', top_files)
        
        # Non-security files should be lower (test or readme should be last)
        last_file = prioritized[-1].name
        self.assertIn(last_file, ['readme.md', 'test.py'], 
                     f"Expected readme.md or test.py to be last, got {last_file}")
    
    def test_mcp_pattern_priority(self):
        """Test MCP-specific pattern prioritization"""
        files = [
            Path('utils.py'),
            Path('mcp_server.py'),
            Path('mcp_handler.py'),
            Path('context_manager.py'),
            Path('test.py'),
        ]
        
        prioritized = SmartFilePrioritizer.prioritize_files(files)
        
        # MCP files should be first
        self.assertEqual(prioritized[0].name, 'mcp_handler.py')  # Has both mcp and handler
        self.assertEqual(prioritized[1].name, 'mcp_server.py')   # Has mcp and server
    
    def test_low_priority_filtering(self):
        """Test that test/example files get low priority"""
        files = [
            Path('handler.py'),
            Path('test_handler.py'),
            Path('example_usage.py'),
            Path('demo.py'),
            Path('__pycache__/compiled.pyc'),
            Path('node_modules/package.json'),
        ]
        
        prioritized = SmartFilePrioritizer.prioritize_files(files)
        
        # High priority should be first
        self.assertEqual(prioritized[0].name, 'handler.py')
        
        # Low priority should be last
        bottom_files = [f.name for f in prioritized[-3:]]
        self.assertIn('compiled.pyc', bottom_files)
        self.assertIn('package.json', bottom_files)
    
    def test_config_file_priority(self):
        """Test configuration file prioritization"""
        files = [
            Path('readme.txt'),
            Path('.env'),
            Path('config.json'),
            Path('settings.yaml'),
            Path('manifest.json'),
            Path('regular.py'),
        ]
        
        prioritized = SmartFilePrioritizer.prioritize_files(files)
        
        # Config files should be prioritized
        top_files = [f.name for f in prioritized[:4]]
        self.assertIn('.env', top_files)
        self.assertIn('config.json', top_files)
        self.assertIn('manifest.json', top_files)
    
    def test_critical_file_detection(self):
        """Test critical file detection"""
        files = [
            Path('utils.py'),
            Path('handler.py'),
            Path('.env'),
            Path('main.py'),
            Path('test.py'),
        ]
        
        critical_files = []
        for file in files:
            score, reason, is_critical = SmartFilePrioritizer._calculate_priority(file)
            if is_critical:
                critical_files.append(file.name)
        
        # These should be marked as critical
        self.assertIn('handler.py', critical_files)
        self.assertIn('.env', critical_files)
        self.assertIn('main.py', critical_files)
        
        # This should not be critical
        self.assertNotIn('test.py', critical_files)
    
    def test_user_preferences(self):
        """Test user preference integration"""
        files = [
            Path('normal.py'),
            Path('custom_important.py'),
            Path('blocked_file.py'),
        ]
        
        user_prefs = {
            'neverShare': ['custom_important'],
            'blockedPatterns': ['blocked'],
            'filePriorities': {'normal': 50}
        }
        
        prioritized = SmartFilePrioritizer.prioritize_files(files, user_prefs)
        
        # User preferences should override defaults
        self.assertEqual(prioritized[0].name, 'custom_important.py')
        self.assertEqual(prioritized[1].name, 'blocked_file.py')
    
    def test_batch_creation(self):
        """Test batch creation for parallel processing"""
        files = [Path(f'file_{i}.py') for i in range(25)]
        
        batches = SmartFilePrioritizer.get_batch_priorities(files, batch_size=10)
        
        # Should create 3 batches
        self.assertEqual(len(batches), 3)
        self.assertEqual(len(batches[0]), 10)
        self.assertEqual(len(batches[1]), 10)
        self.assertEqual(len(batches[2]), 5)
    
    def test_extension_scoring(self):
        """Test file extension scoring"""
        files = [
            Path('script.sh'),    # Shell scripts are risky
            Path('code.py'),      # Python
            Path('page.php'),     # PHP historically risky
            Path('safe.rs'),      # Rust is safer
            Path('doc.md'),       # Documentation
        ]
        
        scores = {}
        for file in files:
            score, _, _ = SmartFilePrioritizer._calculate_priority(file)
            scores[file.suffix] = score
        
        # Verify relative scoring
        self.assertGreater(scores['.sh'], scores['.rs'])
        self.assertGreater(scores['.php'], scores['.py'])
        self.assertEqual(scores['.md'], 0)  # No score for docs
    
    def test_filter_critical_files(self):
        """Test filtering to only critical files"""
        files = [
            Path('main.py'),
            Path('handler.py'),
            Path('utils.py'),
            Path('test.py'),
            Path('.env'),
            Path('readme.md'),
        ]
        
        critical = SmartFilePrioritizer.filter_critical_files(files)
        
        # Should only include critical files
        critical_names = [f.name for f in critical]
        self.assertIn('main.py', critical_names)
        self.assertIn('handler.py', critical_names)
        self.assertIn('.env', critical_names)
        
        # Should exclude non-critical
        self.assertNotIn('utils.py', critical_names)
        self.assertNotIn('test.py', critical_names)
        self.assertNotIn('readme.md', critical_names)


def run_tests():
    """Run all file prioritizer tests"""
    print("\n" + "="*60)
    print("FILE PRIORITIZER TEST SUITE")
    print("="*60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test class
    suite.addTests(loader.loadTestsFromTestCase(TestFilePrioritizer))
    
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