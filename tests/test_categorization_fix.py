#!/usr/bin/env python3
"""
Test to verify attack vector categorization is working correctly
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.comprehensive.models import AttackVector


def test_categorization():
    """Test that each threat type is correctly categorized"""
    
    print("\n" + "="*70)
    print("🔍 ATTACK VECTOR CATEGORIZATION TEST")
    print("="*70)
    
    test_cases = [
        # (code, expected_attack_vector, description)
        ("exec(user_input)", AttackVector.COMMAND_INJECTION, "Command injection"),
        ("eval(data)", AttackVector.COMMAND_INJECTION, "Eval injection"),
        ("os.system(cmd)", AttackVector.COMMAND_INJECTION, "OS command injection"),
        ("subprocess.run(cmd, shell=True)", AttackVector.COMMAND_INJECTION, "Subprocess with shell"),
        
        ("password = 'secret123'", AttackVector.CREDENTIAL_THEFT, "Hardcoded password"),
        ("api_key = 'sk-1234567890'", AttackVector.CREDENTIAL_THEFT, "Hardcoded API key"),
        ("aws_key = os.environ.get('AWS_SECRET_ACCESS_KEY')", AttackVector.CREDENTIAL_THEFT, "AWS key access"),
        ("token = 'ghp_abcdef123456'", AttackVector.CREDENTIAL_THEFT, "Hardcoded token"),
        
        ("open('../../etc/passwd')", AttackVector.PATH_TRAVERSAL, "Path traversal"),
        ("path = '../../../etc/shadow'", AttackVector.PATH_TRAVERSAL, "Shadow file access"),
        ("os.path.join(base, '../' + user_input)", AttackVector.PATH_TRAVERSAL, "Path join traversal"),
        
        ("requests.get(url + user_input)", AttackVector.SSRF, "SSRF vulnerability"),
        ("urllib.urlopen('http://169.254.169.254')", AttackVector.SSRF, "AWS metadata access"),
        
        ("pickle.loads(data)", AttackVector.UNSAFE_DESERIALIZATION, "Pickle loads"),
        ("yaml.load(data)", AttackVector.UNSAFE_DESERIALIZATION, "Unsafe YAML load"),
    ]
    
    all_passed = True
    results = []
    
    with tempfile.TemporaryDirectory() as td:
        analyzer = ComprehensiveMCPAnalyzer(verbose=False)
        
        for code, expected_vector, description in test_cases:
            # Create test file
            test_file = Path(td) / "test.py"
            test_file.write_text(f"import os\nimport subprocess\nimport requests\nimport pickle\nimport yaml\n\n{code}")
            
            # Analyze
            report = analyzer.analyze_repository(str(td))
            
            # Check categorization
            found_vectors = set()
            for threat in report.threats_found:
                # Handle both enum and string values
                if isinstance(threat.attack_vector, AttackVector):
                    found_vectors.add(threat.attack_vector)
                else:
                    # Try to convert string to enum for comparison
                    for av in AttackVector:
                        if str(threat.attack_vector) == str(av) or threat.attack_vector == av.value:
                            found_vectors.add(av)
                            break
            
            if expected_vector in found_vectors:
                print(f"✅ {description:30} -> {expected_vector.value}")
                results.append((description, True, expected_vector.value))
            else:
                # Show what was actually found
                found_names = [v.value if isinstance(v, AttackVector) else str(v) for v in found_vectors]
                print(f"❌ {description:30} -> Expected: {expected_vector.value}, Got: {found_names}")
                results.append((description, False, f"Expected {expected_vector.value}"))
                all_passed = False
    
    # Summary
    print("\n" + "="*70)
    print("CATEGORIZATION TEST RESULTS")
    print("="*70)
    
    passed_count = sum(1 for _, passed, _ in results if passed)
    total_count = len(results)
    
    print(f"\nPassed: {passed_count}/{total_count} tests")
    
    if all_passed:
        print("\n✅ ALL CATEGORIZATION TESTS PASSED!")
        print("Attack vectors are correctly categorized.")
    else:
        print("\n❌ SOME CATEGORIZATION TESTS FAILED")
        print("Review the failed tests above.")
    
    return all_passed


def test_multiple_threats_in_one_file():
    """Test that multiple threat types in one file are all correctly categorized"""
    
    print("\n" + "="*70)
    print("🔍 MULTIPLE THREATS IN ONE FILE TEST")
    print("="*70)
    
    test_code = """
import os
import subprocess
import requests
import pickle

# Command injection threats
exec(user_input)
os.system(command)

# Credential theft threats  
password = "admin123"
api_key = "sk-secret-key-123"
aws = os.environ.get('AWS_SECRET_ACCESS_KEY')

# Path traversal threats
with open("../../etc/passwd") as f:
    data = f.read()

# SSRF threats
requests.get(base_url + user_path)

# Unsafe deserialization
pickle.loads(untrusted_data)
"""
    
    with tempfile.TemporaryDirectory() as td:
        test_file = Path(td) / "multi_threat.py"
        test_file.write_text(test_code)
        
        analyzer = ComprehensiveMCPAnalyzer(verbose=False)
        report = analyzer.analyze_repository(str(td))
        
        # Count threats by category
        threat_counts = {}
        for threat in report.threats_found:
            vector = threat.attack_vector
            # Normalize to enum if string
            if not isinstance(vector, AttackVector):
                for av in AttackVector:
                    if str(vector) == str(av) or vector == av.value:
                        vector = av
                        break
            if vector not in threat_counts:
                threat_counts[vector] = 0
            threat_counts[vector] += 1
        
        print(f"\nTotal threats found: {len(report.threats_found)}")
        print("\nThreats by category:")
        
        expected_categories = [
            AttackVector.COMMAND_INJECTION,
            AttackVector.CREDENTIAL_THEFT,
            AttackVector.PATH_TRAVERSAL,
            AttackVector.SSRF,
            AttackVector.UNSAFE_DESERIALIZATION
        ]
        
        all_found = True
        for category in expected_categories:
            count = threat_counts.get(category, 0)
            if count > 0:
                print(f"  ✅ {category.value:25} : {count} threats")
            else:
                print(f"  ❌ {category.value:25} : NOT DETECTED")
                all_found = False
        
        # Show any unexpected categories
        for category, count in threat_counts.items():
            if category not in expected_categories:
                cat_name = category.value if isinstance(category, AttackVector) else str(category)
                print(f"  ⚠️  {cat_name:25} : {count} threats (unexpected)")
        
        if all_found:
            print("\n✅ All expected threat categories detected!")
        else:
            print("\n❌ Some threat categories were not detected")
        
        return all_found


if __name__ == "__main__":
    print("Testing attack vector categorization fixes...")
    
    # Run individual categorization tests
    test1_passed = test_categorization()
    
    # Run multiple threats test
    test2_passed = test_multiple_threats_in_one_file()
    
    # Final summary
    print("\n" + "="*70)
    print("FINAL TEST SUMMARY")
    print("="*70)
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED!")
        print("Attack vector categorization is working correctly.")
        sys.exit(0)
    else:
        print("\n⚠️ Some tests failed. Please review the output above.")
        sys.exit(1)