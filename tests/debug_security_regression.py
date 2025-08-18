#!/usr/bin/env python3
"""
Debug the security regression in pattern detection
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.unified_pattern_registry import pattern_registry

with tempfile.TemporaryDirectory() as td:
    temp_path = Path(td)
    
    code = """#!/usr/bin/env python3
# Command injection
exec(user_input)
eval(dangerous_code)

# Credential theft
password = "hardcoded123"
api_key = os.environ['AWS_SECRET_ACCESS_KEY']

# Path traversal
with open("../../etc/passwd") as f:
    data = f.read()

# Data exfiltration
import requests
requests.post(url + secret_data)
"""
    
    test_file = temp_path / "malicious.py"
    test_file.write_text(code)
    
    print(f"Test file: {test_file}")
    print(f"File exists: {test_file.exists()}")
    print(f"File size: {test_file.stat().st_size}")
    print(f"File extension: {test_file.suffix}")
    
    # Test pattern registry directly
    print("\n=== PATTERN REGISTRY ===")
    matches = pattern_registry.scan_content(code)
    print(f"Pattern matches: {len(matches)}")
    for i, match in enumerate(matches):
        print(f"  {i+1}. {match.category}: {match.pattern_name} (line {match.line_number})")
    
    # Test full analyzer
    print("\n=== FULL ANALYZER ===")
    analyzer = ComprehensiveMCPAnalyzer(verbose=True, profile="development")
    report = analyzer.analyze_repository(str(temp_path))
    
    print(f"Analyzer threats: {len(report.threats_found)}")
    print(f"Files scanned: {report.total_files_scanned}")
    print(f"Fingerprints: {len(report.file_fingerprints)}")
    
    if report.threats_found:
        print("Threats found:")
        for i, threat in enumerate(report.threats_found):
            print(f"  {i+1}. {threat.attack_vector.value}: {threat.description}")
    else:
        print("NO THREATS FOUND BY ANALYZER!")
        
    print(f"\nFile fingerprints: {list(report.file_fingerprints.keys())}")