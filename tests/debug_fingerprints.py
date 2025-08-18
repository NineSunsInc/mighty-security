#!/usr/bin/env python3
"""
Debug fingerprinting issue
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer

with tempfile.TemporaryDirectory() as td:
    test_dir = Path(td)
    
    # Create a simple test file
    test_file = test_dir / "test.py"
    test_file.write_text("exec('malicious code')")
    
    print(f"Created test file: {test_file}")
    print(f"File exists: {test_file.exists()}")
    print(f"File size: {test_file.stat().st_size}")
    print(f"Content: {test_file.read_text()}")
    
    # Test sequential
    print("\n=== SEQUENTIAL ===")
    analyzer = ComprehensiveMCPAnalyzer(verbose=True, enable_parallel=False, use_cache=False)
    report = analyzer.analyze_repository(str(test_dir))
    
    print(f"Threats found: {len(report.threats_found)}")
    print(f"Fingerprints: {len(report.file_fingerprints)}")
    print(f"Files scanned: {report.total_files_scanned}")
    
    print(f"Raw file_fingerprints type: {type(report.file_fingerprints)}")
    print(f"Raw file_fingerprints: {report.file_fingerprints}")
    
    if report.file_fingerprints:
        print("Fingerprint details:")
        for path, fp in report.file_fingerprints.items():
            print(f"  Path: '{path}' (type: {type(path)})")
            print(f"  Fingerprint: {fp} (type: {type(fp)})")
    else:
        print("NO FINGERPRINTS GENERATED!")
        
    # Test parallel too
    print("\n=== PARALLEL ===")
    analyzer2 = ComprehensiveMCPAnalyzer(verbose=False, enable_parallel=True, use_cache=False)
    report2 = analyzer2.analyze_repository(str(test_dir))
    
    print(f"Parallel fingerprints: {len(report2.file_fingerprints)}")
    print(f"Parallel raw: {report2.file_fingerprints}")