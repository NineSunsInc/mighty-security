#!/usr/bin/env python3
"""
Critical Fingerprinting Integrity Test
Ensures parallel processing maintains exact same fingerprints as sequential
"""

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


def test_fingerprint_integrity():
    """Test that fingerprints are identical between sequential and parallel"""

    print("\n" + "="*70)
    print("🔒 CRITICAL FINGERPRINTING INTEGRITY TEST")
    print("="*70)
    print("This ensures parallel processing maintains exact same file fingerprints")
    print("as sequential processing - critical for security verification")

    with tempfile.TemporaryDirectory() as td:
        test_dir = Path(td)

        # Create test files with known content
        test_files = []
        for i in range(10):
            file_path = test_dir / f"test_{i}.py"
            padding = 'x' * (100 + i)
            content = f"""#!/usr/bin/env python3
# Test file {i}
import os
import subprocess

def dangerous_function_{i}():
    exec("print('test {i}')")
    os.system("echo test {i}")
    password = "secret{i}"
    
    # File content 
    data = "{padding}"
    return data

if __name__ == "__main__":
    dangerous_function_{i}()
"""
            file_path.write_text(content)
            test_files.append(file_path)

            # Calculate expected fingerprints manually
            content_bytes = content.encode('utf-8')
            expected_sha512 = hashlib.sha512(content_bytes).hexdigest()
            expected_sha3_512 = hashlib.sha3_512(content_bytes).hexdigest()

            print(f"   📁 Created test_{i}.py ({len(content)} bytes)")
            print(f"      Expected SHA512: {expected_sha512[:16]}...")

        print(f"\n✅ Created {len(test_files)} test files")

        # Test sequential processing
        print("\n🔄 Testing Sequential Processing...")
        seq_analyzer = ComprehensiveMCPAnalyzer(
            verbose=False,
            enable_parallel=False,
            use_cache=False,
            profile="development"  # Include all files
        )

        seq_report = seq_analyzer.analyze_repository(str(test_dir))
        seq_fingerprints = seq_report.file_fingerprints

        print(f"   ✅ Sequential: {len(seq_fingerprints)} fingerprints generated")

        # Test parallel processing
        print("\n⚡ Testing Parallel Processing...")
        par_analyzer = ComprehensiveMCPAnalyzer(
            verbose=False,
            enable_parallel=True,
            max_workers=4,
            use_cache=False,
            profile="development"  # Include all files
        )

        par_report = par_analyzer.analyze_repository(str(test_dir))
        par_fingerprints = par_report.file_fingerprints

        print(f"   ✅ Parallel: {len(par_fingerprints)} fingerprints generated")

        # Critical comparison
        print("\n🔍 Comparing Fingerprints...")

        all_match = True
        files_checked = 0

        for file_path in seq_fingerprints.keys():
            if file_path not in par_fingerprints:
                print(f"   ❌ MISSING in parallel: {file_path}")
                all_match = False
                continue

            seq_fp = seq_fingerprints[file_path]
            par_fp = par_fingerprints[file_path]

            files_checked += 1

            # Check SHA512
            if seq_fp.get('sha512') != par_fp.get('sha512'):
                print(f"   ❌ SHA512 MISMATCH for {file_path}")
                print(f"      Sequential: {seq_fp.get('sha512', 'MISSING')}")
                print(f"      Parallel:   {par_fp.get('sha512', 'MISSING')}")
                all_match = False
                continue

            # Check SHA3-512
            if seq_fp.get('sha3_512') != par_fp.get('sha3_512'):
                print(f"   ❌ SHA3-512 MISMATCH for {file_path}")
                print(f"      Sequential: {seq_fp.get('sha3_512', 'MISSING')}")
                print(f"      Parallel:   {par_fp.get('sha3_512', 'MISSING')}")
                all_match = False
                continue

            # Check file size
            if seq_fp.get('size') != par_fp.get('size'):
                print(f"   ❌ SIZE MISMATCH for {file_path}")
                print(f"      Sequential: {seq_fp.get('size')} bytes")
                print(f"      Parallel:   {par_fp.get('size')} bytes")
                all_match = False
                continue

            # Check entropy (allow small differences due to floating point)
            seq_entropy = seq_fp.get('entropy', 0)
            par_entropy = par_fp.get('entropy', 0)
            if abs(seq_entropy - par_entropy) > 0.001:
                print(f"   ❌ ENTROPY MISMATCH for {file_path}")
                print(f"      Sequential: {seq_entropy}")
                print(f"      Parallel:   {par_entropy}")
                all_match = False
                continue

            print(f"   ✅ {file_path}: ALL fingerprints match")

        # Check for extra files in parallel
        for file_path in par_fingerprints.keys():
            if file_path not in seq_fingerprints:
                print(f"   ❌ EXTRA in parallel: {file_path}")
                all_match = False

        # Final validation
        print("\n📊 Validation Results:")
        print(f"   Files checked: {files_checked}")
        print(f"   Sequential fingerprints: {len(seq_fingerprints)}")
        print(f"   Parallel fingerprints: {len(par_fingerprints)}")

        if all_match and files_checked > 0:
            print("\n✅ FINGERPRINT INTEGRITY VERIFIED!")
            print("🔒 Parallel processing maintains EXACT same fingerprints")
            print("   - SHA512 hashes: ✅ Perfect match")
            print("   - SHA3-512 hashes: ✅ Perfect match")
            print("   - File sizes: ✅ Perfect match")
            print("   - Entropy values: ✅ Perfect match")
            return True
        else:
            print("\n❌ FINGERPRINT INTEGRITY COMPROMISED!")
            print("🚨 Parallel processing produces different fingerprints")
            print("   This is a CRITICAL SECURITY ISSUE!")
            return False


def test_merkle_root_consistency():
    """Test that merkle root calculation is consistent"""

    print("\n" + "="*70)
    print("🌳 MERKLE ROOT CONSISTENCY TEST")
    print("="*70)

    with tempfile.TemporaryDirectory() as td:
        test_dir = Path(td)

        # Create multiple test files
        for i in range(5):
            file_path = test_dir / f"file_{i}.py"
            file_path.write_text(f"# File {i}\nexec('test {i}')")

        # Sequential
        seq_analyzer = ComprehensiveMCPAnalyzer(verbose=False, enable_parallel=False, use_cache=False, profile="development")
        seq_report = seq_analyzer.analyze_repository(str(test_dir))
        seq_merkle = seq_report.merkle_root

        # Parallel
        par_analyzer = ComprehensiveMCPAnalyzer(verbose=False, enable_parallel=True, use_cache=False, profile="development")
        par_report = par_analyzer.analyze_repository(str(test_dir))
        par_merkle = par_report.merkle_root

        print(f"Sequential Merkle Root: {seq_merkle}")
        print(f"Parallel Merkle Root:   {par_merkle}")

        if seq_merkle == par_merkle:
            print("✅ Merkle root consistency verified")
            return True
        else:
            print("❌ Merkle root INCONSISTENCY detected!")
            return False


if __name__ == "__main__":
    print("🔒 CRITICAL FINGERPRINT INTEGRITY AUDIT")
    print("This test ensures parallel processing doesn't compromise security")

    integrity_ok = test_fingerprint_integrity()
    merkle_ok = test_merkle_root_consistency()

    print("\n" + "="*70)
    print("FINAL SECURITY AUDIT RESULTS")
    print("="*70)

    if integrity_ok and merkle_ok:
        print("\n🎉 ALL FINGERPRINTING SECURITY CHECKS PASSED!")
        print("✅ Parallel processing is SAFE for production use")
        print("✅ File integrity verification is maintained")
        print("✅ Security guarantees are preserved")
        sys.exit(0)
    else:
        print("\n🚨 FINGERPRINTING SECURITY FAILURE!")
        print("❌ DO NOT USE PARALLEL PROCESSING IN PRODUCTION")
        print("❌ Security integrity is COMPROMISED")
        if not integrity_ok:
            print("❌ File fingerprints don't match")
        if not merkle_ok:
            print("❌ Merkle root calculation inconsistent")
        sys.exit(1)
