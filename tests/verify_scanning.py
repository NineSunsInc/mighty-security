#!/usr/bin/env python3
"""
Verify what files are actually being scanned vs what exists
"""

import os
import sys
from pathlib import Path

def count_all_source_files(root_path):
    """Count ALL source files (including what we might be missing)"""
    root = Path(root_path)
    
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.kt'}
    all_files = []
    scanned_files = []
    skipped_files = []
    
    print(f"🔍 Analyzing: {root_path}\n")
    
    # Count ALL files first
    for ext in extensions:
        for file in root.rglob(f"*{ext}"):
            all_files.append(file)
    
    print(f"📊 Total source files found: {len(all_files)}")
    
    # Group by directory to see what's where
    by_dir = {}
    for file in all_files:
        dir_name = file.parent.name
        if dir_name not in by_dir:
            by_dir[dir_name] = 0
        by_dir[dir_name] += 1
    
    print(f"\n📁 Files by directory:")
    for dir_name, count in sorted(by_dir.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {dir_name}: {count} files")
    
    # Now check what our smart filter would scan
    try:
        from src.analyzers.smart_file_filter import get_files_to_scan, SKIP_DIRS
        smart_files = get_files_to_scan(root_path)
        print(f"\n✅ Smart filter would scan: {len(smart_files)} files")
        
        # Find what we're missing
        smart_paths = set(smart_files)
        all_paths = set(all_files)
        
        missing = all_paths - smart_paths
        
        if missing:
            print(f"\n⚠️  MISSING {len(missing)} source files!")
            print("\nExamples of missed files:")
            for file in list(missing)[:10]:
                rel_path = file.relative_to(root)
                print(f"  ❌ {rel_path}")
                
                # Check why it was skipped
                for parent in file.parents:
                    if parent.name in SKIP_DIRS:
                        print(f"     → Skipped because parent dir '{parent.name}' is in SKIP_DIRS")
                        break
        else:
            print("\n✅ All source files will be scanned!")
            
    except Exception as e:
        print(f"\n❌ Error with smart filter: {e}")
    
    # Show what the enhanced analyzer actually scans
    print("\n" + "="*60)
    print("📋 Enhanced Analyzer Behavior:")
    print("="*60)
    
    # The analyzer limits to certain extensions
    analyzer_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.go', '.rs', '.java', '.rb'}
    
    analyzer_files = [f for f in all_files if f.suffix in analyzer_extensions]
    print(f"Files matching analyzer extensions: {len(analyzer_files)}")
    
    # Check depth limit (analyzer skips > 5 levels deep)
    deep_files = [f for f in analyzer_files if len(f.relative_to(root).parts) > 5]
    if deep_files:
        print(f"Files too deep (>5 levels): {len(deep_files)} - WILL BE SKIPPED")
        
    return all_files

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_scanning.py <directory>")
        sys.exit(1)
    
    path = sys.argv[1]
    count_all_source_files(path)