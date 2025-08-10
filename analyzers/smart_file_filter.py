#!/usr/bin/env python3
"""
Smart file filtering for MCP Security Analyzer
Excludes unnecessary directories and focuses on actual source code
"""

# Directories to ALWAYS skip
SKIP_DIRS = {
    # Python virtual environments
    'venv', '.venv', 'env', '.env', 'virtualenv',
    'virtualenvs', '__pycache__', '.pytest_cache',
    'site-packages', 'dist-packages',
    
    # Node modules
    'node_modules', '.npm', 'bower_components',
    
    # Build/dist directories  
    'build', 'dist', 'target', 'out', 'bin',
    '.build', '_build', 'cmake-build-debug',
    
    # Package managers
    '.yarn', '.pnpm', 'vendor',
    
    # IDE/Editor
    '.idea', '.vscode', '.vs', '.eclipse',
    
    # Version control
    '.git', '.svn', '.hg', '.bzr',
    
    # Cache directories
    '.cache', 'cache', 'Caches', '.mypy_cache',
    '.tox', '.nox', '.hypothesis',
    
    # Documentation (usually safe)
    'docs', 'documentation', 'doc',
    
    # Test coverage
    'coverage', '.coverage', 'htmlcov',
    
    # OS specific
    '.DS_Store', 'Thumbs.db',
    
    # Library/Framework specific
    'Library', '.gradle', '.m2', 'pods',
    
    # Temporary
    'tmp', 'temp', '.tmp', '.temp'
}

# File extensions to analyze
ANALYZE_EXTENSIONS = {
    '.py',    # Python
    '.js',    # JavaScript
    '.ts',    # TypeScript
    '.jsx',   # React
    '.tsx',   # TypeScript React
    '.java',  # Java
    '.kt',    # Kotlin
    '.go',    # Go
    '.rs',    # Rust
    '.rb',    # Ruby
    '.php',   # PHP
    '.cs',    # C#
    '.cpp',   # C++
    '.c',     # C
    '.sh',    # Shell scripts
    '.bash',  # Bash scripts
    '.yaml',  # YAML configs
    '.yml',   # YAML configs
    '.json',  # JSON configs (esp. mcp.json, package.json)
}

# Files to always analyze regardless of extension
ALWAYS_ANALYZE = {
    'mcp.json',
    'package.json',
    'manifest.json',
    'config.json',
    'settings.json',
    '.env',  # Check for exposed secrets
    'Dockerfile',
    'docker-compose.yml',
    'requirements.txt',  # Check for malicious packages
    'Gemfile',
    'Cargo.toml',
    'go.mod'
}

def should_analyze_file(file_path):
    """
    Determine if a file should be analyzed
    """
    from pathlib import Path
    
    path = Path(file_path)
    
    # Check if any parent directory should be skipped
    for parent in path.parents:
        if parent.name in SKIP_DIRS:
            return False
    
    # Check if the immediate parent is a skip directory
    if path.parent.name in SKIP_DIRS:
        return False
    
    # Always analyze specific important files
    if path.name in ALWAYS_ANALYZE:
        return True
    
    # Check file extension
    return path.suffix.lower() in ANALYZE_EXTENSIONS

def get_files_to_scan(root_path):
    """
    Get list of files to scan, excluding unnecessary directories
    """
    from pathlib import Path
    
    root = Path(root_path)
    files_to_scan = []
    
    def should_skip_dir(dir_path):
        """Check if directory should be skipped"""
        dir_name = dir_path.name
        
        # Skip hidden directories (except .github)
        if dir_name.startswith('.') and dir_name != '.github':
            return True
            
        return dir_name in SKIP_DIRS
    
    # Walk the directory tree
    for item in root.rglob('*'):
        # Skip if any parent is in SKIP_DIRS
        skip = False
        for parent in item.parents:
            if parent != root and should_skip_dir(parent):
                skip = True
                break
        
        if skip:
            continue
            
        # Only process files
        if item.is_file() and should_analyze_file(item):
            files_to_scan.append(item)
    
    return files_to_scan

def print_scan_plan(root_path):
    """
    Print what will be scanned
    """
    from pathlib import Path
    
    files = get_files_to_scan(root_path)
    
    print(f"📁 Scan Plan for: {root_path}")
    print(f"📊 Found {len(files)} files to analyze")
    
    # Group by extension
    by_ext = {}
    for f in files:
        ext = f.suffix or f.name
        if ext not in by_ext:
            by_ext[ext] = []
        by_ext[ext].append(f)
    
    print("\n📈 Files by type:")
    for ext, file_list in sorted(by_ext.items()):
        print(f"  {ext}: {len(file_list)} files")
    
    print("\n✅ Will scan:")
    for f in files[:10]:  # Show first 10
        print(f"  - {f.relative_to(Path(root_path))}")
    
    if len(files) > 10:
        print(f"  ... and {len(files) - 10} more files")
    
    print("\n❌ Will skip:")
    print(f"  - virtualenv directories")
    print(f"  - node_modules")
    print(f"  - build/dist directories")
    print(f"  - cache directories")
    print(f"  - {len(SKIP_DIRS)} total exclusion patterns")
    
    return files

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python smart_file_filter.py <directory>")
        sys.exit(1)
    
    path = sys.argv[1]
    print_scan_plan(path)