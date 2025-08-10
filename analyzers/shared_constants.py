#!/usr/bin/env python3
"""
Shared Constants and Utilities for MCP Security Analyzers
Centralizes commonly used constants and patterns
"""

# File Extensions by Category
CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rb', '.java', 
    '.cpp', '.c', '.cs', '.php', '.sh', '.rs', '.swift', '.kt',
    '.scala', '.lua', '.perl', '.r', '.m', '.mm', '.h', '.hpp'
}

CONFIG_EXTENSIONS = {
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.xml', '.properties', '.env'
}

IMPORTANT_FILES = {
    'mcp.json', 'package.json', 'requirements.txt', 'go.mod', 
    'cargo.toml', 'Gemfile', 'pom.xml', 'build.gradle', 
    'composer.json', 'setup.py', 'setup.cfg', 'pyproject.toml',
    '.env', '.env.local', '.env.production', 'Dockerfile',
    'docker-compose.yml', 'Makefile', 'CMakeLists.txt'
}

# Directories to Skip during scanning
SKIP_DIRECTORIES = {
    'dist', 'build', 'node_modules', 'vendor', 'venv', '.venv',
    'target', 'out', 'bin', 'coverage', '.next', '.nuxt',
    'public', 'static', 'assets', '__pycache__', '.pytest_cache',
    'htmlcov', '.tox', 'wheels', 'eggs', '.eggs', 'sdist',
    'lib', 'lib64', 'parts', 'include', 'share',
    '.git', '.svn', '.hg', '.bzr', '_darcs', '.idea', '.vscode'
}

# LLM Analysis Skip Patterns - Files to skip for LLM/error reporting (but still scan)
LLM_SKIP_PATTERNS = [
    # Test files
    '_test.go', '_test.py', '_test.js', '_test.ts', '_test.rb', '_test.java',
    '.test.js', '.test.ts', '.spec.js', '.spec.ts', '.test.py',
    '/test/', '/tests/', '/testing/', '/__tests__/', 
    '/e2e/', '/integration/', '/fixtures/', '/spec/', '/specs/',
    # Package/Library directories
    '/pkg/',          # Go packages
    '/vendor/',       # Go/PHP/Ruby vendor
    '/node_modules/', # JavaScript/TypeScript
    '/lib/',          # Common library directory
    '/libs/',         # Alternative library directory
    '/packages/',     # Monorepo packages
    '/third_party/',  # Third-party code
    '/external/',     # External dependencies
    '/deps/',         # Dependencies
    '/dependencies/', # Dependencies
    # Language-specific package directories
    '/site-packages/',    # Python packages
    '/dist-packages/',    # Python dist packages
    '/gems/',            # Ruby gems
    '/bower_components/', # Legacy JS
    '/jspm_packages/',   # JSPM packages
    '/.bundle/',         # Ruby bundle
    '/target/',          # Java/Rust build
    '/build/',           # Build output
    '/dist/',            # Distribution files
    '/out/',             # Output directory
    '/.cargo/',          # Rust cargo
    '/Pods/',            # iOS CocoaPods
    '/.gradle/',         # Gradle cache
    '/.m2/',             # Maven cache
    '/.ivy2/',           # Ivy cache
    '/.sbt/',            # SBT cache
    '/composer/',        # PHP Composer
    '/vendor/',          # PHP vendor
]

def should_skip_for_llm(file_path: str) -> bool:
    """Check if file should be skipped for LLM analysis and error reporting"""
    file_lower = file_path.lower()
    return any(pattern in file_lower for pattern in LLM_SKIP_PATTERNS)

# Binary and Non-Code Extensions to Skip
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
    '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.xz',
    '.exe', '.dll', '.so', '.dylib', '.a', '.lib', '.o', '.obj',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.mkv',
    '.db', '.sqlite', '.sqlite3', '.lock', '.log',
    '.min.js', '.min.css', '.map'
}

# Security-sensitive files
SECURITY_FILES = {
    '.env', '.env.local', '.env.production', '.env.development',
    '.git-credentials', '.netrc', '.pgpass', '.my.cnf',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    '.aws/credentials', '.aws/config',
    '.docker/config.json', '.kube/config',
    'credentials.xml', 'secrets.yml', 'secrets.yaml',
    'key.pem', 'cert.pem', 'private.key', 'public.key'
}

# Language Detection Map
LANGUAGE_MAP = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.mjs': 'JavaScript',
    '.cjs': 'JavaScript', 
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    '.jsx': 'JavaScript',
    '.rb': 'Ruby',
    '.go': 'Go',
    '.rs': 'Rust',
    '.java': 'Java',
    '.cpp': 'C++',
    '.cxx': 'C++',
    '.cc': 'C++',
    '.c': 'C',
    '.h': 'C/C++',
    '.hpp': 'C++',
    '.cs': 'C#',
    '.php': 'PHP',
    '.sh': 'Shell',
    '.bash': 'Bash',
    '.ps1': 'PowerShell',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.scala': 'Scala',
    '.lua': 'Lua',
    '.pl': 'Perl',
    '.r': 'R',
    '.m': 'Objective-C',
    '.mm': 'Objective-C++',
    '.dart': 'Dart',
    '.ex': 'Elixir',
    '.exs': 'Elixir',
    '.clj': 'Clojure',
    '.hs': 'Haskell',
    '.ml': 'OCaml',
    '.nim': 'Nim',
    '.zig': 'Zig',
    '.v': 'V',
    '.jl': 'Julia'
}

# Size Limits
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_ANALYSIS_SIZE = 500 * 1024   # 500KB for deep analysis
MAX_ENTROPY_SIZE = 100 * 1024    # 100KB for entropy calculation

# Severity Mappings
SEVERITY_WEIGHTS = {
    'CRITICAL': 1.0,
    'HIGH': 0.7,
    'MEDIUM': 0.4,
    'LOW': 0.2,
    'INFO': 0.1
}

# Risk Score Thresholds
RISK_THRESHOLDS = {
    'CRITICAL': 0.8,
    'HIGH': 0.6,
    'MEDIUM': 0.4,
    'LOW': 0.2,
    'MINIMAL': 0.0
}

def should_skip_file(file_path, check_security=False):
    """
    Determine if a file should be skipped during scanning
    
    Args:
        file_path: Path object or string path to check
        check_security: If True, don't skip security-sensitive files
    
    Returns:
        bool: True if file should be skipped
    """
    from pathlib import Path
    
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    # Check directory components
    path_parts = set(p.lower() for p in file_path.parts)
    if any(skip_dir in path_parts for skip_dir in SKIP_DIRECTORIES):
        return True
    
    # Check hidden files (except .env)
    if file_path.name.startswith('.') and file_path.name not in SECURITY_FILES:
        return True
    
    # Check file size
    try:
        if file_path.is_file() and file_path.stat().st_size > MAX_FILE_SIZE:
            return True
    except:
        pass
    
    # Check extensions
    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    
    # If checking security, don't skip security files
    if check_security and file_path.name in SECURITY_FILES:
        return False
    
    return False

def is_code_file(file_path):
    """Check if a file is a code file"""
    from pathlib import Path
    
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    return file_path.suffix.lower() in CODE_EXTENSIONS

def is_config_file(file_path):
    """Check if a file is a configuration file"""
    from pathlib import Path
    
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    return (file_path.suffix.lower() in CONFIG_EXTENSIONS or 
            file_path.name in IMPORTANT_FILES)

def detect_language(file_path):
    """Detect programming language from file extension"""
    from pathlib import Path
    
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    return LANGUAGE_MAP.get(file_path.suffix.lower())

def get_scannable_files(repo_path, include_configs=True, include_security=True):
    """
    Get list of files that should be scanned
    
    Args:
        repo_path: Path to repository
        include_configs: Include configuration files
        include_security: Include security-sensitive files
    
    Returns:
        List of Path objects
    """
    from pathlib import Path
    
    repo_path = Path(repo_path)
    scannable_files = []
    
    for file_path in repo_path.rglob("*"):
        if not file_path.is_file():
            continue
        
        if should_skip_file(file_path, check_security=include_security):
            continue
        
        # Include based on type
        if is_code_file(file_path):
            scannable_files.append(file_path)
        elif include_configs and is_config_file(file_path):
            scannable_files.append(file_path)
        elif include_security and file_path.name in SECURITY_FILES:
            scannable_files.append(file_path)
    
    return scannable_files

def calculate_severity_score(severity_string):
    """Convert severity string to numeric score"""
    return SEVERITY_WEIGHTS.get(severity_string.upper(), 0.1)

def determine_risk_level(risk_score):
    """Determine risk level from numeric score"""
    if risk_score >= RISK_THRESHOLDS['CRITICAL']:
        return 'CRITICAL'
    elif risk_score >= RISK_THRESHOLDS['HIGH']:
        return 'HIGH'
    elif risk_score >= RISK_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    elif risk_score >= RISK_THRESHOLDS['LOW']:
        return 'LOW'
    else:
        return 'MINIMAL'