"""
Centralized configuration for all MCP Security Suite analyzers
Single source of truth for all configuration values
"""

import os
from pathlib import Path
from typing import Any


class AnalyzerConfig:
    """
    Centralized configuration for all analyzers.
    
    This replaces scattered constants and try/except imports throughout the codebase.
    All configuration values should be accessed through this class.
    """

    # ========================================================================
    # File Size Limits
    # ========================================================================
    MAX_FILE_SIZE = 5 * 1024 * 1024          # 5MB - Maximum file size to analyze
    MAX_ANALYSIS_SIZE = 500 * 1024           # 500KB - Maximum size for deep analysis
    MAX_ENTROPY_SIZE = 100 * 1024            # 100KB - Maximum size for entropy calculation
    MAX_LLM_CONTEXT_SIZE = 50 * 1024         # 50KB - Maximum size for LLM analysis
    LARGE_FILE_THRESHOLD = 1024 * 1024       # 1MB - Threshold for considering a file "large"

    # ========================================================================
    # Performance Settings
    # ========================================================================
    DEFAULT_MAX_WORKERS = min(os.cpu_count() or 1, 8)  # Max parallel workers
    BATCH_SIZE = 10                          # Default batch size for parallel processing
    CACHE_SIZE = 200                         # Maximum AST cache size
    PATTERN_CACHE_SIZE = 1000               # Maximum compiled pattern cache size
    MIN_FILES_FOR_PARALLEL = 10             # Minimum files to trigger parallel processing

    # ========================================================================
    # Detection Thresholds
    # ========================================================================
    CRITICAL_THREAT_THRESHOLD = 3           # Number of critical threats to trigger early exit
    HIGH_CONFIDENCE_THRESHOLD = 0.8         # Confidence threshold for high confidence
    MEDIUM_CONFIDENCE_THRESHOLD = 0.5       # Confidence threshold for medium confidence
    LOW_CONFIDENCE_THRESHOLD = 0.3          # Confidence threshold for low confidence
    MIN_THREAT_SCORE = 0.1                  # Minimum threat score to report

    # ========================================================================
    # Threat Scoring Weights
    # ========================================================================
    CRITICAL_SEVERITY_WEIGHT = 1.0          # Weight for critical severity threats
    HIGH_SEVERITY_WEIGHT = 0.7              # Weight for high severity threats
    MEDIUM_SEVERITY_WEIGHT = 0.4            # Weight for medium severity threats
    LOW_SEVERITY_WEIGHT = 0.2               # Weight for low severity threats

    # ========================================================================
    # Timeouts
    # ========================================================================
    FILE_READ_TIMEOUT = 5                   # Seconds - Timeout for reading a single file
    FILE_ANALYSIS_TIMEOUT = 30              # Seconds - Timeout for analyzing a single file
    BATCH_ANALYSIS_TIMEOUT = 60             # Seconds - Timeout for analyzing a batch
    REPO_ANALYSIS_TIMEOUT = 600             # Seconds - Timeout for analyzing entire repo
    LLM_REQUEST_TIMEOUT = 30                # Seconds - Timeout for LLM requests

    # ========================================================================
    # Cache Settings
    # ========================================================================
    CACHE_ENABLED = True                    # Enable/disable caching globally
    CACHE_TTL = 3600                        # Seconds - Cache time-to-live (1 hour)
    CACHE_DATABASE = "analysis_cache.db"    # Default cache database name
    MAX_CACHE_SIZE_MB = 100                 # Maximum cache database size in MB

    # ========================================================================
    # Logging and Reporting
    # ========================================================================
    LOG_FILE = "mcp_security.log"           # Default log file name
    LOG_LEVEL = os.environ.get("MCP_LOG_LEVEL", "INFO")
    VERBOSE_DEFAULT = False                  # Default verbosity
    REPORT_DIR = "reports"                   # Default report directory
    MAX_LOG_SIZE = 10 * 1024 * 1024        # 10MB - Maximum log file size

    # ========================================================================
    # File Extensions and Patterns
    # ========================================================================
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php',
        '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.kt', '.scala'
    }

    CONFIG_EXTENSIONS = {
        '.json', '.yaml', '.yml', '.toml', '.ini', '.env', '.config'
    }

    SKIP_EXTENSIONS = {
        '.pyc', '.pyo', '.pyd', '.so', '.dll', '.dylib', '.exe',
        '.class', '.jar', '.war', '.ear', '.zip', '.tar', '.gz',
        '.rar', '.7z', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.pdf', '.doc', '.docx', '.xls', '.xlsx'
    }

    SKIP_DIRECTORIES = {
        '__pycache__', 'node_modules', '.git', '.svn', '.hg',
        'venv', '.venv', 'env', '.env', 'virtualenv',
        'dist', 'build', 'target', 'out', 'bin', 'obj',
        '.idea', '.vscode', '.vs', 'vendor', 'packages'
    }

    # ========================================================================
    # Security Files
    # ========================================================================
    SECURITY_FILES = {
        '.env', '.env.local', '.env.production', '.env.development',
        'secrets.json', 'credentials.json', 'config.json',
        'settings.json', 'auth.json', 'api_keys.json'
    }

    MCP_CONFIG_FILES = {
        'mcp.json', 'mcp.yaml', 'mcp.yml', 'manifest.json'
    }

    # ========================================================================
    # Pattern Categories
    # ========================================================================
    PATTERN_CATEGORIES = [
        'command_injection',
        'code_injection',
        'credential_theft',
        'data_exfiltration',
        'path_traversal',
        'ssrf',
        'unsafe_deserialization',
        'prompt_injection',
        'obfuscation',
        'sandbox_escape'
    ]

    # ========================================================================
    # Risk Scoring
    # ========================================================================
    RISK_SCORE_RANGES = {
        'CRITICAL': (0.8, 1.0),
        'HIGH': (0.6, 0.8),
        'MEDIUM': (0.4, 0.6),
        'LOW': (0.2, 0.4),
        'MINIMAL': (0.0, 0.2)
    }

    # ========================================================================
    # Environment Variables
    # ========================================================================
    ENABLE_PARALLEL = os.environ.get("MCP_ENABLE_PARALLEL", "true").lower() == "true"
    ENABLE_CACHE = os.environ.get("MCP_ENABLE_CACHE", "true").lower() == "true"
    ENABLE_LLM = os.environ.get("MCP_ENABLE_LLM", "false").lower() == "true"
    CEREBRAS_API_KEY = os.environ.get("CEREBRAS_API_KEY", "")

    # ========================================================================
    # Development Settings
    # ========================================================================
    DEV_MODE = os.environ.get("MCP_DEV_MODE", "false").lower() == "true"
    DEBUG = os.environ.get("MCP_DEBUG", "false").lower() == "true"
    TEST_MODE = os.environ.get("MCP_TEST_MODE", "false").lower() == "true"

    # ========================================================================
    # Class Methods
    # ========================================================================

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """
        Get configuration value with fallback.
        
        Args:
            key: Configuration key (e.g., 'MAX_FILE_SIZE')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return getattr(cls, key, default)

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        """
        Set configuration value (for testing or runtime override).
        
        Args:
            key: Configuration key
            value: New value
        """
        setattr(cls, key, value)

    @classmethod
    def update(cls, config_dict: dict[str, Any]) -> None:
        """
        Update multiple configuration values.
        
        Args:
            config_dict: Dictionary of configuration updates
        """
        for key, value in config_dict.items():
            cls.set(key, value)

    @classmethod
    def reset(cls) -> None:
        """Reset all configuration to defaults (useful for testing)."""
        # Re-initialize all class variables
        cls.__init__()

    @classmethod
    def to_dict(cls) -> dict[str, Any]:
        """
        Export configuration as dictionary.
        
        Returns:
            Dictionary of all configuration values
        """
        config = {}
        for key in dir(cls):
            if not key.startswith('_') and key.isupper():
                config[key] = getattr(cls, key)
        return config

    @classmethod
    def from_file(cls, config_path: Path) -> None:
        """
        Load configuration from JSON or YAML file.
        
        Args:
            config_path: Path to configuration file
        """
        import json

        if config_path.suffix in ['.yaml', '.yml']:
            try:
                import yaml
                with open(config_path) as f:
                    config = yaml.safe_load(f)
            except ImportError:
                raise ImportError("PyYAML required for YAML config files")
        else:
            with open(config_path) as f:
                config = json.load(f)

        cls.update(config)

    @classmethod
    def validate(cls) -> bool:
        """
        Validate configuration values.
        
        Returns:
            True if configuration is valid
        """
        # Check file size limits make sense
        assert cls.MAX_FILE_SIZE > cls.MAX_ANALYSIS_SIZE
        assert cls.MAX_ANALYSIS_SIZE > cls.MAX_ENTROPY_SIZE

        # Check thresholds are in valid ranges
        assert 0 <= cls.HIGH_CONFIDENCE_THRESHOLD <= 1
        assert 0 <= cls.MEDIUM_CONFIDENCE_THRESHOLD <= 1
        assert 0 <= cls.LOW_CONFIDENCE_THRESHOLD <= 1

        # Check weights are reasonable
        assert 0 <= cls.CRITICAL_SEVERITY_WEIGHT <= 1
        assert 0 <= cls.HIGH_SEVERITY_WEIGHT <= 1
        assert 0 <= cls.MEDIUM_SEVERITY_WEIGHT <= 1
        assert 0 <= cls.LOW_SEVERITY_WEIGHT <= 1

        # Check timeouts are positive
        assert cls.FILE_READ_TIMEOUT > 0
        assert cls.FILE_ANALYSIS_TIMEOUT > 0

        return True


# ============================================================================
# Helper Functions
# ============================================================================

def get_config() -> AnalyzerConfig:
    """Get the global configuration instance."""
    return AnalyzerConfig


def load_config(config_path: Path | None = None) -> AnalyzerConfig:
    """
    Load configuration from file or use defaults.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Configured AnalyzerConfig instance
    """
    config = AnalyzerConfig()

    if config_path and config_path.exists():
        config.from_file(config_path)

    # Check for local config overrides
    local_config = Path("mcp_security.config.json")
    if local_config.exists():
        config.from_file(local_config)

    config.validate()
    return config
