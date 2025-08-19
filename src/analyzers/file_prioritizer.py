"""
Smart File Prioritization for Security Analysis
Analyzes high-risk files first for better threat detection
"""

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FilePriority:
    """Represents a file with its priority score"""
    path: Path
    score: int
    reason: str
    is_critical: bool = False


class SmartFilePrioritizer:
    """
    Prioritize high-risk files for analysis.
    Improves threat detection by analyzing critical files first.
    """

    # File name patterns and their priority scores
    HIGH_PRIORITY_NAMES = {
        'handler': 100,
        'execute': 95,
        'process': 90,
        'run': 85,
        'eval': 100,
        'exec': 100,
        'command': 90,
        'server': 80,
        'api': 75,
        'auth': 85,
        'login': 85,
        'admin': 90,
        'root': 95,
        'sudo': 95,
        'privilege': 90,
        'permission': 80,
        'credential': 95,
        'secret': 95,
        'token': 90,
        'key': 85,
        'password': 90,
        'config': 70,
        'settings': 70,
        'env': 80
    }

    # Entry point files (highest priority)
    ENTRY_POINTS = {
        'main.py', '__main__.py', 'app.py', 'server.py', 'index.js',
        'index.ts', 'main.js', 'main.ts', 'handler.py', 'lambda_function.py',
        'function.py', 'worker.py', 'service.py', '__init__.py'
    }

    # Configuration files (high priority)
    CONFIG_FILES = {
        'mcp.json', 'manifest.json', '.env', '.env.local', '.env.production',
        'config.json', 'config.yaml', 'config.yml', 'settings.json',
        'settings.yaml', 'settings.yml', 'secrets.json', 'secrets.yaml',
        'credentials.json', 'docker-compose.yml', 'dockerfile'
    }

    # MCP-specific patterns
    MCP_PATTERNS = {
        'mcp': 100,
        'context': 70,
        'protocol': 75,
        'model': 70,
        'llm': 75,
        'prompt': 80,
        'agent': 75,
        'tool': 70,
        'function': 75
    }

    # File extensions and their base scores
    EXTENSION_SCORES = {
        '.py': 30,
        '.js': 30,
        '.ts': 30,
        '.jsx': 25,
        '.tsx': 25,
        '.java': 25,
        '.go': 25,
        '.rb': 25,
        '.php': 35,  # Higher risk historically
        '.sh': 40,   # Shell scripts are risky
        '.bash': 40,
        '.ps1': 40,  # PowerShell
        '.yml': 20,
        '.yaml': 20,
        '.json': 15,
        '.xml': 15,
        '.sql': 35,  # Database queries
        '.c': 30,
        '.cpp': 30,
        '.rs': 20,   # Rust is safer
        '.swift': 20,
        '.kt': 20,
        '.scala': 20
    }

    # Low priority patterns
    LOW_PRIORITY_PATTERNS = {
        'test': -50,
        'spec': -50,
        'example': -40,
        'demo': -40,
        'sample': -40,
        'mock': -45,
        'stub': -45,
        'fixture': -45,
        '__pycache__': -100,
        'node_modules': -100,
        'vendor': -80,
        'dist': -70,
        'build': -70,
        '.git': -100,
        'docs': -30,
        'documentation': -30,
        'readme': -40,
        'license': -50,
        'changelog': -50,
        'contributing': -50
    }

    @staticmethod
    def prioritize_files(files: list[Path],
                        user_preferences: dict | None = None) -> list[Path]:
        """
        Sort files by threat likelihood
        
        Args:
            files: List of file paths to prioritize
            user_preferences: Optional user preferences for prioritization
            
        Returns:
            List of files sorted by priority (highest first)
        """
        prioritized = []

        for file_path in files:
            score, reason, is_critical = SmartFilePrioritizer._calculate_priority(
                file_path, user_preferences
            )
            prioritized.append(FilePriority(file_path, score, reason, is_critical))

        # Sort by score (highest first)
        prioritized.sort(key=lambda x: x.score, reverse=True)

        # Log summary
        critical_files = [p for p in prioritized if p.is_critical]
        if critical_files:
            logger.info(f"Found {len(critical_files)} critical priority files")
            for cf in critical_files[:5]:  # Log first 5
                logger.debug(f"Critical: {cf.path.name} (score: {cf.score}, reason: {cf.reason})")

        return [p.path for p in prioritized]

    @staticmethod
    def _calculate_priority(file_path: Path,
                           user_preferences: dict | None = None) -> tuple[int, str, bool]:
        """
        Calculate priority score for a file
        
        Args:
            file_path: Path to file
            user_preferences: Optional user preferences
            
        Returns:
            Tuple of (score, reason, is_critical)
        """
        score = 0
        reasons = []
        is_critical = False

        name_lower = file_path.name.lower()
        path_str = str(file_path).lower()

        # Check entry points (highest priority)
        if file_path.name in SmartFilePrioritizer.ENTRY_POINTS:
            score += 100
            reasons.append("entry point")
            is_critical = True

        # Check configuration files
        if file_path.name.lower() in SmartFilePrioritizer.CONFIG_FILES:
            score += 80
            reasons.append("config file")
            is_critical = True

        # Check high priority name patterns
        for pattern, pattern_score in SmartFilePrioritizer.HIGH_PRIORITY_NAMES.items():
            if pattern in name_lower:
                score += pattern_score
                reasons.append(f"{pattern} pattern")
                if pattern_score >= 90:
                    is_critical = True

        # Check MCP-specific patterns
        for pattern, pattern_score in SmartFilePrioritizer.MCP_PATTERNS.items():
            if pattern in path_str:
                score += pattern_score
                reasons.append(f"MCP {pattern}")
                if pattern == 'mcp':
                    is_critical = True

        # Check file extension
        ext = file_path.suffix.lower()
        if ext in SmartFilePrioritizer.EXTENSION_SCORES:
            score += SmartFilePrioritizer.EXTENSION_SCORES[ext]
            reasons.append(f"{ext} file")

        # Check low priority patterns
        for pattern, penalty in SmartFilePrioritizer.LOW_PRIORITY_PATTERNS.items():
            if pattern in path_str:
                score += penalty  # Negative value
                reasons.append(f"low priority: {pattern}")

        # Apply user preferences if provided
        if user_preferences:
            # Check never share patterns (highest priority)
            never_share = user_preferences.get('neverShare', [])
            for pattern in never_share:
                if pattern.lower() in path_str:
                    score += 200
                    reasons.append(f"user critical: {pattern}")
                    is_critical = True

            # Check blocked patterns
            blocked = user_preferences.get('blockedPatterns', [])
            for pattern in blocked:
                if pattern.lower() in path_str:
                    score += 150
                    reasons.append(f"user blocked: {pattern}")
                    is_critical = True

            # Check custom priorities
            priorities = user_preferences.get('filePriorities', {})
            for pattern, priority in priorities.items():
                if pattern.lower() in path_str:
                    score += priority
                    reasons.append(f"user priority: {pattern}")

        # File size consideration (smaller files are faster to analyze)
        try:
            size = file_path.stat().st_size
            if size > 1024 * 1024:  # > 1MB
                score -= 10
                reasons.append("large file")
            elif size < 10 * 1024:  # < 10KB
                score += 5
                reasons.append("small file")
        except OSError:
            pass

        # Build reason string
        reason = ", ".join(reasons) if reasons else "default"

        return max(0, score), reason, is_critical

    @staticmethod
    def get_batch_priorities(files: list[Path],
                            batch_size: int = 10) -> list[list[Path]]:
        """
        Create prioritized batches of files for parallel processing
        
        Args:
            files: List of files to batch
            batch_size: Size of each batch
            
        Returns:
            List of file batches, ordered by priority
        """
        # First prioritize all files
        prioritized = SmartFilePrioritizer.prioritize_files(files)

        # Create batches
        batches = []
        for i in range(0, len(prioritized), batch_size):
            batch = prioritized[i:i + batch_size]
            batches.append(batch)

        return batches

    @staticmethod
    def filter_critical_files(files: list[Path]) -> list[Path]:
        """
        Get only critical priority files for quick scanning
        
        Args:
            files: List of all files
            
        Returns:
            List of critical files only
        """
        critical = []

        for file_path in files:
            score, reason, is_critical = SmartFilePrioritizer._calculate_priority(file_path)
            if is_critical:
                critical.append(file_path)

        logger.info(f"Filtered to {len(critical)} critical files from {len(files)} total")
        return critical


class AdaptivePrioritizer:
    """
    Learns from scan results to improve prioritization over time
    """

    def __init__(self):
        """Initialize adaptive prioritizer"""
        self.threat_history = {}  # File patterns -> threat counts
        self.scan_count = 0

    def update_from_scan(self, scan_results: dict[str, list]):
        """
        Update prioritization based on scan results
        
        Args:
            scan_results: Dictionary mapping file paths to threats found
        """
        self.scan_count += 1

        for file_path, threats in scan_results.items():
            if threats:
                path = Path(file_path)

                # Update patterns that had threats
                patterns = self._extract_patterns(path)
                for pattern in patterns:
                    if pattern not in self.threat_history:
                        self.threat_history[pattern] = 0
                    self.threat_history[pattern] += len(threats)

    def _extract_patterns(self, file_path: Path) -> list[str]:
        """Extract patterns from file path for learning"""
        patterns = []

        # File name patterns
        name_parts = file_path.stem.lower().split('_')
        patterns.extend(name_parts)

        # Directory patterns
        for part in file_path.parts[:-1]:
            patterns.append(part.lower())

        # Extension
        patterns.append(file_path.suffix.lower())

        return patterns

    def get_learned_priorities(self) -> dict[str, int]:
        """
        Get learned priority adjustments
        
        Returns:
            Dictionary of pattern -> priority adjustment
        """
        if not self.threat_history:
            return {}

        # Calculate average threats per pattern
        priorities = {}
        for pattern, threat_count in self.threat_history.items():
            avg_threats = threat_count / max(1, self.scan_count)

            # Convert to priority score
            if avg_threats > 5:
                priorities[pattern] = 50
            elif avg_threats > 2:
                priorities[pattern] = 30
            elif avg_threats > 1:
                priorities[pattern] = 20
            elif avg_threats > 0.5:
                priorities[pattern] = 10

        return priorities
