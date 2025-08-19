"""
AST Cache for Python File Analysis
Performance optimization to avoid re-parsing Python files
"""

import ast
import hashlib
import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ASTCache:
    """
    Cache for Python AST trees to avoid re-parsing.
    Uses LRU eviction strategy and content-based hashing.
    """

    def __init__(self, max_size: int = 100):
        """
        Initialize AST cache with maximum size
        
        Args:
            max_size: Maximum number of AST trees to cache
        """
        self._cache = OrderedDict()  # LRU order
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
        self._parse_errors = 0

    def get_ast(self, file_path: Path, content: str | None = None) -> ast.AST | None:
        """
        Get cached AST or parse and cache new one
        
        Args:
            file_path: Path to Python file
            content: Optional content (if already loaded)
            
        Returns:
            Parsed AST tree or None if parsing fails
        """
        # Read content if not provided
        if content is None:
            try:
                with open(file_path, encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (OSError, FileNotFoundError, PermissionError) as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                return None

        # Create cache key from content hash
        content_hash = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()[:16]
        cache_key = f"{file_path}:{content_hash}"

        # Check cache
        if cache_key in self._cache:
            self._hits += 1
            # Move to end (most recently used)
            self._cache.move_to_end(cache_key)
            logger.debug(f"AST cache hit for {file_path.name}")
            return self._cache[cache_key]

        self._misses += 1

        # Parse AST
        try:
            tree = ast.parse(content, filename=str(file_path))

            # Add to cache with LRU eviction
            if len(self._cache) >= self._max_size:
                # Remove oldest (least recently used)
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                logger.debug(f"Evicted {oldest_key} from AST cache")

            self._cache[cache_key] = tree
            logger.debug(f"AST cached for {file_path.name}")
            return tree

        except SyntaxError as e:
            self._parse_errors += 1
            logger.debug(f"Syntax error parsing {file_path}: {e}")
            return None
        except Exception as e:
            self._parse_errors += 1
            logger.debug(f"Error parsing {file_path}: {e}")
            return None

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache performance statistics
        
        Returns:
            Dictionary with cache statistics
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0

        return {
            'hit_rate': f"{hit_rate:.1f}%",
            'hits': self._hits,
            'misses': self._misses,
            'parse_errors': self._parse_errors,
            'cache_size': len(self._cache),
            'max_size': self._max_size,
            'total_requests': total
        }

    def clear(self):
        """Clear the cache"""
        self._cache.clear()
        logger.info("AST cache cleared")

    def preload_directory(self, directory: Path, extensions: list = None):
        """
        Preload all Python files from a directory into cache
        
        Args:
            directory: Directory to scan
            extensions: File extensions to include (default: ['.py'])
        """
        if extensions is None:
            extensions = ['.py']

        count = 0
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if file_path.is_file():
                    # Skip very large files
                    if file_path.stat().st_size > 500 * 1024:  # 500KB
                        continue

                    self.get_ast(file_path)
                    count += 1

                    # Don't exceed cache size
                    if count >= self._max_size:
                        break

        logger.info(f"Preloaded {count} files into AST cache")

    def analyze_ast_patterns(self, tree: ast.AST) -> dict[str, int]:
        """
        Analyze AST for common security patterns
        
        Args:
            tree: Parsed AST tree
            
        Returns:
            Dictionary of pattern counts
        """
        patterns = {
            'exec_calls': 0,
            'eval_calls': 0,
            'subprocess_calls': 0,
            'imports': 0,
            'functions': 0,
            'classes': 0,
            'try_except': 0
        }

        class PatternVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'exec':
                        patterns['exec_calls'] += 1
                    elif node.func.id == 'eval':
                        patterns['eval_calls'] += 1
                elif isinstance(node.func, ast.Attribute):
                    if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == 'subprocess'):
                        patterns['subprocess_calls'] += 1
                self.generic_visit(node)

            def visit_Import(self, node):
                patterns['imports'] += 1
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                patterns['imports'] += 1
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                patterns['functions'] += 1
                self.generic_visit(node)

            def visit_ClassDef(self, node):
                patterns['classes'] += 1
                self.generic_visit(node)

            def visit_Try(self, node):
                patterns['try_except'] += 1
                self.generic_visit(node)

        visitor = PatternVisitor()
        visitor.visit(tree)

        return patterns


class GlobalASTCache:
    """Singleton global AST cache for the entire application"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = ASTCache(max_size=200)  # Larger cache for global use
        return cls._instance


# Global cache instance
global_ast_cache = GlobalASTCache()
