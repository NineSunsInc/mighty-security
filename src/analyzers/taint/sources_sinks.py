#!/usr/bin/env python3
"""
Catalogs for sources, sinks, and sanitizers.

These catalog entries are platform-aware and rule-engine agnostic.
Contributors should add to these lists without touching the engine internals.
"""


# Simple starter catalogs (expand over time)
SOURCE_PATTERNS: dict[str, list[str]] = {
    "user_input": [r"\binput\s*\("],
    "env": [r"os\.environ\b", r"dotenv\."],
    "file_read": [r"open\s*\([^)]*[\"']r"],
    "network": [r"socket\.recv\(", r"request\.args\[", r"requests\."]
}

SINK_PATTERNS: dict[str, list[str]] = {
    "exec": [r"exec\s*\(", r"eval\s*\(", r"subprocess\.", r"os\.system\s*\("],
    "network": [r"requests\.(post|put|patch)\s*\(", r"socket\.send\("],
    "file_write": [r"open\s*\([^)]*[\"']w"],
    "database": [r"execute\s*\("]
}

SANITIZERS: list[str] = [
    # Add sanitizer function names or regexes
    "shlex.quote",
    "urllib.parse.quote",
]


