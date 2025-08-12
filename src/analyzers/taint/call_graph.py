#!/usr/bin/env python3
"""
Call graph construction across files/functions (skeleton).
"""

from typing import Dict, List, Set
from pathlib import Path


class CallGraph:
    def __init__(self):
        self.graph: Dict[str, Set[str]] = {}

    def add_edge(self, caller: str, callee: str) -> None:
        self.graph.setdefault(caller, set()).add(callee)

    def outgoing(self, function_fqn: str) -> List[str]:
        return list(self.graph.get(function_fqn, set()))


def build_call_graph(repo_path: Path) -> CallGraph:
    """Build a lightweight call graph (placeholder)."""
    # TODO: Implement language-aware parsing; for now return empty graph
    return CallGraph()


