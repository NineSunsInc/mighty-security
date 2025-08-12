#!/usr/bin/env python3
"""
Inter-procedural taint engine (skeleton).

API: analyze(repo_path, call_graph, catalog) -> List[FlowTrace]
"""

from typing import List, Any
from pathlib import Path

from .types import FlowTrace, TaintKind, Frame


def analyze(repo_path: Path, call_graph: Any, catalog: Any = None) -> List[FlowTrace]:
    """Analyze repository for tainted flows (placeholder implementation).

    Returns a list of FlowTrace objects with minimal fields filled.
    """
    # TODO: Implement actual inter-procedural taint; return empty list for now
    return []


