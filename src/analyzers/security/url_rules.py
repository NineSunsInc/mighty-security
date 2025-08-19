#!/usr/bin/env python3
"""
URL/SSRF rules (skeleton).

API: detect_ssrf_risk(call_site_ast) -> dict
"""

from typing import Any


def detect_ssrf_risk(call_site_ast: Any) -> dict[str, Any]:
    """Analyze a call site AST node and return SSRF risk hints (placeholder)."""
    # TODO: Inspect requests.get/post calls, url origin, redirects, guards
    return {
        "missing_guards": [],
        "url_expr_classification": "unknown",
        "severity_hint": "MEDIUM",
    }


