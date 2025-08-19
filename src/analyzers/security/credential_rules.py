#!/usr/bin/env python3
"""
Credential theft rules (skeleton).

API: detect_credential_access(ast_node) -> dict
"""

from typing import Any

SENSITIVE_PATHS = [
    "~/.aws/credentials",
    "~/.ssh/id_rsa",
    "~/.docker/config.json",
    "~/.kube/config",
    "cookies.sqlite",
]


def detect_credential_access(ast_node: Any) -> dict[str, Any]:
    """Inspect AST node for sensitive path or credential-store access (placeholder)."""
    # TODO: Parse string literals, os.path usage, keychain APIs
    return {}


