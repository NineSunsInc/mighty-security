#!/usr/bin/env python3
"""
Taint types and trace structures.

Defines the core data structures used by the taint engine and security rules.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class TaintKind(Enum):
    USER_INPUT = "user_input"
    FILE_READ = "file_read"
    ENV = "env"
    NETWORK = "network"
    CREDENTIAL = "credential"


@dataclass
class Frame:
    file_path: str
    line: int
    function: Optional[str] = None
    code_preview: Optional[str] = None


@dataclass
class FlowTrace:
    id: str
    taint_kind: TaintKind
    source_type: str
    sink_type: str
    source_location: str
    sink_location: str
    path: List[Frame] = field(default_factory=list)
    sanitized: bool = False
    sanitizers: List[str] = field(default_factory=list)
    confidence: float = 0.0

