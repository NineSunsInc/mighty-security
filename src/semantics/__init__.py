#!/usr/bin/env python3
"""Semantic ensemble namespace."""

from .model_ensemble import ModelEnsemble as SecurityModelEnsemble
from .semantic_security_analyzer import SemanticSecurityAnalyzer

__all__ = ["SemanticSecurityAnalyzer", "SecurityModelEnsemble"]


