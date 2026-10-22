"""Airlock: a firewall between LLM agents and the model.

Untrusted content (tool results, MCP tool definitions) goes through the
airlock before it reaches the model.
"""

from .engine import Airlock, Decision
from .policy import DEFAULT_POLICY, Policy
from .types import Action, Category, Finding, Segment, Severity, Source

__all__ = [
    "Action",
    "Airlock",
    "Category",
    "DEFAULT_POLICY",
    "Decision",
    "Finding",
    "Policy",
    "Segment",
    "Severity",
    "Source",
]
