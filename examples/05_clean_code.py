"""
Example 5: Well-written code.
Expected findings: zero or very few, demonstrating that the agent returns
an empty findings list when nothing is genuinely wrong rather than
inventing issues to appear thorough. The performance pass specifically
was prompted with "return zero findings rather than inventing marginal ones"
-- this example is the honest test of whether that instruction holds.
"""
from __future__ import annotations

import logging
from typing import Sequence

logger = logging.getLogger(__name__)


def find_duplicates(items: Sequence[int]) -> set[int]:
    """Return the set of values that appear more than once in `items`.

    Uses a single-pass counter approach -- O(n) time, O(n) space.
    """
    seen: set[int] = set()
    duplicates: set[int] = set()
    for item in items:
        if item in seen:
            duplicates.add(item)
        else:
            seen.add(item)
    return duplicates


def safe_divide(numerator: float, denominator: float) -> float | None:
    """Divides numerator by denominator, returning None on division by zero.

    Callers should always check for None before using the result.
    """
    if denominator == 0:
        logger.warning("Attempted division by zero: numerator=%s", numerator)
        return None
    return numerator / denominator


def parse_config(config: dict | None) -> tuple[str, int] | None:
    """Extracts host and port from a config dict.

    Returns None if config is missing or required keys are absent,
    rather than raising KeyError or AttributeError.
    """
    if config is None:
        return None
    host = config.get("host")
    port = config.get("port")
    if not isinstance(host, str) or not isinstance(port, int):
        return None
    return host, port
