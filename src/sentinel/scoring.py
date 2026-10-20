"""Transparent scoring.

score    = PASS / (PASS + FAIL)          N/A excluded; ERROR / NOT_CHECKED / MANUAL_REVIEW are never counted as pass
coverage = (PASS + FAIL) / applicable    applicable = every result except NOT_APPLICABLE
Internal technical-compliance figure only; not a CIS certification result.
"""
from __future__ import annotations

from collections import Counter

from .models import Outcome, Result


def summarize(results: list[Result]) -> dict:
    c = Counter(r.outcome for r in results)
    n = lambda o: c.get(o, 0)  # noqa: E731
    assessed = n(Outcome.PASS) + n(Outcome.FAIL)
    applicable = len(results) - n(Outcome.NOT_APPLICABLE)
    return {
        "total_rules": len(results),
        "applicable": applicable,
        "counts": {o.value: n(o) for o in Outcome},
        "score_percent": round(100 * n(Outcome.PASS) / assessed, 2) if assessed else None,
        "coverage_percent": round(100 * assessed / applicable, 2) if applicable else None,
        "note": "Internal technical-compliance score; not an official CIS certification.",
    }
