"""Rule loading and read-only audit execution."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from .checks import REGISTRY, CheckError, Ctx
from .models import LoadError, Outcome, Result, Rule

MAX_RULE_FILE_BYTES = 256 * 1024


def load_rules(rules_dir: Path) -> tuple[list[Rule], list[LoadError]]:
    """Strictly validate every rule file; invalid files are reported, never silently skipped."""
    rules: list[Rule] = []
    errors: list[LoadError] = []
    seen: set[str] = set()
    for f in sorted(rules_dir.rglob("*.y*ml")):
        try:
            if f.stat().st_size > MAX_RULE_FILE_BYTES:
                raise ValueError("rule file too large")
            doc = yaml.safe_load(f.read_text())  # safe_load only: no object construction
            for item in (doc if isinstance(doc, list) else [doc]):
                rule = Rule.model_validate(item)
                if rule.check.type not in REGISTRY:
                    raise ValueError(f"unknown check type: {rule.check.type}")
                if rule.id in seen:
                    raise ValueError(f"duplicate rule id: {rule.id}")
                seen.add(rule.id)
                rules.append(rule)
        except (ValidationError, ValueError, yaml.YAMLError, OSError) as e:
            errors.append(LoadError(path=str(f), error=str(e)[:500]))
    return rules, errors


def _sha(evidence: dict) -> str:
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()


def _result(rule: Rule, outcome: Outcome, msg: str, ev: dict, t0: datetime) -> Result:
    return Result(
        rule_id=rule.id, rule_version=rule.version, title=rule.title, severity=rule.severity,
        outcome=outcome, profile=rule.profile, remediation=rule.remediation, message=msg, evidence=ev, evidence_sha256=_sha(ev),
        provenance=rule.provenance, started_at=t0, finished_at=datetime.now(timezone.utc),
    )


def run_audit(rules: list[Rule], ctx: Ctx) -> list[Result]:
    results: list[Result] = []
    for rule in rules:
        t0 = datetime.now(timezone.utc)
        if rule.status == "disabled":
            continue
        if rule.status != "approved":  # covers all drafts, including AI-generated ones
            results.append(_result(rule, Outcome.NOT_CHECKED, "rule not approved for execution", {}, t0))
            continue
        if ctx.os_family not in rule.platforms or (rule.distros and ctx.distro not in rule.distros):
            results.append(_result(rule, Outcome.NOT_APPLICABLE, "rule does not apply to this platform", {}, t0))
            continue
        try:
            outcome, ev = REGISTRY[rule.check.type](ctx, rule.check.params)
            results.append(_result(rule, outcome, "", ev, t0))
        except (CheckError, KeyError, TypeError) as e:
            results.append(_result(rule, Outcome.ERROR, f"{type(e).__name__}: {e}", {}, t0))  # never PASS
    return results
