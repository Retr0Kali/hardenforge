"""Validated data models: rules, results, outcomes."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"
    ERROR = "ERROR"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["official", "community", "ai_draft"]
    source: str
    version: str
    control_ref: str | None = None  # original benchmark control ID, preserved verbatim


class CheckSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    params: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    version: int = Field(default=1, ge=1)
    title: str
    description: str
    platforms: list[Literal["linux", "windows", "darwin"]]
    distros: list[str] = Field(default_factory=list)  # empty = any
    severity: Literal["low", "medium", "high", "critical"]
    provenance: Provenance
    status: Literal["draft", "approved", "disabled"] = "draft"
    profile: Literal["L1", "L2"] | None = None  # benchmark profile level tag
    check: CheckSpec
    remediation: str = ""      # human-readable only; nothing here is ever executed
    rollback: str = ""         # procedure or documented limitation
    impact: str = ""
    requires_privilege: bool = False


class Result(BaseModel):
    rule_id: str
    rule_version: int
    title: str
    severity: str
    outcome: Outcome
    profile: str | None = None
    remediation: str = ""
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_sha256: str = ""
    provenance: Provenance
    started_at: datetime
    finished_at: datetime


class LoadError(BaseModel):
    path: str
    error: str
