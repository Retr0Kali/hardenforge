"""Check implementations. Every check is read-only.

A check returns (Outcome, evidence). Any unexpected problem raises CheckError,
which the engine converts to ERROR -- never to PASS.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import Outcome


class CheckError(Exception):
    pass


# Read-only inspection binaries only. Rules cannot name anything else.
ALLOWED_COMMANDS = frozenset({
    "sshd", "systemctl", "ufw", "firewall-cmd", "sestatus", "getenforce", "aa-status",
    "auditctl", "sysctl", "mount", "findmnt", "lsblk", "dpkg-query", "rpm", "id",
    "csrutil", "fdesetup", "spctl", "defaults",
})


def _default_runner(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(  # noqa: S603 - shell=False, allowlisted binary, list argv
            argv, shell=False, capture_output=True, text=True, timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except FileNotFoundError as e:
        raise CheckError(f"command not found: {argv[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise CheckError(f"command timed out: {argv[0]}") from e
    return p.returncode, p.stdout


@dataclass
class Ctx:
    root: Path = Path("/")
    os_family: str = "linux"
    distro: str | None = None
    runner: Callable[[list[str]], tuple[int, str]] = field(default=_default_runner)

    def resolve(self, path: str) -> Path:
        """Resolve a rule-supplied path strictly inside ctx.root (traversal-safe)."""
        if "\x00" in path:
            raise CheckError("invalid path")
        root = self.root.resolve()
        full = (root / path.lstrip("/")).resolve()
        if full != root and root not in full.parents:
            raise CheckError("path escapes audit root")
        return full


def compare(op: str, observed: str, expected: Any) -> bool:
    try:
        if op == "eq":
            return observed.strip().lower() == str(expected).strip().lower()
        if op == "in":
            return observed.strip().lower() in {str(e).strip().lower() for e in expected}
        if op == "le":
            return float(observed) <= float(expected)
        if op == "ge":
            return float(observed) >= float(expected)
        if op == "regex":
            return re.search(str(expected), observed) is not None
    except (ValueError, TypeError, re.error) as e:
        raise CheckError(f"cannot compare {observed!r} with {expected!r} using {op}: {e}") from e
    raise CheckError(f"unknown operator: {op}")


def _read_text(ctx: Ctx, path: str) -> str | None:
    p = ctx.resolve(path)
    try:
        return p.read_text(errors="replace")
    except FileNotFoundError:
        return None
    except PermissionError as e:
        raise CheckError(f"permission denied reading {path} (run with required privileges)") from e


def config_kv(ctx: Ctx, p: dict[str, Any]) -> tuple[Outcome, dict[str, Any]]:
    path, key = p["path"], p["key"]
    sep = p.get("separator", "space")
    text = _read_text(ctx, path)
    if text is None:
        out = Outcome.NOT_APPLICABLE if p.get("missing_file") == "not_applicable" else Outcome.FAIL
        return out, {"path": path, "note": "file not found"}
    stop = re.compile(p["stop_at_regex"], re.I) if p.get("stop_at_regex") else None
    observed = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if stop and stop.match(s):
            break
        k, v = (s.split("=", 1) if sep == "=" else (s.split(None, 1) + [""])[:2])
        if k.strip().lower() == key.lower():
            observed = v.strip()
            break  # first occurrence wins (sshd semantics)
    note = "explicit"
    if observed is None and "default" in p:
        observed, note = str(p["default"]), "implicit default (key not set)"
    if observed is None:
        return Outcome.FAIL, {"path": path, "key": key, "observed": None, "note": "key not set"}
    op = p.get("op", "eq")
    ok = compare(op, observed, p["value"])
    return (Outcome.PASS if ok else Outcome.FAIL), {
        "path": path, "key": key, "observed": observed, "expected": p["value"], "op": op, "note": note,
    }


def file_permission(ctx: Ctx, p: dict[str, Any]) -> tuple[Outcome, dict[str, Any]]:
    path = p["path"]
    full = ctx.resolve(path)
    try:
        st = full.stat()
    except FileNotFoundError:
        if p.get("missing_file") == "not_applicable":
            return Outcome.NOT_APPLICABLE, {"path": path, "note": "file not found"}
        return Outcome.FAIL, {"path": path, "note": "file not found"}
    except PermissionError as e:
        raise CheckError(f"permission denied: {path}") from e
    mode = st.st_mode & 0o7777
    max_mode = int(str(p["max_mode"]), 8)
    ok = (mode & ~max_mode) == 0
    ev: dict[str, Any] = {"path": path, "mode": f"{mode:04o}", "max_mode": f"{max_mode:04o}"}
    if "owner_uid" in p:
        ev["owner_uid"], ev["expected_owner_uid"] = st.st_uid, p["owner_uid"]
        ok = ok and st.st_uid == int(p["owner_uid"])
    return (Outcome.PASS if ok else Outcome.FAIL), ev


_SYSCTL_KEY = re.compile(r"^[a-z0-9_.-]+$")


def sysctl(ctx: Ctx, p: dict[str, Any]) -> tuple[Outcome, dict[str, Any]]:
    key = p["key"]
    if not _SYSCTL_KEY.match(key):
        raise CheckError("invalid sysctl key")
    full = ctx.resolve("/proc/sys/" + key.replace(".", "/"))
    try:
        observed = full.read_text().strip()
    except FileNotFoundError:
        return Outcome.NOT_APPLICABLE, {"key": key, "note": "parameter not present on this kernel"}
    except OSError as e:
        raise CheckError(f"cannot read {key}: {e}") from e
    ok = compare(p.get("op", "eq"), observed, p["value"])
    return (Outcome.PASS if ok else Outcome.FAIL), {"key": key, "observed": observed, "expected": p["value"]}


def command_output(ctx: Ctx, p: dict[str, Any]) -> tuple[Outcome, dict[str, Any]]:
    argv = p["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise CheckError("argv must be a non-empty list of strings")
    if os.path.basename(argv[0]) != argv[0] or argv[0] not in ALLOWED_COMMANDS:
        raise CheckError(f"command not on read-only allowlist: {argv[0]}")
    code, out = ctx.runner(argv)
    ev: dict[str, Any] = {"argv": argv, "exit_code": code, "stdout": out[:4096]}
    if "expect_exit_code" in p and code != int(p["expect_exit_code"]):
        return Outcome.FAIL, ev
    if "expect_regex" in p:
        try:
            ok = re.search(p["expect_regex"], out, re.M) is not None
        except re.error as e:
            raise CheckError(f"bad regex: {e}") from e
        return (Outcome.PASS if ok else Outcome.FAIL), ev
    if "expect_exit_code" in p:
        return Outcome.PASS, ev
    raise CheckError("command_output needs expect_exit_code or expect_regex")


def manual(ctx: Ctx, p: dict[str, Any]) -> tuple[Outcome, dict[str, Any]]:
    return Outcome.MANUAL_REVIEW, {"instructions": p.get("instructions", "")}


REGISTRY: dict[str, Callable[[Ctx, dict[str, Any]], tuple[Outcome, dict[str, Any]]]] = {
    "config_kv": config_kv,
    "file_permission": file_permission,
    "sysctl": sysctl,
    "command_output": command_output,
    "manual": manual,
}
