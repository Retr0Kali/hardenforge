import os
from pathlib import Path

import pytest

from sentinel.checks import Ctx, CheckError
from sentinel.engine import load_rules, run_audit
from sentinel.models import Outcome, Rule
from sentinel.redact import redact
from sentinel.scoring import summarize


def mk(rid="SH-TEST-001", check=None, **kw):
    d = dict(id=rid, title="t", description="d", platforms=["linux"], severity="low", status="approved",
             provenance={"kind": "community", "source": "t", "version": "1"},
             check=check or {"type": "manual", "params": {}})
    d.update(kw)
    return Rule.model_validate(d)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel/randomize_va_space").write_text("2\n")
    return tmp_path


def ctx(root, **kw):
    return Ctx(root=root, os_family="linux", distro="debian", **kw)


def sshd(root, text):
    (root / "etc/ssh/sshd_config").write_text(text)


def ssh_rule(**p):
    params = {"path": "/etc/ssh/sshd_config", "key": "PermitRootLogin", "value": "no", **p}
    return mk(check={"type": "config_kv", "params": params})


def test_config_pass_fail_default_and_first_wins(root):
    sshd(root, "PermitRootLogin no\nPermitRootLogin yes\n")
    assert run_audit([ssh_rule()], ctx(root))[0].outcome == Outcome.PASS
    sshd(root, "PermitRootLogin yes\n")
    assert run_audit([ssh_rule()], ctx(root))[0].outcome == Outcome.FAIL
    sshd(root, "# nothing\n")
    assert run_audit([ssh_rule()], ctx(root))[0].outcome == Outcome.FAIL
    assert run_audit([ssh_rule(default="no")], ctx(root))[0].evidence["note"].startswith("implicit")


def test_match_block_ignored(root):
    sshd(root, "Match User bob\nPermitRootLogin no\n")
    r = run_audit([ssh_rule(stop_at_regex=r"^match\b")], ctx(root))[0]
    assert r.outcome == Outcome.FAIL


def test_numeric_compare_and_bad_value_is_error(root):
    sshd(root, "MaxAuthTries 3\n")
    r = mk(check={"type": "config_kv", "params": {"path": "/etc/ssh/sshd_config", "key": "MaxAuthTries", "op": "le", "value": 4}})
    assert run_audit([r], ctx(root))[0].outcome == Outcome.PASS
    sshd(root, "MaxAuthTries lots\n")
    assert run_audit([r], ctx(root))[0].outcome == Outcome.ERROR


def test_path_traversal_is_error_not_pass(root):
    r = mk(check={"type": "config_kv", "params": {"path": "/../../etc/passwd", "key": "root", "value": "x", "separator": "="}})
    out = run_audit([r], ctx(root))[0]
    assert out.outcome == Outcome.ERROR and "escapes" in out.message


def test_permission_check(root):
    f = root / "etc/passwd"
    f.write_text("x")
    os.chmod(f, 0o644)
    r = mk(check={"type": "file_permission", "params": {"path": "/etc/passwd", "max_mode": "0644"}})
    assert run_audit([r], ctx(root))[0].outcome == Outcome.PASS
    os.chmod(f, 0o666)
    assert run_audit([r], ctx(root))[0].outcome == Outcome.FAIL


def test_sysctl_and_missing_param_is_na(root):
    r = mk(check={"type": "sysctl", "params": {"key": "kernel.randomize_va_space", "value": "2"}})
    assert run_audit([r], ctx(root))[0].outcome == Outcome.PASS
    r2 = mk("SH-TEST-002", check={"type": "sysctl", "params": {"key": "kernel.nope", "value": "1"}})
    assert run_audit([r2], ctx(root))[0].outcome == Outcome.NOT_APPLICABLE
    r3 = mk("SH-TEST-003", check={"type": "sysctl", "params": {"key": "../../etc/passwd", "value": "1"}})
    assert run_audit([r3], ctx(root))[0].outcome == Outcome.ERROR


def test_command_allowlist_and_injection(root):
    calls = []
    runner = lambda argv: (calls.append(argv) or (0, "enforcing\n"))
    ok = mk(check={"type": "command_output", "params": {"argv": ["getenforce"], "expect_regex": "^Enforcing|enforcing"}})
    assert run_audit([ok], ctx(root, runner=runner))[0].outcome == Outcome.PASS
    for bad in (["rm", "-rf", "/"], ["/bin/sh", "-c", "id"], ["id; reboot"]):
        r = mk("SH-TEST-009", check={"type": "command_output", "params": {"argv": bad, "expect_exit_code": 0}})
        assert run_audit([r], ctx(root, runner=runner))[0].outcome == Outcome.ERROR
    assert calls == [["getenforce"]]


def test_runner_failure_is_error(root):
    def boom(argv): raise CheckError("command not found")
    r = mk(check={"type": "command_output", "params": {"argv": ["getenforce"], "expect_exit_code": 0}})
    assert run_audit([r], ctx(root, runner=boom))[0].outcome == Outcome.ERROR


def test_applicability_and_approval(root):
    win = mk("SH-TEST-010", platforms=["windows"])
    deb = mk("SH-TEST-011", distros=["rhel"])
    draft = mk("SH-TEST-012", status="draft", provenance={"kind": "ai_draft", "source": "x", "version": "0"})
    off = mk("SH-TEST-013", status="disabled")
    res = {r.rule_id: r.outcome for r in run_audit([win, deb, draft, off], ctx(root))}
    assert res == {"SH-TEST-010": Outcome.NOT_APPLICABLE, "SH-TEST-011": Outcome.NOT_APPLICABLE, "SH-TEST-012": Outcome.NOT_CHECKED}


def test_scoring():
    rs = []
    root = Path("/nonexistent")
    from sentinel.models import Result
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    def r(o): return Result(rule_id="X-1", rule_version=1, title="t", severity="low", outcome=o,
                            provenance={"kind": "community", "source": "s", "version": "1"}, started_at=now, finished_at=now)
    results = [r(Outcome.PASS)] * 3 + [r(Outcome.FAIL), r(Outcome.ERROR), r(Outcome.MANUAL_REVIEW), r(Outcome.NOT_APPLICABLE), r(Outcome.NOT_APPLICABLE)]
    s = summarize(results)
    assert s["applicable"] == 6 and s["score_percent"] == 75.0 and s["coverage_percent"] == round(400 / 6, 2)
    assert summarize([r(Outcome.NOT_APPLICABLE)])["score_percent"] is None


def test_loader_rejects_bad_rules(tmp_path):
    (tmp_path / "bad.yaml").write_text("- id: x\n  title: no\n")
    (tmp_path / "evil.yaml").write_text("!!python/object/apply:os.system ['id']\n")
    (tmp_path / "unk.yaml").write_text(
        "id: SH-UNK-001\ntitle: t\ndescription: d\nplatforms: [linux]\nseverity: low\n"
        "provenance: {kind: community, source: s, version: '1'}\ncheck: {type: shell, params: {cmd: id}}\n")
    rules, errs = load_rules(tmp_path)
    assert rules == [] and len(errs) == 3


def test_shipped_rules_load():
    rules, errs = load_rules(Path(__file__).parent.parent / "rules")
    assert not errs and len(rules) >= 5


def test_redaction():
    t = "key sk-ant-abcdefgh12345678 ip 10.1.2.3 mail a@b.com password=hunter2 /home/alice/x AIzaSyA1234567890123456789012"
    o = redact(t)
    for leak in ("sk-ant-", "10.1.2.3", "a@b.com", "hunter2", "alice", "AIzaSy"):
        assert leak not in o
    assert "SECRETVALUE" not in redact("x SECRETVALUE y", ["SECRETVALUE"])
