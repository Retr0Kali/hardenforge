import json

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from sentinel.ai.manager import AIError, AIManager, AIRequest, ConsentRequired, configs_from_env
from sentinel.api import create_app
from sentinel.secrets import SecretStore, SecretStoreError, mask

MK = Fernet.generate_key().decode()


def env(tmp_path, **extra):
    base = {"SENTINEL_MASTER_KEY": MK, "SENTINEL_DATA_DIR": str(tmp_path), "SENTINEL_API_TOKEN": "t" * 24,
            "SENTINEL_OPENAI_MODEL": "m-openai", "SENTINEL_ANTHROPIC_MODEL": "m-model-b", "SENTINEL_GEMINI_MODEL": "m-gem"}
    base.update(extra)
    return base


def test_store_roundtrip_encrypted_and_mask(tmp_path):
    s = SecretStore(tmp_path / "s.json", environ={"SENTINEL_MASTER_KEY": MK})
    s.set("openai", "sk-test-1234567890abcd")
    raw = (tmp_path / "s.json").read_text()
    assert "sk-test" not in raw and oct((tmp_path / "s.json").stat().st_mode & 0o777) == "0o600"
    assert s.get("openai") == "sk-test-1234567890abcd"
    assert mask(s.get("openai")) == "****abcd"
    assert s.delete("openai") and s.get("openai") is None
    with pytest.raises(SecretStoreError):
        s.set("evil", "sk-test-1234567890abcd")
    with pytest.raises(SecretStoreError):
        SecretStore(tmp_path / "s.json", environ={}).set("openai", "sk-test-1234567890abcd")


def mgr(tmp_path, handler, **kw):
    e = env(tmp_path, SENTINEL_OPENAI_API_KEY="sk-openai-SECRET123456", SENTINEL_ANTHROPIC_API_KEY="sk-ant-SECRET123456789",
            SENTINEL_OPENAI_PRICE_IN="1", SENTINEL_OPENAI_PRICE_OUT="2")
    store = SecretStore(tmp_path / "s.json", environ=e)
    return AIManager(store=store, configs=configs_from_env(e), sharing={"findings"},
                     client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda s: None, **kw)


OPENAI_OK = {"choices": [{"message": {"content": "advice"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
ALT_OK = {"content": [{"type": "text", "text": "alt advice"}], "usage": {"input_tokens": 3, "output_tokens": 4}}


def test_consent_required(tmp_path):
    m = mgr(tmp_path, lambda r: httpx.Response(200, json=OPENAI_OK))
    with pytest.raises(ConsentRequired):
        m.complete(AIRequest("explain", "x", data_category="inventory"))


def test_redaction_before_send_and_estimate(tmp_path):
    seen = {}
    def h(r):
        seen["body"] = r.content.decode()
        return httpx.Response(200, json=OPENAI_OK)
    m = mgr(tmp_path, h)
    out = m.complete(AIRequest("explain", "host 10.0.0.5 key sk-openai-SECRET123456", "findings"), order=["openai"])
    assert "10.0.0.5" not in seen["body"] and "SECRET123456" not in seen["body"] and "<evidence>" in seen["body"]
    assert out.estimated_cost_usd == pytest.approx(20 / 1e6) and out.advisory
    assert m.usage_summary()["cost_is_estimate"] is True


def test_fallback_on_rate_limit(tmp_path):
    def h(r):
        if "openai" in str(r.url):
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, json=ALT_OK)
    m = mgr(tmp_path, h, max_retries=1)
    out = m.complete(AIRequest("summarize", "x"), order=["openai", "anthropic"])
    assert out.provider == "anthropic"


def test_auth_error_not_retried_and_key_not_in_error(tmp_path):
    calls = []
    def h(r):
        calls.append(1)
        return httpx.Response(401, json={"error": "bad key sk-openai-SECRET123456"})
    m = mgr(tmp_path, h)
    with pytest.raises(AIError) as e:
        m.complete(AIRequest("x", "y"), order=["openai"])
    assert len(calls) == 1 and "SECRET123456" not in str(e.value)


def test_missing_model_and_key_fail_cleanly(tmp_path):
    m = mgr(tmp_path, lambda r: httpx.Response(200, json=OPENAI_OK))
    with pytest.raises(AIError):
        m.complete(AIRequest("x", "y"), order=["gemini"])


def test_api_auth_and_key_masking(tmp_path):
    c = TestClient(create_app(env(tmp_path)))
    assert c.get("/health").status_code == 200
    assert c.get("/system").status_code == 401
    assert c.post("/audit", headers={"authorization": "Bearer wrong"}).status_code == 401
    h = {"authorization": "Bearer " + "t" * 24}
    r = c.put("/providers/openai/key", json={"api_key": "sk-test-1234567890abcd"}, headers=h)
    assert r.json()["key"] == "****abcd"
    listing = c.get("/providers", headers=h).text
    assert "sk-test" not in listing and "****abcd" in listing
    assert c.put("/providers/nope/key", json={"api_key": "sk-test-1234567890abcd"}, headers=h).status_code == 400
    assert c.delete("/providers/openai/key", headers=h).json() == {"deleted": True}


def test_api_refuses_to_start_without_token(tmp_path):
    with pytest.raises(RuntimeError):
        create_app({"SENTINEL_DATA_DIR": str(tmp_path)})


def test_audit_endpoint_readonly(tmp_path):
    e = env(tmp_path, SENTINEL_RULES_DIR=str(__import__("pathlib").Path(__file__).parent.parent / "rules"))
    c = TestClient(create_app(e))
    d = c.post("/audit", headers={"authorization": "Bearer " + "t" * 24}).json()
    assert d["mode"] == "read-only" and d["summary"]["total_rules"] >= 5


def test_dashboard_served_with_csp(tmp_path):
    r = TestClient(create_app(env(tmp_path))).get("/")
    assert r.status_code == 200 and "SentinelHardener" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "innerHTML" not in r.text  # untrusted evidence must only be rendered as text


def _client(tmp_path):
    e = env(tmp_path, SENTINEL_RULES_DIR=str(__import__("pathlib").Path(__file__).parent.parent / "rules"))
    return TestClient(create_app(e)), {"authorization": "Bearer " + "t" * 24}


def test_scan_saved_profiles_and_history(tmp_path):
    c, h = _client(tmp_path)
    a = c.post("/audit", headers=h).json()["scan_id"]
    b = c.post("/audit", headers=h).json()["scan_id"]
    assert b > a and len(c.get("/scans", headers=h).json()) == 1  # one latest per target
    s = c.get(f"/scans/{b}", headers=h).json()
    assert len(s["history"]) == 2 and s["profiles"]["L1"]["total_rules"] >= 4 and s["profiles"]["L2"]["total_rules"] >= 1
    assert c.get("/scans/99999", headers=h).status_code == 404
    assert c.get("/scans").status_code == 401


def test_ingest_recomputes_summary_and_validates(tmp_path):
    c, h = _client(tmp_path)
    mk = lambda o: {"rule_id": "WIN-1", "rule_version": 1, "title": "t", "severity": "low", "outcome": o,
                    "provenance": {"kind": "community", "source": "s", "version": "1"},
                    "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z"}
    body = {"system": {"os_family": "windows", "hostname": "WS1", "version": "2022"},
            "results": [mk("PASS"), mk("PASS"), mk("FAIL"), mk("NOT_APPLICABLE")], "summary": {"score_percent": 100}}
    r = c.post("/ingest", json=body, headers=h).json()
    assert r["summary"]["score_percent"] == 66.67  # client-supplied summary ignored
    assert {s["os_family"] for s in c.get("/scans", headers=h).json()} == {"windows"}
    bad = {**body, "results": [{**mk("PASS"), "outcome": "COMPLIANT"}]}
    assert c.post("/ingest", json=bad, headers=h).status_code == 422


def test_reports_escape_and_neutralise(tmp_path):
    from sentinel import report
    evil = {"id": 1, "ts": "t", "host": "<script>x</script>", "os_family": "linux", "distro": None, "version": None, "source": "local",
            "summary": {"score_percent": 50, "coverage_percent": 100, "counts": {"PASS": 1}},
            "results": [{"rule_id": "A-1", "rule_version": 1, "title": "=HYPERLINK(\"http://x\")", "severity": "high", "outcome": "FAIL",
                         "message": "<img src=x onerror=1>", "evidence": {"v": "<b>"}, "evidence_sha256": "ab", "remediation": "+cmd",
                         "provenance": {"kind": "community", "source": "s", "version": "1"}}]}
    h = report.to_html(evil, {"L1": {"score_percent": 1, "coverage_percent": 1}})
    assert "<script>x" not in h and "<img src" not in h and "&lt;img" in h
    assert "'=HYPERLINK" in report.to_csv(evil) and "'+cmd" in report.to_csv(evil)


def test_report_endpoint_and_big_ruleset(tmp_path):
    c, h = _client(tmp_path)
    d = c.post("/audit", headers=h).json()
    assert d["summary"]["total_rules"] >= 30 and not d["rule_load_errors"]
    sid = d["scan_id"]
    assert "Configuration audit report" in c.get(f"/scans/{sid}/report?format=html", headers=h).text
    assert c.get(f"/scans/{sid}/report?format=csv", headers=h).text.startswith("rule_id,")
    assert c.get(f"/scans/{sid}/report?format=pdf", headers=h).status_code == 400
    assert c.get(f"/scans/{sid}/report").status_code == 401
