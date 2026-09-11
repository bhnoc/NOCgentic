"""zeek-detector: the APE-85/86 research pipeline as a service (APE-762).

What has to stay true:

  1. An upload of ssl.log + conn.log comes back as findings, and the synthetic
     agentic session (api.openai.com, three context windows of eight ~0.5 s
     requests) is the one flagged: openai, agentic-orchestration, both timing
     patterns, high severity. The four browsing clusters stay low/unknown.
  2. The response IS the stored record. GET /analyses/{id} returns the same
     findings; /findings filters across analyses.
  3. Rules mode needs no key and no network. LLM mode is validated field by
     field against the rules baseline, and a model failure on one cluster
     degrades to `rules-fallback` instead of failing the upload.
  4. Uploads are bounded (413), typed (422 when we cannot tell ssl from conn),
     and the bearer gate applies to everything but /health once a token is set.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "zeek"
_AGENT_DIR = Path(__file__).resolve().parents[2] / "agents" / "zeek-detector"

SSL_LOG = (_FIXTURES / "ssl.log").read_bytes()
CONN_LOG = (_FIXTURES / "conn.log").read_bytes()
SSL_JSON = (_FIXTURES / "ssl.json.log").read_bytes()


def _load_service(monkeypatch, tmp_path, **env):
    """Import a fresh copy of the service against a temp SQLite file."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZEEK_DB_PATH", str(tmp_path / "zeek.db"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for name in ("zeek_main", "pipeline", "pipeline.classifier", "pipeline.findings_generator",
                 "pipeline.timing_detector", "pipeline.zeek_parser", "storage"):
        sys.modules.pop(name, None)
    if str(_AGENT_DIR) not in sys.path:
        sys.path.insert(0, str(_AGENT_DIR))
    spec = importlib.util.spec_from_file_location("zeek_main", _AGENT_DIR / "main.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["zeek_main"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def svc(monkeypatch, tmp_path):
    return _load_service(monkeypatch, tmp_path)


@pytest.fixture
def client(svc):
    return TestClient(svc.app)


def _upload(client, ssl=SSL_LOG, conn=CONN_LOG, **params):
    files = []
    if ssl is not None:
        files.append(("files", ("ssl.log", io.BytesIO(ssl), "text/plain")))
    if conn is not None:
        files.append(("files", ("conn.log", io.BytesIO(conn), "text/plain")))
    return client.post("/analyze", files=files, params=params)


# ── 1. The pipeline, end to end ───────────────────────────────────────────────

def test_analyze_flags_the_agentic_session_and_only_it(client):
    r = _upload(client)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["classifier"] == {"mode": "rules", "model": None}
    assert body["event_count"] == 98
    assert body["cluster_count"] == 5
    assert [sf["log_type"] for sf in body["source_files"]] == ["ssl", "conn"]
    assert all(sf["sha256"] and sf["events"] > 0 for sf in body["source_files"])

    findings = body["findings"]
    assert len(findings) == 5
    top = findings[0]
    assert top["finding_id"] == "AI-0001"
    assert top["host"] == "192.168.1.20"
    assert top["service_id"] == "openai"
    assert top["behavior_classification"] == "agentic-orchestration"
    assert sorted(top["detected_patterns"]) == ["agentic_loop", "context_reset"]
    assert top["severity"] == "high"
    assert top["confidence_level"] == "high"
    assert top["server_names"] == ["api.openai.com"]
    assert top["classifier_mode"] == "rules"
    assert top["metrics"]["request_count"] == 24
    assert top["metrics"]["sawtooth_score"] >= 0.5
    assert top["timeline"]["first_seen"] and top["timeline"]["last_seen"]
    assert any(e.startswith("SNI/server_name: api.openai.com") for e in top["evidence_chain"])
    assert "OpenAI" in top["narrative"] and "192.168.1.20" in top["narrative"]

    for f in findings[1:]:
        assert f["service_id"] == "unknown"
        assert f["severity"] == "low"
        assert f["detected_patterns"] == []

    summary = body["summary"]
    assert summary["agentic_orchestration_findings"] == 1
    assert summary["severity_breakdown"] == {"critical": 0, "high": 1, "medium": 0, "low": 4}
    assert summary["classifier_modes"] == {"rules": 5}


def test_single_log_and_json_format_are_enough(client):
    r = _upload(client, ssl=SSL_JSON, conn=None)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source_files"][0]["log_type"] == "ssl"
    # This fixture was generated separately from the TSV pair: two browsing
    # clusters plus the same api.openai.com agentic session.
    assert body["cluster_count"] == 3
    top = body["findings"][0]
    assert top["service_id"] == "openai"
    assert top["behavior_classification"] == "agentic-orchestration"


def test_log_type_is_inferred_from_the_column_list_not_the_filename(client):
    # Same bytes, unhelpful names. The #fields line settles it; the fixture's
    # #path header says "conn" for both files and must not win.
    files = [("files", ("a.txt", io.BytesIO(SSL_LOG), "text/plain")),
             ("files", ("b.txt", io.BytesIO(CONN_LOG), "text/plain"))]
    r = client.post("/analyze", files=files)
    assert r.status_code == 200, r.text
    assert [sf["log_type"] for sf in r.json()["source_files"]] == ["ssl", "conn"]


def test_explicit_parts_override_inference(client):
    r = client.post("/analyze", files={"ssl": ("whatever", io.BytesIO(SSL_LOG)),
                                       "conn": ("whatever", io.BytesIO(CONN_LOG))})
    assert r.status_code == 200, r.text
    assert [sf["log_type"] for sf in r.json()["source_files"]] == ["ssl", "conn"]


# ── 2. Persistence ────────────────────────────────────────────────────────────

def test_response_is_the_stored_record(client):
    created = _upload(client).json()
    aid = created["analysis_id"]

    fetched = client.get(f"/analyses/{aid}")
    assert fetched.status_code == 200
    assert fetched.json()["findings"] == created["findings"]
    assert fetched.json()["summary"] == created["summary"]

    listed = client.get("/analyses").json()
    assert [a["analysis_id"] for a in listed] == [aid]
    assert "findings" not in listed[0]

    assert client.get("/analyses/nope").status_code == 404

    csv_text = client.get(f"/analyses/{aid}/findings.csv").text
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("finding_id,severity,host,")
    assert len(lines) == 6
    assert "api.openai.com" not in lines[0] and "192.168.1.20" in lines[1]

    health = client.get("/health").json()
    assert health["status"] == "ok"
    assert health["db"] == {"path": health["db"]["path"], "ok": True, "analyses": 1, "findings": 5}


def test_findings_query_filters_across_analyses(client):
    first = _upload(client).json()["analysis_id"]
    second = _upload(client).json()["analysis_id"]

    everything = client.get("/findings", params={"limit": 1000}).json()
    assert len(everything) == 10
    assert {f["analysis_id"] for f in everything} == {first, second}

    high = client.get("/findings", params={"min_severity": "high"}).json()
    assert len(high) == 2 and all(f["host"] == "192.168.1.20" for f in high)

    by_host = client.get("/findings", params={"host": "192.168.1.10"}).json()
    assert len(by_host) == 8 and all(f["service_id"] == "unknown" for f in by_host)

    confident = client.get("/findings", params={"min_confidence": 0.85, "service_id": "openai"}).json()
    assert len(confident) == 2

    assert client.get("/findings", params={"severity": "critical"}).json() == []
    assert client.get("/findings", params={"severity": "bogus"}).status_code == 422


def test_store_survives_a_service_restart(monkeypatch, tmp_path):
    first = _load_service(monkeypatch, tmp_path)
    aid = _upload(TestClient(first.app)).json()["analysis_id"]
    again = _load_service(monkeypatch, tmp_path)
    r = TestClient(again.app).get(f"/analyses/{aid}")
    assert r.status_code == 200 and len(r.json()["findings"]) == 5


# ── 3. Classifier modes ───────────────────────────────────────────────────────

class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeAgent:
    """Stands in for the LangGraph agent: returns canned text, or raises."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, 0

    def invoke(self, payload):
        self.calls += 1
        if self.error:
            raise self.error
        return {"messages": [_FakeMessage(self.reply)]}


def _use_fake_agent(monkeypatch, svc, agent):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(svc.sys.modules["pipeline.classifier"], "build_classifier_agent",
                        lambda *a, **k: agent)


def test_llm_mode_merges_model_answer_and_labels_it(monkeypatch, svc):
    reply = json.dumps({
        "service_id": "openai", "service_name": "OpenAI API",
        "behavior_classification": "agentic-orchestration", "confidence": 0.97,
        "confidence_level": "high", "evidence": ["Model saw api.openai.com"],
        "severity": "critical", "recommendation": "Isolate the host.",
    })
    agent = _FakeAgent(reply=f"```json\n{reply}\n```")
    _use_fake_agent(monkeypatch, svc, agent)

    body = _upload(TestClient(svc.app), classifier="llm", model="claude-opus-5").json()
    assert body["classifier"] == {"mode": "llm", "model": "claude-opus-5"}
    assert agent.calls == 5
    assert all(f["classifier_mode"] == "llm" for f in body["findings"])
    top = body["findings"][0]
    assert top["severity"] == "critical" and top["confidence"] == 0.97
    assert top["recommendation"] == "Isolate the host."
    assert "Model saw api.openai.com" in top["evidence_chain"]
    assert body["metadata"]["classifier"] == "llm:claude-opus-5"


def test_llm_garbage_falls_back_to_rules_values_per_field(monkeypatch, svc):
    agent = _FakeAgent(reply='{"service_id": "skynet", "confidence": 7, "severity": "apocalyptic"}')
    _use_fake_agent(monkeypatch, svc, agent)
    body = _upload(TestClient(svc.app), classifier="llm").json()
    top = body["findings"][0]
    assert top["service_id"] == "openai"
    assert top["severity"] == "high"
    assert 0.0 <= top["confidence"] <= 1.0
    assert top["classifier_mode"] == "llm"


def test_llm_failure_degrades_that_cluster_to_rules_fallback(monkeypatch, svc):
    _use_fake_agent(monkeypatch, svc, _FakeAgent(error=RuntimeError("overloaded")))
    r = _upload(TestClient(svc.app), classifier="llm")
    assert r.status_code == 200
    body = r.json()
    assert body["classifier"]["mode"] == "llm"
    assert body["summary"]["classifier_modes"] == {"rules-fallback": 5}
    assert body["findings"][0]["service_id"] == "openai"


def test_llm_cap_bounds_model_calls_per_upload(monkeypatch, tmp_path):
    svc = _load_service(monkeypatch, tmp_path, ZEEK_LLM_MAX_CLUSTERS="2")
    agent = _FakeAgent(reply='{"service_id": "unknown", "severity": "low"}')
    _use_fake_agent(monkeypatch, svc, agent)
    body = _upload(TestClient(svc.app), classifier="llm").json()
    assert agent.calls == 2
    assert body["summary"]["classifier_modes"] == {"llm": 2, "rules": 3}


def test_auto_mode_follows_the_key(monkeypatch, svc):
    assert svc.resolve_mode("auto") == "rules"
    assert TestClient(svc.app).get("/health").json()["classifier"]["effective_mode"] == "rules"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert svc.resolve_mode("auto") == "llm"


def test_llm_requested_without_a_key_is_a_clear_503(client):
    r = _upload(client, classifier="llm")
    assert r.status_code == 503
    assert "ANTHROPIC_API_KEY" in r.json()["detail"]


def test_bad_mode_env_fails_at_startup(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="ZEEK_CLASSIFIER_MODE"):
        _load_service(monkeypatch, tmp_path, ZEEK_CLASSIFIER_MODE="vibes")


# ── 4. Bounds and auth ────────────────────────────────────────────────────────

def test_oversized_upload_is_413(monkeypatch, tmp_path):
    svc = _load_service(monkeypatch, tmp_path, ZEEK_MAX_UPLOAD_BYTES="1024")
    r = _upload(TestClient(svc.app))
    assert r.status_code == 413
    assert "ZEEK_MAX_UPLOAD_BYTES" in r.json()["detail"]


def test_empty_and_untyped_uploads_are_422(client):
    assert client.post("/analyze", files=[]).status_code == 422
    r = client.post("/analyze", files=[("files", ("blob", io.BytesIO(b"hello world\n")))])
    assert r.status_code == 422
    assert "ssl.log or conn.log" in r.json()["detail"]
    header_only = b"#separator \\x09\n#fields\tts\tuid\n#types\ttime\tstring\n"
    r = client.post("/analyze", files=[("files", ("conn.log", io.BytesIO(header_only)))])
    assert r.status_code == 422
    assert "no parseable Zeek events" in r.json()["detail"]


def test_bearer_gate_when_token_is_set(monkeypatch, tmp_path):
    svc = _load_service(monkeypatch, tmp_path, ZEEK_DETECTOR_API_TOKEN="s3cret")
    c = TestClient(svc.app)
    assert c.get("/health").status_code == 200
    assert c.get("/health").json()["auth"] == "bearer"
    assert c.get("/analyses").status_code == 401
    assert _upload(c).status_code == 401
    assert c.get("/analyses", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/analyses", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_no_token_means_open_on_the_internal_network(client):
    assert client.get("/health").json()["auth"] == "none"
    assert client.get("/analyses").status_code == 200


# ── Compose wiring ────────────────────────────────────────────────────────────

def test_compose_service_is_internal_and_opt_in():
    text = (Path(__file__).resolve().parents[2] / "docker-compose.agents.yml").read_text()
    block = text.split("  zeek-detector:\n", 1)[1].split("\n  thousandeyes-analyst:", 1)[0]
    assert 'profiles: ["zeek"]' in block
    assert '- "8007"' in block and "ports:" not in block
    assert "zeek-detector-data:/data" in block
    for var in ("ANTHROPIC_API_KEY", "ZEEK_CLASSIFIER_MODE", "ZEEK_CLASSIFIER_MODEL",
                "ZEEK_DB_PATH", "ZEEK_DETECTOR_API_TOKEN", "ZEEK_MAX_UPLOAD_BYTES"):
        assert var in block, f"compose zeek-detector missing {var}"
