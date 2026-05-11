import datetime as dt
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from soc.events import Alert, AlertSeverity, Event
from soc.triage import AlertTriager


class _Resp:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, content):
        self.content = content

    def chat(self, messages, **kw):
        return _Resp(self.content)


class _BoomLLM:
    def chat(self, messages, **kw):
        raise RuntimeError("boom")


def _alert():
    return Alert(
        id="alert-001", rule_id="AUTH-001",
        rule_name="SSH brute-force",
        severity=AlertSeverity.HIGH,
        timestamp=dt.datetime(2024, 5, 1, 10, 0, 25, tzinfo=dt.timezone.utc),
        description="Brute force followed by login",
        host="prod-web01", user="root", src_ip="185.220.101.5",
    )


def test_triage_happy_path():
    payload = json.dumps({
        "is_true_positive": True,
        "confidence": 0.92,
        "severity": "critical",
        "mitre_techniques": ["T1110.001", "T1078"],
        "rationale": "3 failed logins followed by success from a known TOR exit IP.",
        "recommended_actions": [
            "Isolate prod-web01",
            "Reset SSH credentials",
            "Block 185.220.101.5",
        ],
    })
    tr = AlertTriager(_FakeLLM(payload))
    v = tr.triage(_alert())
    assert v.is_true_positive is True
    assert v.confidence == 0.92
    assert v.severity == "critical"
    assert "T1110.001" in v.mitre_techniques
    assert len(v.recommended_actions) == 3


def test_triage_clamps_confidence():
    tr = AlertTriager(_FakeLLM(json.dumps({"confidence": 5.0})))
    v = tr.triage(_alert())
    assert 0.0 <= v.confidence <= 1.0


def test_triage_invalid_json_returns_error():
    tr = AlertTriager(_FakeLLM("not json"))
    v = tr.triage(_alert())
    assert v.error == "invalid JSON from model"
    assert v.is_true_positive is False


def test_triage_handles_llm_exception():
    tr = AlertTriager(_BoomLLM())
    v = tr.triage(_alert())
    assert v.error and "LLM" in v.error
    assert v.is_true_positive is False


def test_triage_caps_action_count():
    payload = json.dumps({
        "is_true_positive": True,
        "confidence": 0.5,
        "recommended_actions": [f"step {i}" for i in range(20)],
    })
    tr = AlertTriager(_FakeLLM(payload))
    v = tr.triage(_alert())
    assert len(v.recommended_actions) <= 6


def test_triage_passes_events_into_prompt():
    captured = {}

    class C:
        def chat(self, messages, **kw):
            captured["messages"] = messages
            return _Resp("{}")

    tr = AlertTriager(C(), events_per_alert=2)
    events = [Event(id=f"e{i}", timestamp=dt.datetime.now(dt.timezone.utc),
                      source="x", event_type="y", message=f"m{i}")
                for i in range(5)]
    tr.triage(_alert(), events)
    user_msg = captured["messages"][1]["content"]
    # Only first 2 events should be present
    assert '"id": "e0"' in user_msg
    assert '"id": "e1"' in user_msg
    assert '"id": "e2"' not in user_msg
