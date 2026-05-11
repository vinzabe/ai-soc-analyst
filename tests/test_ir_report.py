import datetime as dt
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from soc.events import Alert, AlertSeverity, Event
from soc.ir_report import IRReportGenerator


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
        raise RuntimeError("LLM down")


def _alert():
    return Alert(id="a1", rule_id="r1", rule_name="brute force",
                   severity=AlertSeverity.HIGH,
                   timestamp=dt.datetime(2024, 5, 1, 10, 0, tzinfo=dt.timezone.utc),
                   description="3x failed then success")


def test_generate_happy_path():
    md = ("# Executive Summary\nA suspected SSH brute force succeeded.\n"
           "## Timeline\n... ")
    gen = IRReportGenerator(_FakeLLM(md))
    rep = gen.generate(incident_id="INC-1", title="t", alerts=[_alert()])
    assert rep.error is None
    assert "Executive Summary" in rep.markdown
    d = rep.to_dict()
    assert d["incident_id"] == "INC-1"
    assert d["n_alerts"] == 1


def test_generate_unwraps_codefence():
    md = "```markdown\n# Executive Summary\nbody\n```"
    gen = IRReportGenerator(_FakeLLM(md))
    rep = gen.generate(incident_id="INC-1", title="t", alerts=[_alert()])
    assert rep.markdown.startswith("# Executive Summary")
    assert "```" not in rep.markdown


def test_generate_handles_llm_exception():
    gen = IRReportGenerator(_BoomLLM())
    rep = gen.generate(incident_id="INC-1", title="t", alerts=[_alert()])
    assert rep.error and "LLM error" in rep.error
    assert rep.markdown == ""


def test_generate_truncates_inputs():
    captured = {}

    class C:
        def chat(self, messages, **kw):
            captured["msg"] = messages[1]["content"]
            return _Resp("# Report")

    gen = IRReportGenerator(C(), max_alerts=2, max_events=3)
    alerts = [_alert() for _ in range(5)]
    events = [Event(id=f"e{i}", timestamp=dt.datetime.now(dt.timezone.utc),
                      source="x", event_type="y") for i in range(10)]
    rep = gen.generate(incident_id="x", title="y", alerts=alerts,
                          events=events)
    # only 2 alerts, 3 events should appear in user message
    msg = captured["msg"]
    assert msg.count('"rule_id": "r1"') == 2
    assert msg.count('"event_type": "y"') == 3
    assert len(rep.alerts) == 2
    assert len(rep.events) == 3
