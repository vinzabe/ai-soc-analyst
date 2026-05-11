"""Live LLM smoke test for the SOC analyst."""
import datetime as dt
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from soc.events import Alert, AlertSeverity, Event
from soc.index import LocalLogIndex
from soc.nl_query import NLQueryEngine
from soc.triage import AlertTriager


@pytest.mark.skipif(not os.environ.get("LLM_LIVE"),
                     reason="set LLM_LIVE=1 for live LLM smoke test")
def test_live_nl_query_failed_ssh():
    from llm_client import LLMClient
    client = LLMClient(timeout=180.0)
    eng = NLQueryEngine(client, model="glm-5.1", temperature=0.0)
    res = eng.translate("show me failed SSH login attempts",
                          now=dt.datetime(2024, 5, 1, 12, 0,
                                            tzinfo=dt.timezone.utc))
    assert res.error is None, f"{res.error}: {res.raw[:300]}"
    assert res.query is not None
    # Quality check: should mention something like ssh / failed / event_type
    blob = json.dumps(res.query.to_dict()).lower()
    assert ("ssh" in blob) and ("fail" in blob or "auth" in blob)


@pytest.mark.skipif(not os.environ.get("LLM_LIVE"),
                     reason="set LLM_LIVE=1 for live LLM smoke test")
def test_live_triage_brute_force_then_login():
    from llm_client import LLMClient
    client = LLMClient(timeout=180.0)
    tr = AlertTriager(client, model="glm-5.1", temperature=0.0)
    alert = Alert(
        id="alert-001", rule_id="AUTH-001",
        rule_name="SSH brute-force then successful login",
        severity=AlertSeverity.HIGH,
        timestamp=dt.datetime(2024, 5, 1, 10, 0, 25, tzinfo=dt.timezone.utc),
        description=("Three failed SSH logins for root, admin, oracle from "
                      "185.220.101.5 (a known TOR exit node), followed by a "
                      "successful root login from the same IP within 30 seconds."),
        host="prod-web01", user="root", src_ip="185.220.101.5",
        mitre_techniques=["T1110.001"],
    )
    v = tr.triage(alert)
    assert v.error is None, v.error
    # Strong signal of compromise; expect TP=true with reasonable confidence
    assert v.is_true_positive is True
    assert v.confidence >= 0.6
    assert v.recommended_actions  # non-empty
