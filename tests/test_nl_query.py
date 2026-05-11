import datetime as dt
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from soc.nl_query import NLQueryEngine, _extract_json


class _Resp:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def chat(self, messages, **kw):
        self.calls.append(messages)
        return _Resp(self.content)


class _BoomLLM:
    def chat(self, messages, **kw):
        raise RuntimeError("boom")


def test_extract_json_simple():
    assert _extract_json('{"must":[]}') == {"must": []}


def test_translate_happy_path():
    payload = json.dumps({
        "must": [{"field": "event_type", "op": "eq",
                   "value": "ssh_failed_login"}],
        "limit": 50,
        "sort": "timestamp_desc",
    })
    eng = NLQueryEngine(_FakeLLM(payload))
    res = eng.translate("show me failed SSH logins")
    assert res.error is None
    assert res.query is not None
    assert res.query.must == [{"field": "event_type", "op": "eq",
                                  "value": "ssh_failed_login"}]
    assert res.query.limit == 50


def test_translate_invalid_json():
    eng = NLQueryEngine(_FakeLLM("nonsense"))
    res = eng.translate("anything")
    assert res.query is None
    assert "invalid JSON" in res.error


def test_translate_invalid_query():
    payload = json.dumps({"must": [{"field": "x", "op": "wat"}]})
    eng = NLQueryEngine(_FakeLLM(payload))
    res = eng.translate("malformed query")
    assert res.query is None
    assert "unknown op" in res.error


def test_translate_handles_llm_exception():
    eng = NLQueryEngine(_BoomLLM())
    res = eng.translate("anything")
    assert res.query is None
    assert "LLM error" in res.error


def test_translate_passes_now_in_message():
    eng = NLQueryEngine(_FakeLLM('{"must":[]}'))
    eng.translate("anything", now=dt.datetime(2024, 5, 1, tzinfo=dt.timezone.utc))
    user_content = eng.client.calls[0][1]["content"]
    assert "2024-05-01" in user_content


def test_translate_unwraps_codefence():
    payload = '```json\n{"must":[]}\n```'
    eng = NLQueryEngine(_FakeLLM(payload))
    res = eng.translate("anything")
    assert res.query is not None
    assert res.query.must == []
