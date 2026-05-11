import datetime as dt
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from soc.events import Event
from soc.index import LocalLogIndex, LogQuery


FIXTURES = os.path.normpath(os.path.join(_HERE, "..", "fixtures"))


def _load_events():
    out = []
    with open(os.path.join(FIXTURES, "events.jsonl")) as f:
        for line in f:
            out.append(Event.from_dict(json.loads(line)))
    return out


def _idx():
    return LocalLogIndex(_load_events())


def test_load_and_count():
    idx = _idx()
    assert len(idx) == 10


def test_query_eq_event_type():
    idx = _idx()
    q = LogQuery(must=[{"field": "event_type", "op": "eq",
                          "value": "ssh_failed_login"}], limit=100)
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e1", "e2", "e3", "e10"}


def test_query_in_op():
    idx = _idx()
    q = LogQuery(must=[{"field": "host", "op": "in",
                          "value": ["prod-web01", "jumpbox"]}], limit=100)
    rows = idx.search(q)
    hosts = {r.host for r in rows}
    assert hosts == {"prod-web01", "jumpbox"}


def test_query_contains_message():
    idx = _idx()
    q = LogQuery(must=[{"field": "message", "op": "contains",
                          "value": "Accepted password"}], limit=100)
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e4"}


def test_query_must_not_excludes():
    idx = _idx()
    q = LogQuery(must=[{"field": "event_type", "op": "eq",
                          "value": "ssh_failed_login"}],
                   must_not=[{"field": "host", "op": "eq",
                                "value": "prod-web01"}])
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e10"}


def test_query_time_range():
    idx = _idx()
    q = LogQuery(time_range={"from": "2024-05-01T10:00:00+00:00",
                                "to": "2024-05-01T10:01:00+00:00"})
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e1", "e2", "e3", "e4"}


def test_query_regex_op():
    idx = _idx()
    q = LogQuery(must=[{"field": "cmdline", "op": "regex",
                          "value": r"curl\s+-o"}])
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e5"}


def test_query_sort_and_limit():
    idx = _idx()
    q = LogQuery(must=[{"field": "event_type", "op": "eq",
                          "value": "ssh_failed_login"}],
                   sort="timestamp_asc", limit=2)
    rows = idx.search(q)
    assert [r.id for r in rows] == ["e1", "e2"]


def test_query_dotted_field():
    idx = _idx()
    q = LogQuery(must=[{"field": "fields.signature_id", "op": "eq",
                          "value": "2014935"}])
    rows = idx.search(q)
    assert {r.id for r in rows} == {"e7"}


def test_invalid_query_raises():
    idx = _idx()
    q = LogQuery(must=[{"field": "x", "op": "wat"}])
    with pytest.raises(ValueError):
        idx.search(q)


def test_aggregate_by_src_ip():
    idx = _idx()
    q = LogQuery(must=[{"field": "event_type", "op": "eq",
                          "value": "ssh_failed_login"}])
    agg = idx.aggregate_by(q, "src_ip", top_n=5)
    assert agg[0]["key"] == "185.220.101.5"
    assert agg[0]["count"] == 4


def test_query_validate_bad_time():
    q = LogQuery(time_range={"from": "not-a-date"})
    errs = q.validate()
    assert any("time_range.from" in e for e in errs)


def test_query_to_dict_and_from_dict_roundtrip():
    q = LogQuery(must=[{"field": "user", "op": "eq", "value": "root"}],
                   time_range={"from": "2024-01-01T00:00:00+00:00"},
                   limit=42, sort="timestamp_asc")
    d = q.to_dict()
    q2 = LogQuery.from_dict(d)
    assert q2.must == q.must
    assert q2.time_range == q.time_range
    assert q2.limit == 42
    assert q2.sort == "timestamp_asc"
