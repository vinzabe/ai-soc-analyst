"""LogIndex backends.

`LogQuery` is a small structured query language understood by every
backend. `LocalLogIndex` is an in-process implementation; an
`ElasticsearchLogIndex` is also provided for production use but only
imported lazily.

Filter shape (all optional):

    {
      "must":      [{"field": "event_type", "op": "eq",        "value": "ssh_failed_login"},
                    {"field": "src_ip",     "op": "in",         "value": ["1.2.3.4", "5.6.7.8"]},
                    {"field": "message",    "op": "contains",   "value": "sudo"}],
      "must_not":  [{"field": "user", "op": "eq", "value": "root"}],
      "time_range": {"from": "2024-01-01T00:00:00Z",
                     "to":   "2024-01-02T00:00:00Z"},
      "limit": 200,
      "sort":  "timestamp_desc"      # also: timestamp_asc
    }
"""
from __future__ import annotations
import datetime as dt
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .events import Event


_OPS = {"eq", "neq", "in", "not_in", "contains", "regex", "gt", "gte",
         "lt", "lte"}


@dataclass
class LogQuery:
    must: List[Dict[str, Any]] = field(default_factory=list)
    must_not: List[Dict[str, Any]] = field(default_factory=list)
    time_range: Optional[Dict[str, str]] = None
    limit: int = 100
    sort: str = "timestamp_desc"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LogQuery":
        return cls(
            must=list(d.get("must", []) or []),
            must_not=list(d.get("must_not", []) or []),
            time_range=d.get("time_range"),
            limit=int(d.get("limit", 100) or 100),
            sort=d.get("sort", "timestamp_desc"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"must": list(self.must),
                 "must_not": list(self.must_not),
                 "time_range": self.time_range,
                 "limit": self.limit,
                 "sort": self.sort}

    def validate(self) -> List[str]:
        errs: List[str] = []
        for clause_name, clauses in (("must", self.must),
                                       ("must_not", self.must_not)):
            for c in clauses:
                if not isinstance(c, dict):
                    errs.append(f"{clause_name}: clause not a dict: {c}")
                    continue
                if "field" not in c or "op" not in c:
                    errs.append(f"{clause_name}: missing field/op: {c}")
                    continue
                if c["op"] not in _OPS:
                    errs.append(f"{clause_name}: unknown op {c['op']!r}")
        if self.time_range:
            for k in ("from", "to"):
                v = self.time_range.get(k)
                if v is not None:
                    try:
                        dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                    except Exception:
                        errs.append(f"time_range.{k}: not ISO datetime")
        if self.sort not in ("timestamp_desc", "timestamp_asc"):
            errs.append(f"unknown sort {self.sort!r}")
        if self.limit < 1 or self.limit > 100000:
            errs.append("limit out of range")
        return errs


# ---------------------------------------------------------------------------
def _get_field(ev: Event, field_path: str) -> Any:
    """Resolve dotted field path on an Event."""
    if "." in field_path:
        head, rest = field_path.split(".", 1)
        if head == "fields":
            return ev.fields.get(rest)
    return getattr(ev, field_path, ev.fields.get(field_path))


def _match_clause(ev: Event, clause: Dict[str, Any]) -> bool:
    field_path = clause.get("field", "")
    op = clause.get("op")
    val = clause.get("value")
    cur = _get_field(ev, field_path)
    if op == "eq":
        return cur == val
    if op == "neq":
        return cur != val
    if op == "in":
        return cur in (val or [])
    if op == "not_in":
        return cur not in (val or [])
    if op == "contains":
        if cur is None:
            return False
        return str(val).lower() in str(cur).lower()
    if op == "regex":
        if cur is None:
            return False
        try:
            return bool(re.search(str(val), str(cur)))
        except re.error:
            return False
    if op in ("gt", "gte", "lt", "lte"):
        try:
            cur_n = float(cur)
            val_n = float(val)
        except (TypeError, ValueError):
            return False
        return ((op == "gt" and cur_n > val_n)
                 or (op == "gte" and cur_n >= val_n)
                 or (op == "lt" and cur_n < val_n)
                 or (op == "lte" and cur_n <= val_n))
    return False


def _match_time_range(ev: Event, tr: Optional[Dict[str, str]]) -> bool:
    if not tr:
        return True
    if tr.get("from"):
        f = dt.datetime.fromisoformat(tr["from"].replace("Z", "+00:00"))
        if ev.timestamp < f:
            return False
    if tr.get("to"):
        t = dt.datetime.fromisoformat(tr["to"].replace("Z", "+00:00"))
        if ev.timestamp > t:
            return False
    return True


# ---------------------------------------------------------------------------
class LocalLogIndex:
    """In-memory log index. Useful for testing and small deployments."""

    def __init__(self, events: Optional[Iterable[Event]] = None):
        self.events: List[Event] = list(events or [])

    def add(self, event: Event) -> None:
        self.events.append(event)

    def add_many(self, events: Iterable[Event]) -> None:
        self.events.extend(events)

    def __len__(self) -> int:
        return len(self.events)

    def search(self, query: LogQuery) -> List[Event]:
        errs = query.validate()
        if errs:
            raise ValueError("invalid query: " + "; ".join(errs))
        out: List[Event] = []
        for ev in self.events:
            if not _match_time_range(ev, query.time_range):
                continue
            if not all(_match_clause(ev, c) for c in query.must):
                continue
            if any(_match_clause(ev, c) for c in query.must_not):
                continue
            out.append(ev)
        out.sort(key=lambda e: e.timestamp,
                  reverse=(query.sort == "timestamp_desc"))
        return out[: query.limit]

    def aggregate_by(self, query: LogQuery, field_path: str,
                       *, top_n: int = 10) -> List[Dict[str, Any]]:
        rows = self.search(query)
        counts: Dict[Any, int] = {}
        for ev in rows:
            v = _get_field(ev, field_path)
            counts[v] = counts.get(v, 0) + 1
        items = sorted(counts.items(), key=lambda kv: -kv[1])[: top_n]
        return [{"key": k, "count": c} for k, c in items]


# ---------------------------------------------------------------------------
class ElasticsearchLogIndex:
    """Thin Elasticsearch backend (production).

    Translates `LogQuery` to an ES boolean query. Imports `elasticsearch`
    lazily so unit tests don't need it.
    """
    def __init__(self, hosts: Sequence[str] = ("http://localhost:9200",),
                  index: str = "soc-events", **client_kwargs):
        from elasticsearch import Elasticsearch  # noqa: WPS433
        self._es = Elasticsearch(list(hosts), **client_kwargs)
        self.index = index

    def search(self, query: LogQuery) -> List[Event]:
        es_query = self._to_es(query)
        body = {"query": es_query, "size": query.limit,
                 "sort": [{"timestamp": {"order":
                            "desc" if query.sort == "timestamp_desc" else "asc"}}]}
        resp = self._es.search(index=self.index, body=body)
        return [Event.from_dict(hit["_source"])
                for hit in resp.get("hits", {}).get("hits", [])]

    def _to_es(self, query: LogQuery) -> Dict[str, Any]:
        must: List[Dict[str, Any]] = []
        must_not: List[Dict[str, Any]] = []
        for clause in query.must:
            must.append(self._clause_to_es(clause))
        for clause in query.must_not:
            must_not.append(self._clause_to_es(clause))
        if query.time_range:
            r = {}
            if query.time_range.get("from"):
                r["gte"] = query.time_range["from"]
            if query.time_range.get("to"):
                r["lte"] = query.time_range["to"]
            must.append({"range": {"timestamp": r}})
        return {"bool": {"must": must, "must_not": must_not}}

    def _clause_to_es(self, c: Dict[str, Any]) -> Dict[str, Any]:
        f, op, v = c["field"], c["op"], c.get("value")
        if op == "eq":
            return {"term": {f: v}}
        if op == "in":
            return {"terms": {f: v or []}}
        if op == "contains":
            return {"match_phrase": {f: v}}
        if op == "regex":
            return {"regexp": {f: v}}
        if op in ("gt", "gte", "lt", "lte"):
            return {"range": {f: {op: v}}}
        if op == "neq":
            return {"bool": {"must_not": [{"term": {f: v}}]}}
        if op == "not_in":
            return {"bool": {"must_not": [{"terms": {f: v or []}}]}}
        return {"match_all": {}}
