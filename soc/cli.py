"""SOC analyst CLI — query logs in NL, triage alerts, generate IR reports."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import sys
from typing import Sequence

from .events import Alert, Event
from .index import LocalLogIndex, LogQuery
from .nl_query import NLQueryEngine
from .triage import AlertTriager
from .ir_report import IRReportGenerator


def _llm_client(timeout: float = 180.0):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from llm_client import LLMClient
    return LLMClient(timeout=timeout)


def _load_events(path: str):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield Event.from_dict(json.loads(line))


def _cmd_query(ns) -> int:
    idx = LocalLogIndex(_load_events(ns.events))
    eng = NLQueryEngine(_llm_client())
    res = eng.translate(ns.question)
    if res.error:
        print(json.dumps({"error": res.error, "raw": res.raw[:500]}, indent=2))
        return 1
    rows = idx.search(res.query)
    print(json.dumps({
        "query": res.query.to_dict(),
        "n_results": len(rows),
        "results": [r.to_dict() for r in rows],
    }, indent=2, default=str))
    return 0


def _cmd_triage(ns) -> int:
    with open(ns.alert) as f:
        alert = Alert.from_dict(json.load(f))
    related = list(_load_events(ns.events)) if ns.events else []
    tr = AlertTriager(_llm_client())
    verdict = tr.triage(alert, related)
    print(json.dumps(verdict.to_dict(), indent=2, default=str))
    return 0


def _cmd_report(ns) -> int:
    with open(ns.alerts) as f:
        alerts_raw = json.load(f)
    if not isinstance(alerts_raw, list):
        alerts_raw = [alerts_raw]
    alerts = [Alert.from_dict(a) for a in alerts_raw]
    events = list(_load_events(ns.events)) if ns.events else []
    gen = IRReportGenerator(_llm_client())
    rep = gen.generate(incident_id=ns.id, title=ns.title,
                          alerts=alerts, events=events)
    if rep.error:
        print(rep.error, file=sys.stderr)
        return 1
    if ns.output:
        with open(ns.output, "w") as f:
            f.write(rep.markdown)
    print(rep.markdown)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc",
                                  description="AI SOC analyst")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="natural-language log search")
    q.add_argument("--events", required=True,
                     help="JSONL file of events to search")
    q.add_argument("question", help="English question")
    q.set_defaults(func=_cmd_query)

    t = sub.add_parser("triage", help="triage a single alert")
    t.add_argument("--alert", required=True, help="JSON file with one alert")
    t.add_argument("--events", help="JSONL of related events")
    t.set_defaults(func=_cmd_triage)

    r = sub.add_parser("report", help="generate IR report")
    r.add_argument("--alerts", required=True,
                     help="JSON file with a list of alerts")
    r.add_argument("--events", help="JSONL of events")
    r.add_argument("--id", default="INC-0001")
    r.add_argument("--title", default="Suspected intrusion")
    r.add_argument("--output", "-o")
    r.set_defaults(func=_cmd_report)

    ns = p.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
